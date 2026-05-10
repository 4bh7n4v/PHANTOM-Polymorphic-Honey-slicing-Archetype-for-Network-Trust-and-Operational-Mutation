"""
Ryu ZTNA Application — Zero Trust OpenFlow 1.3 Controller
SDN_Controller/ryu_ztna_app.py

Responsibilities:
  - Connect to Open vSwitch via OpenFlow 1.3 (TCP :6653)
  - Install default deny-all rule on every switch that connects
  - Install per-session ALLOW/DENY/RATE-LIMIT flow rules on PEP decision
  - Expose REST API on :8085 for PEP to push flow commands
  - Auto-expire idle sessions via OpenFlow idle_timeout

REST API (consumed by PEP):
  POST /ztna/flows/allow       — install allow flow for a session
  POST /ztna/flows/deny        — remove flow / install explicit drop
  POST /ztna/flows/rate-limit  — install throttled flow (STEP_UP)
  DELETE /ztna/flows/{session} — explicit session teardown
  GET  /ztna/flows             — list all active session flows
  GET  /ztna/switches          — list connected OVS datapaths
"""

import json
import logging
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Constants                                                           #
# ------------------------------------------------------------------ #

FLOW_IDLE_TIMEOUT  = 300    # seconds — session flow auto-expires if idle
FLOW_HARD_TIMEOUT  = 3600   # seconds — absolute max session lifetime

PRIORITY_DEFAULT_DENY  = 0    # catch-all drop
PRIORITY_ARP           = 10   # ARP flooding
PRIORITY_RATE_LIMITED  = 150  # STEP_UP sessions
PRIORITY_ALLOW_BASE    = 200  # ALLOW sessions (+ trust score bonus)
PRIORITY_EXPLICIT_DENY = 500  # explicit per-IP drop (DENY decision)


# ------------------------------------------------------------------ #
#  Flow Registry (in-memory — authoritative list of installed flows)  #
# ------------------------------------------------------------------ #

class FlowRegistry:
    """Tracks all ZTNA session flows currently installed in OVS."""

    def __init__(self):
        self._sessions: dict = {}   # session_id → flow metadata

    def add(self, session_id: str, metadata: dict):
        self._sessions[session_id] = {**metadata, "active": True}

    def remove(self, session_id: str):
        if session_id in self._sessions:
            self._sessions[session_id]["active"] = False

    def get_all(self) -> list:
        return list(self._sessions.values())

    def get(self, session_id: str) -> dict:
        return self._sessions.get(session_id, {})


flow_registry = FlowRegistry()


# ================================================================== #
#  Ryu OpenFlow 1.3 Application                                        #
# ================================================================== #

class ZTNARyuApp(app_manager.RyuApp):
    """
    Core Ryu application.
    Handles switch lifecycle and OpenFlow message exchange.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS    = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict = defaultdict(dict)  # dpid → {mac: port}
        self.datapaths:   dict = {}                  # dpid → datapath object

        # Register REST controller
        wsgi = kwargs["wsgi"]
        wsgi.register(ZTNARestController,
                       {"ryu_app": self, "flow_registry": flow_registry})
        logger.info("[Ryu] ZTNA app started. REST API on :8085")

    # -------------------------------------------------------------- #
    #  Switch Lifecycle                                                #
    # -------------------------------------------------------------- #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when a switch (OVS) connects to the controller."""
        datapath = ev.msg.datapath
        dpid     = datapath.id
        self.datapaths[dpid] = datapath

        logger.info("[Ryu] Switch connected: dpid=%s", hex(dpid))

        # 1. Default deny-all (priority 0 — catches everything not matched above)
        self._install_default_deny(datapath)

        # 2. Allow ARP so hosts can discover each other
        self._install_arp_flood(datapath)

        # 3. Allow LLDP / controller traffic
        self._install_controller_passthrough(datapath)

    def _install_default_deny(self, datapath):
        """Priority 0: drop all unmatched traffic."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        self._add_flow(
            datapath,
            priority=PRIORITY_DEFAULT_DENY,
            match=parser.OFPMatch(),
            actions=[],   # empty actions = DROP
            idle_timeout=0,
            hard_timeout=0,
        )
        logger.info("[Ryu] Installed default-deny on dpid=%s", hex(datapath.id))

    def _install_arp_flood(self, datapath):
        """Priority 10: flood ARP so hosts can resolve MACs."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, PRIORITY_ARP, match, actions)

    def _install_controller_passthrough(self, datapath):
        """Priority 5: send unmatched IPv4 to controller for MAC learning."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch(eth_type=0x0800)  # IPv4
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=5, match=match, actions=actions)

    # -------------------------------------------------------------- #
    #  MAC Learning (Packet-In)                                        #
    # -------------------------------------------------------------- #

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Learn source MAC → port mappings, then forward."""
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match["in_port"]

        pkt      = packet.Packet(msg.data)
        eth_pkt  = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # Learn source MAC
        self.mac_to_port[dpid][src_mac] = in_port

        # Determine output port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # If we know the destination, install a specific flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           idle_timeout=60)

        # Forward current packet
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # -------------------------------------------------------------- #
    #  ZTNA Flow Management (called by REST API)                       #
    # -------------------------------------------------------------- #

    def install_allow_flow(self, src_ip: str, dst_ip: str,
                            session_id: str, trust_score: float):
        """
        Install a bidirectional ALLOW flow for an authenticated session.
        Priority scales with trust score: higher trust = higher priority.
        """
        priority = int(PRIORITY_ALLOW_BASE + (trust_score * 100))
        installed = []

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            # Forward direction: client → resource
            fwd_match = parser.OFPMatch(eth_type=0x0800,
                                         ipv4_src=src_ip, ipv4_dst=dst_ip)
            fwd_actions = [parser.OFPActionOutput(
                datapath.ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, priority, fwd_match, fwd_actions,
                           idle_timeout=FLOW_IDLE_TIMEOUT,
                           hard_timeout=FLOW_HARD_TIMEOUT)

            # Return direction: resource → client
            rev_match = parser.OFPMatch(eth_type=0x0800,
                                         ipv4_src=dst_ip, ipv4_dst=src_ip)
            self._add_flow(datapath, priority, rev_match, fwd_actions,
                           idle_timeout=FLOW_IDLE_TIMEOUT,
                           hard_timeout=FLOW_HARD_TIMEOUT)

            installed.append(hex(dpid))
            logger.info(
                "[Ryu] ALLOW flow installed: %s → %s | session=%s trust=%.2f dpid=%s",
                src_ip, dst_ip, session_id, trust_score, hex(dpid)
            )

        flow_registry.add(session_id, {
            "session_id": session_id,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "trust_score": trust_score,
            "priority":   priority,
            "action":     "ALLOW",
            "switches":   installed,
        })

    def install_deny_flow(self, src_ip: str, dst_ip: str, session_id: str):
        """
        Install an explicit DROP flow for a denied session.
        Higher priority than ALLOW flows — enforces revocation immediately.
        """
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=src_ip, ipv4_dst=dst_ip)
            # Empty actions = DROP
            self._add_flow(datapath, PRIORITY_EXPLICIT_DENY, match, [],
                           idle_timeout=0, hard_timeout=60)

            logger.info(
                "[Ryu] DENY flow installed: %s → %s | session=%s dpid=%s",
                src_ip, dst_ip, session_id, hex(dpid)
            )

        flow_registry.remove(session_id)

    def remove_session_flows(self, src_ip: str, dst_ip: str, session_id: str):
        """
        Delete all flows matching a session's src/dst IPs.
        Called on session termination or DENY decision to revoke access.
        """
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser  = datapath.ofproto_parser

            for s, d in [(src_ip, dst_ip), (dst_ip, src_ip)]:
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=s, ipv4_dst=d)
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match,
                )
                datapath.send_msg(mod)

            logger.info(
                "[Ryu] Session flows REMOVED: session=%s dpid=%s",
                session_id, hex(dpid)
            )

        flow_registry.remove(session_id)

    def install_rate_limit_flow(self, src_ip: str, dst_ip: str,
                                 session_id: str, trust_score: float):
        """
        Install a lower-priority ALLOW flow for STEP_UP sessions.
        In production, pair with an OVS meter for bandwidth throttling.
        """
        priority = int(PRIORITY_RATE_LIMITED + (trust_score * 50))

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match  = parser.OFPMatch(eth_type=0x0800,
                                     ipv4_src=src_ip, ipv4_dst=dst_ip)
            # NORMAL forwarding — meter would be added here in production
            actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, priority, match, actions,
                           idle_timeout=120,        # shorter idle for STEP_UP
                           hard_timeout=600)

            logger.info(
                "[Ryu] RATE-LIMIT flow installed: %s → %s | session=%s trust=%.2f",
                src_ip, dst_ip, session_id, trust_score
            )

        flow_registry.add(session_id, {
            "session_id":  session_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "trust_score": trust_score,
            "priority":    priority,
            "action":      "RATE_LIMITED",
        })

    # -------------------------------------------------------------- #
    #  Helper: Add Flow                                                #
    # -------------------------------------------------------------- #

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        instructions = []
        if actions:
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)


# ================================================================== #
#  REST API Controller (Ryu WSGI — port 8085)                         #
# ================================================================== #

class ZTNARestController(ControllerBase):
    """
    REST bridge between PEP and the Ryu OpenFlow app.
    PEP calls these endpoints after every policy decision.
    """

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.ryu_app:       ZTNARyuApp   = data["ryu_app"]
        self.flow_registry: FlowRegistry = data["flow_registry"]

    # ---- Allow ---- #

    @route("ztna", "/ztna/flows/allow", methods=["POST"])
    def allow_flow(self, req, **kwargs):
        """Install ALLOW flow for a newly authenticated session."""
        try:
            body       = json.loads(req.body)
            session_id = body["session_id"]
            src_ip     = body["src_ip"]
            dst_ip     = body["dst_ip"]
            trust      = float(body.get("trust_score", 0.7))
        except (KeyError, ValueError) as exc:
            return Response(status=400,
                            json={"error": f"Bad request: {exc}"})

        self.ryu_app.install_allow_flow(src_ip, dst_ip, session_id, trust)
        return Response(status=200,
                        json={"status": "flow_installed",
                              "action": "ALLOW",
                              "session_id": session_id})

    # ---- Deny ---- #

    @route("ztna", "/ztna/flows/deny", methods=["POST"])
    def deny_flow(self, req, **kwargs):
        """Install explicit DROP flow and remove any existing ALLOW flows."""
        try:
            body       = json.loads(req.body)
            session_id = body["session_id"]
            src_ip     = body["src_ip"]
            dst_ip     = body["dst_ip"]
        except (KeyError, ValueError) as exc:
            return Response(status=400,
                            json={"error": f"Bad request: {exc}"})

        self.ryu_app.remove_session_flows(src_ip, dst_ip, session_id)
        self.ryu_app.install_deny_flow(src_ip, dst_ip, session_id)
        return Response(status=200,
                        json={"status": "flow_denied",
                              "session_id": session_id})

    # ---- Rate Limit (STEP_UP) ---- #

    @route("ztna", "/ztna/flows/rate-limit", methods=["POST"])
    def rate_limit_flow(self, req, **kwargs):
        """Install throttled flow for STEP_UP sessions."""
        try:
            body       = json.loads(req.body)
            session_id = body["session_id"]
            src_ip     = body["src_ip"]
            dst_ip     = body["dst_ip"]
            trust      = float(body.get("trust_score", 0.5))
        except (KeyError, ValueError) as exc:
            return Response(status=400,
                            json={"error": f"Bad request: {exc}"})

        self.ryu_app.install_rate_limit_flow(src_ip, dst_ip, session_id, trust)
        return Response(status=200,
                        json={"status": "rate_limited",
                              "session_id": session_id})

    # ---- Session Teardown ---- #

    @route("ztna", "/ztna/flows/{session_id}", methods=["DELETE"])
    def teardown_session(self, req, session_id, **kwargs):
        """Remove all flows for a terminated session."""
        flow = self.flow_registry.get(session_id)
        if not flow:
            return Response(status=404,
                            json={"error": f"Session {session_id} not found"})

        self.ryu_app.remove_session_flows(
            flow["src_ip"], flow["dst_ip"], session_id
        )
        return Response(status=200,
                        json={"status": "teardown_complete",
                              "session_id": session_id})

    # ---- List Flows ---- #

    @route("ztna", "/ztna/flows", methods=["GET"])
    def list_flows(self, req, **kwargs):
        """Return all tracked session flows."""
        return Response(status=200,
                        json={"flows": self.flow_registry.get_all(),
                              "count": len(self.flow_registry.get_all())})

    # ---- List Connected Switches ---- #

    @route("ztna", "/ztna/switches", methods=["GET"])
    def list_switches(self, req, **kwargs):
        """Return all connected OVS datapaths."""
        switches = [
            {"dpid": hex(dpid), "dpid_int": dpid}
            for dpid in self.ryu_app.datapaths
        ]
        return Response(status=200,
                        json={"switches": switches,
                              "count": len(switches)})

    # ---- Health ---- #

    @route("ztna", "/ztna/health", methods=["GET"])
    def health(self, req, **kwargs):
        return Response(status=200,
                        json={"status": "ok",
                              "component": "ryu-ztna",
                              "switches": len(self.ryu_app.datapaths),
                              "active_flows": len(self.flow_registry.get_all())})
