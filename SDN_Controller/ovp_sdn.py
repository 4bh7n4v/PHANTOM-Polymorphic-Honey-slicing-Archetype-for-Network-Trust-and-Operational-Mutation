"""
OVP1 — Client-Side Overlay Network Proxy
OVP2 — Resource-Side Overlay Network Proxy

Architecture flow:
  Client → OVP1 (mTLS tunnel) → PEP (enforcement) → OVP2 → Resource

OVP1: Accepts client connections, forwards to PEP with mTLS
OVP2: Receives from PEP, routes to backend resource with access token
"""

import asyncio
import logging
import time
import uuid
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import httpx
import uvicorn
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# ================================================================== #
#  OVP1 — Client-facing overlay proxy                                 #
# ================================================================== #

ovp1_app = FastAPI(title="OVP1 - Client Overlay Proxy", version="1.0.0")

from config_loader import zta_settings
PEP_URL = zta_settings["gateway_url"]


class OVP1Proxy:
    """
    OVP1 responsibilities:
    1. Accept HTTPS/HTTP2 from authenticated FIDO2 clients
    2. Attach mTLS identity header before forwarding to PEP
    3. Handle connection lifecycle and retry logic
    """

    def __init__(self):
        self._http = httpx.AsyncClient(
            timeout=30,
            # In production: client cert + key for mTLS to PEP
            # cert=("certs/ovp1.crt", "certs/ovp1.key"),
            # verify="certs/ca.crt",
        )
        self._request_count = 0
        self._start_time = time.time()

    async def forward_to_pep(self,
                              path: str,
                              method: str,
                              headers: Dict[str, str],
                              body: Optional[bytes]) -> httpx.Response:
        pep_headers = {k: v for k, v in headers.items()
                       if k.lower() not in ("host", "content-length")}
        pep_headers["X-OVP1-Request-ID"] = str(uuid.uuid4())
        pep_headers["X-OVP1-Timestamp"] = str(time.time())
        # In production: certificate fingerprint from mTLS connection
        pep_headers["X-Client-Cert"] = "CN=ovp1.zerotrust.example.com"

        try:
            resp = await self._http.request(
                method=method,
                url=f"{PEP_URL}{path}",
                headers=pep_headers,
                content=body,
            )
            self._request_count += 1
            return resp
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="PEP unreachable")

    def stats(self) -> Dict:
        return {
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "total_requests": self._request_count,
        }


ovp1 = OVP1Proxy()


@ovp1_app.get("/health")
async def ovp1_health():
    return {"status": "ok", "component": "OVP1", **ovp1.stats()}


@ovp1_app.post("/api/v1/session/rat-update")
async def ovp1_rat_update(request: Request,
                           authorization: Optional[str] = Header(None)):
    """Forward RAT context updates from client → PEP."""
    body = await request.body()
    resp = await ovp1.forward_to_pep(
        "/api/v1/session/rat-update",
        "POST",
        dict(request.headers),
        body,
    )
    return JSONResponse(resp.json(), status_code=resp.status_code)


@ovp1_app.api_route("/{path:path}",
                     methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def ovp1_proxy(path: str, request: Request):
    """
    Main OVP1 proxy:
    All client requests routed through here → PEP.
    """
    body = await request.body()
    pep_path = f"/resource/{path}"
    resp = await ovp1.forward_to_pep(
        pep_path,
        request.method,
        dict(request.headers),
        body,
    )
    try:
        return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception:
        return JSONResponse({"data": resp.text}, status_code=resp.status_code)


# ================================================================== #
#  OVP2 — Resource-side overlay proxy                                  #
# ================================================================== #

ovp2_app = FastAPI(title="OVP2 - Resource Overlay Proxy", version="1.0.0")

RESOURCE_URL = "http://localhost:8090"   # Backend resource server


class OVP2Proxy:
    """
    OVP2 responsibilities:
    1. Receive authorized requests from PEP
    2. Verify PEP authorization headers
    3. Strip security headers before forwarding to resource
    4. Inject resource-layer access tokens
    """

    def __init__(self):
        self._http = httpx.AsyncClient(timeout=30)
        self._request_count = 0

    async def forward_to_resource(self,
                                   path: str,
                                   method: str,
                                   headers: Dict[str, str],
                                   body: Optional[bytes]) -> httpx.Response:
        # Verify PEP authorization
        if headers.get("x-pep-authorized", "").lower() != "true":
            raise HTTPException(status_code=403, detail="Request not authorized by PEP")

        # Build resource headers (strip internal security headers)
        resource_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in (
                "host", "content-length",
                "x-pep-authorized", "x-pep-decision",
                "x-client-cert", "authorization"
            )
        }
        resource_headers["X-OVP2-Request-ID"] = str(uuid.uuid4())
        resource_headers["X-Forwarded-By"] = "OVP2"

        # Extract trust score for resource-level logging
        trust_score = headers.get("x-rat-trust-score", "0")
        resource_headers["X-Client-Trust-Score"] = trust_score

        self._request_count += 1
        try:
            resp = await self._http.request(
                method=method,
                url=f"{RESOURCE_URL}{path}",
                headers=resource_headers,
                content=body,
            )
            return resp
        except httpx.ConnectError:
            # Resource offline — return mock for demo
            return self._mock_resource_response(path, method, trust_score)

    def _mock_resource_response(self, path: str, method: str, trust_score: str) -> httpx.Response:
        """Mock resource response for demo/testing."""
        import httpx
        mock_data = {
            "resource": path,
            "method": method,
            "data": {"example": "resource_data", "timestamp": time.time()},
            "client_trust_score": float(trust_score) if trust_score else 0.0,
            "served_by": "OVP2-mock",
        }
        return httpx.Response(200, json=mock_data)


ovp2 = OVP2Proxy()


@ovp2_app.get("/health")
async def ovp2_health():
    return {"status": "ok", "component": "OVP2", "requests": ovp2._request_count}


@ovp2_app.api_route("/{path:path}",
                     methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def ovp2_proxy(path: str, request: Request):
    """Forward PEP-authorized requests to the resource server."""
    body = await request.body()
    resp = await ovp2.forward_to_resource(
        f"/{path}",
        request.method,
        dict(request.headers),
        body,
    )
    try:
        return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception:
        return JSONResponse({"data": resp.text}, status_code=resp.status_code)


# ================================================================== #
#  Ryu API Client — delegates flow management to Ryu OpenFlow app     #
# ================================================================== #

import os

RYU_API_URL = zta_settings["ryu_api_url"]


class RyuAPIClient:
    """
    HTTP client that calls the Ryu OpenFlow controller REST API.
    Falls back to in-memory simulation if Ryu is unreachable (dev mode).
    """

    def __init__(self, ryu_url: str = RYU_API_URL):
        self.ryu_url = ryu_url
        self._http   = httpx.AsyncClient(timeout=5)
        # Fallback in-memory store (used when Ryu is unreachable)
        self._fallback_flows: Dict[str, Dict] = {}
        self._segments:       Dict[str, Dict] = {}

    # ---- Flow Operations ---- #

    async def allow_session(self, session_id: str, src_ip: str,
                             dst_ip: str, trust_score: float) -> Dict:
        payload = {
            "session_id":  session_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "trust_score": trust_score,
        }
        return await self._post("/ztna/flows/allow", payload,
                                fallback_key=session_id,
                                fallback_value={**payload, "action": "ALLOW",
                                                "backend": "fallback"})

    async def deny_session(self, session_id: str, src_ip: str, dst_ip: str) -> Dict:
        payload = {"session_id": session_id, "src_ip": src_ip, "dst_ip": dst_ip}
        result  = await self._post("/ztna/flows/deny", payload,
                                   fallback_key=None,
                                   fallback_value={"status": "denied_fallback"})
        self._fallback_flows.pop(session_id, None)
        return result

    async def rate_limit_session(self, session_id: str, src_ip: str,
                                  dst_ip: str, trust_score: float) -> Dict:
        payload = {
            "session_id":  session_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "trust_score": trust_score,
        }
        return await self._post("/ztna/flows/rate-limit", payload,
                                fallback_key=session_id,
                                fallback_value={**payload, "action": "RATE_LIMITED",
                                                "backend": "fallback"})

    async def teardown_session(self, session_id: str) -> Dict:
        try:
            resp = await self._http.delete(
                f"{self.ryu_url}/ztna/flows/{session_id}"
            )
            return resp.json()
        except Exception as exc:
            logger.warning("[RyuClient] Teardown fallback for %s: %s", session_id, exc)
            self._fallback_flows.pop(session_id, None)
            return {"status": "teardown_fallback", "session_id": session_id}

    # ---- Micro-Segmentation (VLAN metadata) ---- #

    def create_micro_segment(self, session_id: str, user_id: str,
                              allowed_resources: list, rat_trust: float) -> Dict:
        segment = {
            "segment_id":       str(uuid.uuid4()),
            "session_id":       session_id,
            "user_id":          user_id,
            "allowed_resources": allowed_resources,
            "rat_trust_score":  rat_trust,
            "created_at":       time.time(),
            "vlan_id":          hash(session_id) % 4094,
        }
        self._segments[session_id] = segment
        logger.info("[RyuClient] Micro-segment created: session=%s vlan=%d",
                    session_id, segment["vlan_id"])
        return segment

    # ---- RAT Trust Enforcement ---- #

    async def enforce_rat_policy(self, session_id: str, src_ip: str,
                                  dst_ip: str, rat_trust: float):
        """Re-evaluate and update network flows based on new trust score."""
        if rat_trust < 0.40:
            logger.warning("[RyuClient] Trust critical (%.2f) — denying session %s",
                           rat_trust, session_id)
            await self.deny_session(session_id, src_ip, dst_ip)
        elif rat_trust < 0.60:
            logger.info("[RyuClient] Trust low (%.2f) — rate-limiting session %s",
                        rat_trust, session_id)
            await self.rate_limit_session(session_id, src_ip, dst_ip, rat_trust)
        else:
            logger.info("[RyuClient] Trust acceptable (%.2f) — updating allow flow %s",
                        rat_trust, session_id)
            await self.allow_session(session_id, src_ip, dst_ip, rat_trust)

    # ---- Queries ---- #

    async def list_flows(self) -> Dict:
        try:
            resp = await self._http.get(f"{self.ryu_url}/ztna/flows")
            return resp.json()
        except Exception:
            return {"flows": list(self._fallback_flows.values()),
                    "backend": "fallback"}

    async def list_switches(self) -> Dict:
        try:
            resp = await self._http.get(f"{self.ryu_url}/ztna/switches")
            return resp.json()
        except Exception:
            return {"switches": [], "backend": "fallback"}

    async def ryu_health(self) -> Dict:
        try:
            resp = await self._http.get(f"{self.ryu_url}/ztna/health")
            return resp.json()
        except Exception:
            return {"status": "unreachable", "backend": "fallback"}

    # ---- Internal ---- #

    async def _post(self, path: str, payload: Dict,
                    fallback_key: Optional[str], fallback_value: Dict) -> Dict:
        try:
            resp = await self._http.post(f"{self.ryu_url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("[RyuClient] Ryu unreachable (%s) — using fallback for %s",
                           exc, path)
            if fallback_key:
                self._fallback_flows[fallback_key] = fallback_value
            return fallback_value


# ================================================================== #
#  SDN Management FastAPI App (port 8084)                             #
#  Thin REST wrapper around RyuAPIClient for internal use             #
# ================================================================== #

sdn_app = FastAPI(
    title="SDN Management API",
    version="2.0.0",
    description="Proxies flow management requests to Ryu OpenFlow controller (:8085).",
)

sdn = RyuAPIClient()


@sdn_app.get("/health")
async def sdn_health():
    ryu_status = await sdn.ryu_health()
    return {
        "status":     "ok",
        "component":  "SDN-Management",
        "ryu_status": ryu_status,
        "segments":   len(sdn._segments),
    }


@sdn_app.post("/api/v1/flows/rate-limit")
@sdn_app.post("/ztna/flows/rate-limit")
async def api_rate_limit(request: Request):
    body = await request.json()
    result = await sdn.rate_limit_session(
        session_id  = body["session_id"],
        src_ip      = body["src_ip"],
        dst_ip      = body["dst_ip"],
        trust_score = body.get("trust_score", 0.5),
    )
    return result

@sdn_app.post("/api/v1/flows/allow")
@sdn_app.post("/ztna/flows/allow")
async def api_allow_flow(request: Request):
    body = await request.json()
    result = await sdn.allow_session(
        session_id  = body["session_id"],
        src_ip      = body["src_ip"],
        dst_ip      = body["dst_ip"],
        trust_score = body.get("trust_score", 0.7),
    )
    return result

@sdn_app.post("/api/v1/flows/deny")
@sdn_app.post("/ztna/flows/deny")
async def api_deny_flow(request: Request):
    body = await request.json()
    result = await sdn.deny_session(
        session_id = body["session_id"],
        src_ip     = body["src_ip"],
        dst_ip     = body["dst_ip"],
    )
    return result

@sdn_app.get("/api/v1/flows")
@sdn_app.get("/ztna/flows")
async def api_list_flows():
    return await sdn.list_flows()

@sdn_app.delete("/api/v1/sessions/{session_id}")
@sdn_app.delete("/ztna/flows/{session_id}")
async def api_teardown(session_id: str):
    return await sdn.teardown_session(session_id)


@sdn_app.post("/api/v1/enforce")
async def api_enforce(request: Request):
    body = await request.json()
    await sdn.enforce_rat_policy(
        session_id = body["session_id"],
        src_ip     = body.get("src_ip", ""),
        dst_ip     = body.get("dst_ip", ""),
        rat_trust  = body["rat_trust_score"],
    )
    return {"status": "enforced", "session_id": body["session_id"]}


@sdn_app.post("/api/v1/segments")
async def api_create_segment(request: Request):
    body = await request.json()
    seg  = sdn.create_micro_segment(
        session_id        = body["session_id"],
        user_id           = body["user_id"],
        allowed_resources = body.get("allowed_resources", []),
        rat_trust         = body.get("rat_trust_score", 0.5),
    )
    return seg


@sdn_app.get("/api/v1/flows")
async def api_list_flows():
    return await sdn.list_flows()


@sdn_app.get("/api/v1/switches")
async def api_list_switches():
    return await sdn.list_switches()


@sdn_app.delete("/api/v1/sessions/{session_id}")
async def api_teardown(session_id: str):
    return await sdn.teardown_session(session_id)


# ================================================================== #
#  Startup helpers                                                     #
# ================================================================== #

async def run_all():
    config1 = uvicorn.Config(ovp1_app, host="0.0.0.0", port=8080, log_level="info")
    config2 = uvicorn.Config(ovp2_app, host="0.0.0.0", port=8083, log_level="info")
    config3 = uvicorn.Config(sdn_app,  host="0.0.0.0", port=8084, log_level="info")
    server1 = uvicorn.Server(config1)
    server2 = uvicorn.Server(config2)
    server3 = uvicorn.Server(config3)
    await asyncio.gather(server1.serve(), server2.serve(), server3.serve())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    asyncio.run(run_all())
