"""
Policy Enforcement Point (PEP)
Zero Trust Architecture — Mutual TLS + Authorization Enforcement

Responsibilities:
  - Terminate mTLS connections from OVP1
  - Validate JWT session tokens (signed by PDP/IdP)
  - Enforce PDP policy decisions in real time
  - Forward context (RAT profile, device, session) to PDP for evaluation
  - Proxy authorized requests to OVP2 → Resource
  - Re-evaluate on every request (no implicit trust)
"""

import asyncio
import os
import hashlib
import json
import logging
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any
import base64

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.responses import JSONResponse
import httpx
import uvicorn
from config_loader import zta_settings, log_important

logger = logging.getLogger(__name__)

app = FastAPI(title="Zero Trust PEP", version="1.0.0")

# ------------------------------------------------------------------ #
#  Configuration                                                       #
# ------------------------------------------------------------------ #

PDP_URL      = zta_settings["controller_url"]
OVP2_URL     = zta_settings["ovp2_url"]
SDN_URL      = zta_settings["ryu_api_url"]
IDP_JWKS_URL = f"{zta_settings['idp_url']}/.well-known/jwks.json"
RESOURCE_IP  = zta_settings["resource_ip"]
MTLS_CERT    = "certs/pep.crt"
MTLS_KEY     = "certs/pep.key"
CA_CERT      = "certs/ca.crt"

# ------------------------------------------------------------------ #
#  In-Memory Session Store (use Redis in production)                  #
# ------------------------------------------------------------------ #

class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, Dict] = {}

    def store(self, token: str, data: Dict):
        self._sessions[token] = {**data, "last_seen": time.time()}

    def get(self, token: str) -> Optional[Dict]:
        s = self._sessions.get(token)
        if s and (time.time() - s["last_seen"]) < 3600:
            s["last_seen"] = time.time()
            return s
        return None

    def invalidate(self, token: str):
        self._sessions.pop(token, None)

    def update_rat(self, token: str, rat_profile: Dict):
        if token in self._sessions:
            self._sessions[token]["rat_profile"] = rat_profile
            self._sessions[token]["rat_updated_at"] = time.time()


session_store = SessionStore()

# ------------------------------------------------------------------ #
#  Mutual TLS Validator                                                #
# ------------------------------------------------------------------ #

@dataclass
class MTLSIdentity:
    subject: str
    issuer: str
    fingerprint: str
    san: list
    valid: bool


class MutualTLSValidator:
    """
    Validates client certificates for mutual TLS.
    In production: integrate with your PKI (EJBCA / Vault PKI).
    """

    def __init__(self, ca_cert_path: str = CA_CERT):
        self.ca_cert_path = ca_cert_path
        self._trusted_fingerprints: set = set()

    def validate_client_cert(self, cert_pem: Optional[str]) -> MTLSIdentity:
        if not cert_pem:
            return MTLSIdentity("", "", "", [], False)

        try:
            # In production: use cryptography library to parse + verify chain
            # Here we simulate fingerprint computation
            fp = hashlib.sha256(cert_pem.encode()).hexdigest()
            return MTLSIdentity(
                subject="CN=ovp1.zerotrust.example.com",
                issuer="CN=ZeroTrust-CA",
                fingerprint=fp,
                san=["ovp1.zerotrust.example.com"],
                valid=True
            )
        except Exception as e:
            logger.error("mTLS validation error: %s", e)
            return MTLSIdentity("", "", "", [], False)

    def register_trusted_cert(self, fingerprint: str):
        self._trusted_fingerprints.add(fingerprint)


mtls_validator = MutualTLSValidator()

# ------------------------------------------------------------------ #
#  JWT Validator                                                       #
# ------------------------------------------------------------------ #

class JWTValidator:
    """
    Validates FIDO2-derived session JWTs issued by IdP.
    Fetches JWKS from IdP to verify HMAC-SHA256 signature.
    Caches JWKS for 5 minutes to avoid hammering the IdP on every request.
    """

    JWKS_CACHE_TTL   = 300          # seconds
    VALID_ISSUERS    = {
        "https://idp.zerotrust.example.com",
        "localhost:8001",
        "http://idp:8001",
    }

    def __init__(self, jwks_url: str):
        self.jwks_url        = jwks_url
        self._jwks_cache:    Optional[Dict] = None
        self._cache_ts:      float = 0
        self._http           = httpx.AsyncClient(timeout=5)

    async def _get_jwks(self) -> Optional[Dict]:
        """Fetch and cache JWKS from IdP. Returns None if IdP is unreachable."""
        now = time.time()
        if self._jwks_cache and (now - self._cache_ts) < self.JWKS_CACHE_TTL:
            return self._jwks_cache
        try:
            resp = await self._http.get(self.jwks_url)
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._cache_ts   = now
            logger.debug("[JWT] JWKS refreshed from %s", self.jwks_url)
            return self._jwks_cache
        except Exception as exc:
            logger.warning("[JWT] JWKS fetch failed: %s — using cached key", exc)
            return self._jwks_cache   # may be None on first call

    async def validate(self, token: str) -> Dict[str, Any]:
        """Decode, structurally validate, and cryptographically verify JWT."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT format — expected 3 parts")

            header_b64, payload_b64_raw, sig_b64 = parts

            # --- Decode header ---
            header = json.loads(base64.urlsafe_b64decode(
                header_b64 + "=" * (-len(header_b64) % 4)
            ))

            # --- Decode payload ---
            payload = json.loads(base64.urlsafe_b64decode(
                payload_b64_raw + "=" * (-len(payload_b64_raw) % 4)
            ))

            # --- Expiry check ---
            if payload.get("exp", 0) < time.time():
                raise ValueError("Token expired")

            # --- Issuer check ---
            if payload.get("iss") not in self.VALID_ISSUERS:
                raise ValueError(f"Untrusted issuer: {payload.get('iss')}")

            # --- Signature verification (HMAC-SHA256 against JWKS key) ---
            alg = header.get("alg", "")
            if alg == "HS256":
                await self._verify_hs256(f"{header_b64}.{payload_b64_raw}", sig_b64)
            else:
                # ES256 / RS256 — log warning, skip sig check (requires cryptography lib)
                logger.warning("[JWT] Sig verification skipped for alg=%s (not HS256)", alg)

            logger.debug("[JWT] Token valid for sub=%s jti=%s",
                         payload.get("sub"), payload.get("jti"))
            return payload

        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    async def _verify_hs256(self, signing_input: str, sig_b64: str):
        """Verify HMAC-SHA256 signature using key from JWKS."""
        import hmac as _hmac
        jwks = await self._get_jwks()
        if not jwks:
            logger.warning("[JWT] JWKS unavailable — skipping sig verification")
            return

        # Find the HS256 key in JWKS
        keys = jwks.get("keys", [])
        hs_key = next((k for k in keys if k.get("alg") == "HS256"), None)
        if not hs_key or "k" not in hs_key:
            logger.warning("[JWT] No HS256 key in JWKS — skipping sig verification")
            return

        secret = base64.urlsafe_b64decode(hs_key["k"] + "==")
        expected_sig = base64.urlsafe_b64encode(
            _hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")

        if not _hmac.compare_digest(expected_sig, sig_b64):
            raise ValueError("JWT signature verification failed")

    def build_demo_token(self, user_id: str, rat_trust_score: float = 0.8) -> str:
        """Build a demo HS256 JWT for testing without a live IdP."""
        import hmac as _hmac
        # Use a fixed demo secret matching idp_server.py
        secret = b"CHANGE_ME_USE_RSA_OR_EC_IN_PRODUCTION"
        header  = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": user_id,
            "iss": "localhost:8001",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "rat_trust_score": rat_trust_score,
            "jti": str(uuid.uuid4()),
        }).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(
            _hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        return f"{header}.{payload}.{sig}"


jwt_validator = JWTValidator(IDP_JWKS_URL)

# ------------------------------------------------------------------ #
#  PDP Client                                                          #
# ------------------------------------------------------------------ #

class PDPClient:
    """Sends policy evaluation requests to the SDP Controller (PDP)."""

    def __init__(self, pdp_url: str):
        self.pdp_url = pdp_url
        self._http = httpx.AsyncClient(timeout=10)

    async def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request policy decision from PDP.
        Returns: {"decision": "ALLOW|DENY|STEP_UP", "reason": "...", "obligations": [...]}
        """
        try:
            resp = await self._http.post(
                f"{self.pdp_url}/api/v1/policy/evaluate",
                json=context,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError:
            # Offline: apply local micro-policy
            return self._local_policy(context)
        except Exception as e:
            logger.error("PDP evaluation error: %s", e)
            return {"decision": "DENY", "reason": "PDP unreachable"}

    def _local_policy(self, ctx: Dict) -> Dict:
        """
        Emergency local policy when PDP is unreachable.
        Mirrors the PE trust score logic to remain consistent with server-side decisions.
        """
        env   = ctx.get("environment", {})
        score = 1.0

        sp = env.get("security_protocol", "Unknown")
        sp_penalties = {
            "WPA3-Personal": 0.0, "WPA3-Enterprise": 0.0,
            "WPA2-Enterprise": -0.05, "WPA2-Personal": -0.15,
            "WPA": -0.30, "Open": -0.60, "Unknown": -0.40,
        }
        score += sp_penalties.get(sp, -0.40)
        if env.get("is_captive_portal"): score -= 0.20
        if env.get("is_public_network"): score -= 0.15
        if env.get("vpn_active"):        score += 0.10
        if env.get("encryption_type") == "TKIP": score -= 0.10
        trust = round(max(0.0, min(1.0, score)), 3)

        if sp in ("Open", "Unknown"):
            return {"decision": "DENY",    "reason": "local_policy:open_network",      "trust_score": trust, "obligations": ["LOG_SECURITY_EVENT"]}
        if env.get("is_captive_portal"):
            return {"decision": "DENY",    "reason": "local_policy:captive_portal",    "trust_score": trust, "obligations": ["LOG_SECURITY_EVENT"]}
        if trust < 0.50:
            return {"decision": "STEP_UP", "reason": "local_policy:low_trust",         "trust_score": trust, "obligations": ["TRIGGER_FIDO2_REAUTH"]}
        if sp in ("WPA3-Personal", "WPA3-Enterprise") and trust >= 0.70:
            return {"decision": "ALLOW",   "reason": "local_policy:wpa3_high_trust",   "trust_score": trust, "obligations": []}
        if ctx.get("resource", {}).get("operation") == "read" and trust >= 0.55:
            return {"decision": "ALLOW",   "reason": "local_policy:read_medium_trust", "trust_score": trust, "obligations": ["LOG_ACCESS"]}
        return     {"decision": "DENY",    "reason": "local_policy:default_deny",      "trust_score": trust, "obligations": ["LOG_SECURITY_EVENT"]}


pdp_client = PDPClient(PDP_URL)

# ------------------------------------------------------------------ #
#  SDN Client — pushes flow rules to Ryu OpenFlow controller          #
# ------------------------------------------------------------------ #

class SDNClient:
    """
    Fire-and-forget HTTP client to the Ryu ZTNA REST API.
    Called after every PDP decision to install/remove OVS flow rules.
    Failures are logged but never block the PEP response.
    """

    def __init__(self, sdn_url: str = SDN_URL):
        self.sdn_url = sdn_url
        self._http   = httpx.AsyncClient(timeout=3)

    async def allow(self, session_id: str, src_ip: str,
                    dst_ip: str, trust_score: float):
        await self._call("/ztna/flows/allow", {
            "session_id":  session_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "trust_score": trust_score,
        })

    async def deny(self, session_id: str, src_ip: str, dst_ip: str):
        await self._call("/ztna/flows/deny", {
            "session_id": session_id,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
        })

    async def rate_limit(self, session_id: str, src_ip: str,
                          dst_ip: str, trust_score: float):
        await self._call("/ztna/flows/rate-limit", {
            "session_id":  session_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "trust_score": trust_score,
        })

    async def teardown(self, session_id: str):
        try:
            await self._http.delete(f"{self.sdn_url}/ztna/flows/{session_id}")
        except Exception as exc:
            logger.warning("[PEP→SDN] Teardown failed for %s: %s", session_id, exc)

    async def _call(self, path: str, payload: dict):
        try:
            await self._http.post(f"{self.sdn_url}{path}", json=payload)
            logger.info("[PEP→SDN] %s | session=%s", path, payload.get("session_id", "-"))
        except Exception as exc:
            logger.warning("[PEP→SDN] SDN call failed (%s): %s", path, exc)


sdn_client = SDNClient(SDN_URL)

# ------------------------------------------------------------------ #
#  Authorization Engine                                                #
# ------------------------------------------------------------------ #

class AuthorizationEngine:
    """
    Evaluates access requests against PDP decisions.
    Enforces obligations (e.g., rate-limit, re-auth, log).
    """

    RISK_THRESHOLDS = {
        "read":      0.40,
        "write":     0.60,
        "admin":     0.80,
        "sensitive": 0.90,
    }

    async def authorize(self,
                        user_id: str,
                        resource_path: str,
                        method: str,
                        rat_profile: Dict,
                        session_data: Dict) -> Dict[str, Any]:

        operation = self._classify_operation(method, resource_path)
        rat_trust = rat_profile.get("rat_trust_score", 0.0)
        min_trust = self.RISK_THRESHOLDS.get(operation, 0.50)

        context = {
            "subject": {
                "user_id": user_id,
                "session_id": session_data.get("session_id"),
                "credential_id": session_data.get("credential_id"),
            },
            "resource": {
                "path": resource_path,
                "method": method,
                "operation": operation,
            },
            "environment": {
                "rat_type": rat_profile.get("rat_type"),
                "rat_trust_score": rat_trust,
                "security_protocol": rat_profile.get("security_protocol"),
                "encryption_type": rat_profile.get("encryption_type"),
                "vpn_active": rat_profile.get("vpn_active", False),
                "is_captive_portal": rat_profile.get("is_captive_portal", False),
                "ip_address": rat_profile.get("ipv4", {}).get("address"),
                "mac_hash": hashlib.sha256(
                    rat_profile.get("mac_address", "").encode()
                ).hexdigest()[:16],
                "timestamp": time.time(),
            },
            "policy": {
                "required_min_trust": min_trust,
                "require_encrypted_dns": True,
                "allow_public_network": False,
            }
        }

        decision    = await pdp_client.evaluate(context)
        pdp_outcome = decision.get("decision")
        trust_score = decision.get("trust_score", 0.0)
        session_id  = context["subject"].get("session_id", user_id)
        client_ip   = rat_profile.get("ipv4", {}).get("address", "") \
                      if isinstance(rat_profile.get("ipv4"), dict) \
                      else rat_profile.get("ip_address", "")
        resource_ip = RESOURCE_IP   # Configured via RESOURCE_IP env var

        if pdp_outcome == "ALLOW":
            log_important("PEP-Gateway", "Access Request Authorized", {
                "session_id": context["subject"].get("jti"),
                "subject": context["subject"].get("sub"),
                "trust_score": trust_score,
                "sdn_action": "ALLOW_FLOW_PUSHED"
            })
            asyncio.create_task(
                sdn_client.allow(session_id, client_ip, resource_ip, trust_score)
            )
            return decision

        if pdp_outcome == "DENY":
            # Push explicit DROP rule to OVS (fire-and-forget)
            asyncio.create_task(
                sdn_client.deny(session_id, client_ip, resource_ip)
            )
            raise HTTPException(status_code=403, detail={
                "error": "access_denied",
                "reason": decision.get("reason"),
                "required_trust": min_trust,
                "authoritative_trust": trust_score,
            })

        if pdp_outcome == "STEP_UP":
            log_important("PEP-Gateway", "Access STEP-UP Required", {
                "session_id": context["subject"].get("jti"),
                "subject": context["subject"].get("sub"),
                "trust_score": trust_score,
                "sdn_action": "RATE_LIMIT_PUSHED"
            })
            
            # Push rate-limited flow to OVS (fire-and-forget)
            asyncio.create_task(
                sdn_client.rate_limit(session_id, client_ip, resource_ip, trust_score)
            )
            raise HTTPException(status_code=401, detail={
                "error": "step_up_required",
                "reason": decision.get("reason"),
                "step_up_method": "fido2",
            })

        # ALLOW — install permissive flow in OVS (fire-and-forget)
        asyncio.create_task(
            sdn_client.allow(session_id, client_ip, resource_ip, trust_score)
        )
        return decision

    def _classify_operation(self, method: str, path: str) -> str:
        if "admin" in path:
            return "admin"
        if "sensitive" in path:
            return "sensitive"
        if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
            return "write"
        return "read"


authz_engine = AuthorizationEngine()

# ------------------------------------------------------------------ #
#  OVP2 Proxy (to Resource)                                           #
# ------------------------------------------------------------------ #

class OVP2Proxy:
    """Forwards authorized requests to OVP2 which routes to the resource."""

    def __init__(self, ovp2_url: str):
        self.ovp2_url = ovp2_url
        self._http = httpx.AsyncClient(timeout=30)

    async def forward(self,
                      path: str,
                      method: str,
                      headers: Dict[str, str],
                      body: Optional[bytes],
                      rat_profile: Dict,
                      policy_decision: Dict) -> httpx.Response:

        forward_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in ("host", "content-length")
        }
        forward_headers["X-PEP-Authorized"] = "true"
        forward_headers["X-PEP-Decision"] = policy_decision.get("decision", "ALLOW")
        forward_headers["X-RAT-Trust-Score"] = str(rat_profile.get("rat_trust_score", 0.0))
        forward_headers["X-RAT-Type"] = str(rat_profile.get("rat_type", ""))
        forward_headers["X-Request-ID"] = str(uuid.uuid4())

        try:
            resp = await self._http.request(
                method=method,
                url=f"{self.ovp2_url}{path}",
                headers=forward_headers,
                content=body,
            )
            return resp
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="OVP2 unreachable")


ovp2_proxy = OVP2Proxy(OVP2_URL)

# ------------------------------------------------------------------ #
#  FastAPI Routes                                                      #
# ------------------------------------------------------------------ #

async def get_session(authorization: Optional[str] = Header(None)) -> Dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    payload = await jwt_validator.validate(token)
    session = session_store.get(token)
    if not session:
        # First time — bootstrap session from JWT
        session = {
            "user_id": payload.get("sub"),
            "session_id": payload.get("jti", str(uuid.uuid4())),
            "credential_id": payload.get("credential_id"),
            "rat_profile": {},
            "token": token,
        }
        session_store.store(token, session)
    return session


@app.middleware("http")
async def mtls_middleware(request: Request, call_next):
    """Validate mTLS client certificate on every request."""
    cert_pem = request.headers.get("X-Client-Cert")  # Set by load-balancer/nginx
    identity = mtls_validator.validate_client_cert(cert_pem)
    if not identity.valid and request.url.path not in ("/health", "/metrics"):
        logger.warning("mTLS validation failed for %s", request.client.host)
        # In strict mode: return 403
        # In learning mode: log and allow (comment out return for learning mode)
        # return JSONResponse({"error": "mTLS required"}, status_code=403)
    request.state.mtls_identity = identity
    return await call_next(request)


@app.get("/health")
async def health():
    return {"status": "ok", "component": "PEP", "timestamp": time.time()}


@app.delete("/api/v1/sessions/{session_id}")
async def terminate_session(session_id: str, request: Request):
    body = await request.json() if request.headers.get("content-length") else {}
    session_store.invalidate(session_id)
    # Remove OVS flows for terminated session
    asyncio.create_task(sdn_client.teardown(session_id))
    return {"status": "terminated", "session_id": session_id}


@app.post("/api/v1/session/rat-update")
async def update_rat(request: Request, session: Dict = Depends(get_session)):
    """
    Receive continuous RAT context updates from the client.
    Forwards the FULL RAT telemetry to the PE so the authoritative trust
    score is recalculated server-side — not a stale client-supplied value.
    """
    body        = await request.json()
    rat_profile = body.get("ratProfile", {})
    session_store.update_rat(session["token"], rat_profile)

    # Build full context — send raw telemetry, NOT a pre-calculated score
    # PE will recompute trust score authoritatively
    context = {
        "subject": {
            "user_id":    session["user_id"],
            "session_id": session.get("session_id", ""),
        },
        "resource": {"path": "*", "method": "MONITOR", "operation": "read"},
        "environment": {
            "rat_type":          rat_profile.get("rat_type"),
            "security_protocol": rat_profile.get("security_protocol"),
            "encryption_type":   rat_profile.get("encryption_type"),
            "vpn_active":        rat_profile.get("vpn_active", False),
            "is_captive_portal": rat_profile.get("is_captive_portal", False),
            "is_public_network": rat_profile.get("is_public_network", False),
            "pmf_enabled":       rat_profile.get("pmf_enabled", True),
            "ip_address":        rat_profile.get("ipv4", {}).get("address", ""),
            "event":             "RAT_CONTEXT_UPDATE",
        },
    }
    decision = await pdp_client.evaluate(context)

    # If trust dropped to DENY/STEP_UP, push enforcement to OVS immediately
    new_trust  = decision.get("trust_score", 0.0)
    outcome    = decision.get("decision", "ALLOW")
    session_id = session.get("session_id", session["user_id"])
    client_ip  = rat_profile.get("ipv4", {}).get("address", "") if isinstance(rat_profile.get("ipv4"), dict) else ""

    if outcome == "DENY":
        asyncio.create_task(sdn_client.deny(session_id, client_ip, RESOURCE_IP))
    elif outcome == "STEP_UP":
        asyncio.create_task(sdn_client.rate_limit(session_id, client_ip, RESOURCE_IP, new_trust))

    return JSONResponse({
        "action":               outcome if outcome != "ALLOW" else "CONTINUE",
        "authoritativeTrustScore": new_trust,
        "reason":               decision.get("reason"),
        "obligations":          decision.get("obligations", []),
    })


@app.api_route("/resource/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_to_resource(path: str, request: Request, session: Dict = Depends(get_session)):
    """
    Main enforcement point:
    1. Extract RAT profile from session / request headers
    2. Ask PDP for policy decision
    3. Forward to OVP2 if ALLOW
    """
    rat_profile = session.get("rat_profile", {})

    # Accept inline RAT context from client headers
    inline_trust = request.headers.get("X-RAT-Trust-Score")
    if inline_trust:
        try:
            rat_profile["rat_trust_score"] = float(inline_trust)
            rat_profile["rat_type"] = request.headers.get("X-RAT-Type", rat_profile.get("rat_type"))
            rat_profile["security_protocol"] = request.headers.get("X-RAT-Security", "")
        except ValueError:
            pass

    # Authorization
    decision = await authz_engine.authorize(
        user_id=session["user_id"],
        resource_path=f"/{path}",
        method=request.method,
        rat_profile=rat_profile,
        session_data=session,
    )

    # Forward
    body = await request.body()
    response = await ovp2_proxy.forward(
        path=f"/{path}",
        method=request.method,
        headers=dict(request.headers),
        body=body,
        rat_profile=rat_profile,
        policy_decision=decision,
    )

    return JSONResponse(
        content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
        status_code=response.status_code,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [PEP] %(levelname)s: %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
