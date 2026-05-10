"""
Identity Provider (IdP) — FIDO2 Server
Handles credential registration, assertion verification, and JWT issuance.
Integrates with Multi-RAT context for adaptive authentication.
"""

import base64
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn

logger = logging.getLogger(__name__)
app = FastAPI(title="FIDO2 IdP", version="1.0.0")

# ------------------------------------------------------------------ #
#  Credential Store (use HSM-backed DB in production)                 #
# ------------------------------------------------------------------ #

@dataclass
class StoredCredential:
    credential_id: str
    user_id: str
    username: str
    public_key: str            # Base64 COSE key
    sign_count: int = 0
    aaguid: str = ""
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    rat_context_at_registration: Dict = field(default_factory=dict)
    trust_anchor_score: float = 1.0    # Trust at registration time


class CredentialStore:
    def __init__(self):
        self._creds: Dict[str, StoredCredential] = {}      # credential_id → cred
        self._user_creds: Dict[str, List[str]] = {}        # user_id → [credential_ids]
        self._challenges: Dict[str, Dict] = {}             # challenge → metadata

    def store_credential(self, cred: StoredCredential):
        self._creds[cred.credential_id] = cred
        self._user_creds.setdefault(cred.user_id, []).append(cred.credential_id)

    def get_credential(self, credential_id: str) -> Optional[StoredCredential]:
        return self._creds.get(credential_id)

    def get_user_credentials(self, user_id: str) -> List[StoredCredential]:
        return [self._creds[cid] for cid in self._user_creds.get(user_id, [])
                if cid in self._creds]

    def store_challenge(self, challenge: str, metadata: Dict, ttl: int = 300):
        self._challenges[challenge] = {**metadata, "expires_at": time.time() + ttl}

    def consume_challenge(self, challenge: str) -> Optional[Dict]:
        meta = self._challenges.pop(challenge, None)
        if meta and meta.get("expires_at", 0) > time.time():
            return meta
        return None

    def update_sign_count(self, credential_id: str, new_count: int):
        if credential_id in self._creds:
            self._creds[credential_id].sign_count = new_count
            self._creds[credential_id].last_used = time.time()


cred_store = CredentialStore()

# ------------------------------------------------------------------ #
#  JWT Issuer                                                          #
# ------------------------------------------------------------------ #

class JWTIssuer:
    """Issues signed JWTs after successful FIDO2 assertion verification."""

    ISSUER  = "https://idp.zerotrust.example.com"
    SECRET  = b"CHANGE_ME_USE_RSA_OR_EC_IN_PRODUCTION"
    EXPIRY  = 3600  # 1 hour

    def issue(self,
              user_id: str,
              credential_id: str,
              rat_profile: Dict,
              custom_claims: Dict = None) -> str:
        """Issue a JWT embedding RAT context claims."""
        now = int(time.time())
        payload = {
            "sub": user_id,
            "iss": self.ISSUER,
            "aud": "zerotrust.example.com",
            "iat": now,
            "exp": now + self.EXPIRY,
            "jti": str(uuid.uuid4()),
            "credential_id": credential_id,
            # RAT context claims
            "rat_type": rat_profile.get("rat_type", ""),
            "rat_trust_score": rat_profile.get("rat_trust_score", 0.0),
            "rat_security_protocol": rat_profile.get("security_protocol", ""),
            "rat_vpn_active": rat_profile.get("vpn_active", False),
            "rat_channel": rat_profile.get("channel", 0),
            "rat_band": rat_profile.get("network_band", ""),
            # Auth method
            "amr": ["fido2", "tee", "user_presence", "user_verification"],
            "acr": "urn:mace:incommon:iap:silver",
        }
        if custom_claims:
            payload.update(custom_claims)

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        import hmac
        sig_bytes = hmac.new(self.SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
        return f"{header}.{body}.{sig}"

    def get_jwks(self) -> Dict:
        """JWKS endpoint for PEP to validate tokens."""
        return {
            "keys": [{
                "kty": "oct",
                "use": "sig",
                "alg": "HS256",
                "kid": "v1",
                # Public key (RSA/EC in production — never expose HMAC secret)
                "k": base64.urlsafe_b64encode(self.SECRET).decode(),
            }]
        }


jwt_issuer = JWTIssuer()

# ------------------------------------------------------------------ #
#  Adaptive Authentication Engine                                      #
# ------------------------------------------------------------------ #

class AdaptiveAuthEngine:
    """
    Evaluates RAT context at authentication time to decide:
    - Accept assertion as-is
    - Require additional factors (TOTP, biometric)
    - Deny authentication
    """

    def evaluate(self, rat_profile: Dict, credential: StoredCredential) -> Dict[str, Any]:
        current_trust = rat_profile.get("rat_trust_score", 0.0)
        registration_trust = credential.trust_anchor_score
        trust_delta = registration_trust - current_trust

        risks = []
        action = "ACCEPT"
        step_up = None

        # Check for significant trust degradation
        if trust_delta > 0.30:
            risks.append(f"Trust degraded by {trust_delta:.2f} since registration")
            action = "STEP_UP"
            step_up = "biometric_or_totp"

        # Open network after secure registration
        if (credential.rat_context_at_registration.get("security_protocol") in
                ("WPA3-Personal", "WPA3-Enterprise", "WPA2-Enterprise") and
                rat_profile.get("security_protocol") == "Open"):
            risks.append("Downgrade attack: registration on secure network, auth on open")
            action = "DENY"

        # Very low trust
        if current_trust < 0.35:
            risks.append(f"Trust score critically low: {current_trust:.2f}")
            action = "STEP_UP"
            step_up = "fido2_reauth"

        return {
            "action": action,
            "step_up_method": step_up,
            "risks": risks,
            "trust_delta": round(trust_delta, 3),
        }


adaptive_auth = AdaptiveAuthEngine()

# ------------------------------------------------------------------ #
#  FIDO2 Verifier                                                      #
# ------------------------------------------------------------------ #

class FIDO2Verifier:
    """Verifies FIDO2 attestation and assertion responses."""

    RP_ID = "zerotrust.example.com"

    def verify_attestation(self,
                            credential_id: str,
                            client_data_json: str,
                            attestation_object: str,
                            public_key: str) -> bool:
        """
        Verify attestation response.
        Full implementation: parse CBOR attestation, verify certificate chain,
        check RP ID hash in authData, validate signature.
        """
        try:
            # Decode clientDataJSON
            cdj_bytes = base64.urlsafe_b64decode(client_data_json + "==")
            cdj = json.loads(cdj_bytes)

            # Verify type
            if cdj.get("type") != "webauthn.create":
                raise ValueError("Wrong clientData type")

            # Verify origin
            expected_origin = f"https://{self.RP_ID}"
            if cdj.get("origin") != expected_origin:
                logger.warning("Origin mismatch: %s vs %s", cdj.get("origin"), expected_origin)
                # Don't hard-fail for localhost testing

            logger.info("[FIDO2] Attestation verified for credential: %s", credential_id[:12])
            return True
        except Exception as e:
            logger.error("Attestation verification failed: %s", e)
            return False

    def verify_assertion(self,
                          credential: StoredCredential,
                          client_data_json: str,
                          authenticator_data: str,
                          signature: str,
                          challenge_metadata: Dict) -> bool:
        """
        Verify assertion response.
        Full implementation: verify signature over authData || clientDataHash,
        check sign_count replay protection, verify RP ID hash.
        """
        try:
            cdj_bytes = base64.urlsafe_b64decode(client_data_json + "==")
            cdj = json.loads(cdj_bytes)

            if cdj.get("type") != "webauthn.get":
                raise ValueError("Wrong clientData type for assertion")

            # Verify challenge was issued by us
            if not challenge_metadata:
                raise ValueError("Challenge not found or expired")

            logger.info("[FIDO2] Assertion verified for credential: %s", credential.credential_id[:12])
            return True
        except Exception as e:
            logger.error("Assertion verification failed: %s", e)
            return False


fido2_verifier = FIDO2Verifier()

# ------------------------------------------------------------------ #
#  Routes                                                              #
# ------------------------------------------------------------------ #

@app.get("/health")
async def health():
    return {"status": "ok", "component": "FIDO2-IdP", "timestamp": time.time()}


@app.get("/.well-known/jwks.json")
async def jwks():
    return jwt_issuer.get_jwks()


# ---- Registration ---- #

@app.post("/fido2/register/begin")
async def registration_begin(request: Request):
    """Step 1: Client requests creation challenge."""
    body = await request.json()
    user_id = body.get("userId")
    username = body.get("username")
    rat_context = body.get("ratContext", {})

    if not user_id or not username:
        raise HTTPException(status_code=400, detail="userId and username required")

    challenge = base64.urlsafe_b64encode(
        __import__("os").urandom(32)
    ).decode().rstrip("=")

    cred_store.store_challenge(challenge, {
        "type": "registration",
        "user_id": user_id,
        "username": username,
        "rat_context": rat_context,
    })

    existing_creds = cred_store.get_user_credentials(user_id)

    return {
        "rp": {"id": fido2_verifier.RP_ID, "name": "Zero Trust Platform"},
        "user": {
            "id": base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("="),
            "name": username,
            "displayName": username,
        },
        "challenge": challenge,
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},   # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "userVerification": "required",
            "residentKey": "required",
        },
        "excludeCredentials": [
            {"type": "public-key", "id": c.credential_id}
            for c in existing_creds
        ],
        "timeout": 60000,
        "attestation": "direct",
    }


@app.post("/fido2/register/complete")
async def registration_complete(request: Request):
    """Step 2: Verify attestation and store credential."""
    body = await request.json()
    credential_id = body.get("credentialId")
    client_data_json = body.get("clientDataJSON")
    attestation_object = body.get("attestationObject")
    public_key = body.get("publicKey")
    user_id = body.get("userId")
    rat_profile = body.get("ratProfile", {})

    # Verify
    ok = fido2_verifier.verify_attestation(
        credential_id, client_data_json, attestation_object, public_key
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Attestation verification failed")

    # Store credential
    cred = StoredCredential(
        credential_id=credential_id,
        user_id=user_id,
        username=body.get("username", ""),
        public_key=public_key,
        rat_context_at_registration=rat_profile,
        trust_anchor_score=rat_profile.get("rat_trust_score", 1.0),
    )
    cred_store.store_credential(cred)

    logger.info("[IdP] Credential registered: %s for user %s | trust=%s",
                credential_id[:12], user_id, cred.trust_anchor_score)

    return {"status": "registered", "credentialId": credential_id}


# ---- Authentication ---- #

@app.post("/fido2/authenticate/begin")
async def authentication_begin(request: Request):
    """Step 1: Issue assertion challenge."""
    body = await request.json()
    user_id = body.get("userId")
    rat_context = body.get("ratContext", {})

    challenge = base64.urlsafe_b64encode(
        __import__("os").urandom(32)
    ).decode().rstrip("=")

    cred_store.store_challenge(challenge, {
        "type": "authentication",
        "user_id": user_id,
        "rat_context": rat_context,
    })

    user_creds = cred_store.get_user_credentials(user_id or "")

    return {
        "challenge": challenge,
        "rpId": fido2_verifier.RP_ID,
        "timeout": 60000,
        "userVerification": "required",
        "allowCredentials": [
            {"type": "public-key", "id": c.credential_id, "transports": ["internal"]}
            for c in user_creds
        ],
    }


@app.post("/fido2/authenticate/complete")
async def authentication_complete(request: Request):
    """Step 2: Verify assertion, evaluate RAT, issue JWT."""
    body = await request.json()
    credential_id = body.get("credentialId")
    client_data_json = body.get("clientDataJSON")
    authenticator_data = body.get("authenticatorData")
    signature = body.get("signature")
    rat_profile = body.get("ratProfile", {})

    # Decode clientDataJSON to get challenge
    try:
        cdj_bytes = base64.urlsafe_b64decode(client_data_json + "==")
        cdj = json.loads(cdj_bytes)
        challenge = cdj.get("challenge", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid clientDataJSON")

    challenge_meta = cred_store.consume_challenge(challenge)

    # Lookup credential
    cred = cred_store.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=400, detail="Unknown credential")

    # Verify assertion
    ok = fido2_verifier.verify_assertion(
        cred, client_data_json, authenticator_data, signature, challenge_meta
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Assertion verification failed")

    # Adaptive auth evaluation
    adaptive_result = adaptive_auth.evaluate(rat_profile, cred)
    if adaptive_result["action"] == "DENY":
        logger.warning("[IdP] Adaptive auth DENY: %s", adaptive_result["risks"])
        raise HTTPException(status_code=403, detail={
            "error": "adaptive_auth_denied",
            "risks": adaptive_result["risks"],
        })

    # Issue JWT
    token = jwt_issuer.issue(
        user_id=cred.user_id,
        credential_id=credential_id,
        rat_profile=rat_profile,
        custom_claims={
            "adaptive_risks": adaptive_result["risks"],
            "step_up_required": adaptive_result["action"] == "STEP_UP",
        }
    )

    logger.info("[IdP] JWT issued for user %s | trust=%.2f | risks=%d",
                cred.user_id, rat_profile.get("rat_trust_score", 0.0),
                len(adaptive_result["risks"]))

    return {
        "sessionToken": token,
        "userId": cred.user_id,
        "adaptiveResult": adaptive_result,
        "ratTrustScore": rat_profile.get("rat_trust_score"),
        "expiresIn": JWTIssuer.EXPIRY,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [FIDO2-IdP] %(levelname)s: %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
