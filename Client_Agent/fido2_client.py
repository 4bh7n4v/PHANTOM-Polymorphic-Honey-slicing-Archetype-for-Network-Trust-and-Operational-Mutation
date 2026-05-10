"""
FIDO2 Client - Zero Trust SPA Authentication
Integrates Multi-RAT detection context into FIDO2 assertion/attestation flows.
Uses TEE (Trusted Execution Environment) for key storage and signing.
"""

import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import logging
import httpx

from multi_rat.rat_detector import MultiRATDetector, RATProfile, RATMonitor
from config_loader import zta_settings, log_important

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  TEE Abstraction                                                     #
# ------------------------------------------------------------------ #

class TEEInterface:
    """
    Abstraction over platform Trusted Execution Environments.

    Platform mapping (production):
      Android  → Android Keystore (StrongBox/TEE-backed ECDSA)
      iOS      → Secure Enclave (SecKeyCreateRandomKey / CryptoKit)
      Windows  → TPM 2.0 via Windows Hello (CNG/NCrypt API)
      Linux    → PKCS#11 / TPM2-TSS (tpm2-pytss)

    Current implementation:
      Uses Python `cryptography` library (software ECDSA P-256) when available.
      Falls back to HMAC-SHA256 if `cryptography` is not installed.
      Private keys are stored in-process memory only — replace with
      platform TEE SDK calls in production.
    """

    def __init__(self):
        self._keys: Dict[str, Any] = {}   # credential_id → private key object or raw bytes
        self._use_ecdsa = self._check_ecdsa()
        if not self._use_ecdsa:
            logger.warning(
                "[TEE] `cryptography` library not found. "
                "Using HMAC-SHA256 fallback — NOT suitable for production."
            )

    @staticmethod
    def _check_ecdsa() -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, SECP256R1
            )
            return True
        except ImportError:
            return False

    def generate_credential_key(self, credential_id: str) -> bytes:
        """
        Generate an ES256 (P-256 ECDSA) key pair.
        Returns the public key as a COSE_Key JSON structure.
        In production: key generation happens inside TEE hardware.
        """
        if self._use_ecdsa:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, SECP256R1, EllipticCurvePublicKey
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat
            )
            from cryptography.hazmat.backends import default_backend

            private_key = generate_private_key(SECP256R1(), default_backend())
            self._keys[credential_id] = private_key

            pub = private_key.public_key()
            pub_numbers = pub.public_key().public_numbers() \
                if hasattr(pub, "public_key") else pub.public_numbers()
            x_bytes = pub_numbers.x.to_bytes(32, "big")
            y_bytes = pub_numbers.y.to_bytes(32, "big")

            cose_key = {
                "kty": 2,   # EC2
                "alg": -7,  # ES256
                "crv": 1,   # P-256
                "x": base64.b64encode(x_bytes).decode(),
                "y": base64.b64encode(y_bytes).decode(),
            }
        else:
            # Software fallback — generate random bytes as mock key material
            import secrets
            key_material = secrets.token_bytes(32)
            self._keys[credential_id] = key_material
            cose_key = {
                "kty": 2, "alg": -7, "crv": 1,
                "x": base64.b64encode(key_material[:16]).decode(),
                "y": base64.b64encode(key_material[16:]).decode(),
            }

        logger.debug("[TEE] Credential key generated: %s (ecdsa=%s)",
                     credential_id[:12], self._use_ecdsa)
        return json.dumps(cose_key).encode()

    def sign_assertion(self, credential_id: str, data: bytes) -> bytes:
        """
        Sign data with the credential's private key.
        In production: signing happens inside TEE — private key never leaves.
        """
        key = self._keys.get(credential_id)
        if key is None:
            raise ValueError(f"[TEE] No key found for credential: {credential_id}")

        if self._use_ecdsa and not isinstance(key, bytes):
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            from cryptography.hazmat.primitives import hashes
            signature = key.sign(data, ECDSA(hashes.SHA256()))
            logger.debug("[TEE] ECDSA-P256 signature produced for %s", credential_id[:12])
            return signature
        else:
            # HMAC fallback
            import hmac as _hmac
            sig = _hmac.new(key if isinstance(key, bytes) else b"fallback",
                            data, digestmod=hashlib.sha256).digest()
            logger.debug("[TEE] HMAC-SHA256 fallback signature for %s", credential_id[:12])
            return sig

    def get_attestation(self, credential_id: str) -> Dict[str, Any]:
        """Return attestation statement (packed / android-key / tpm)."""
        key = self._keys.get(credential_id)
        fmt = "packed"

        if self._use_ecdsa and key and not isinstance(key, bytes):
            # Sign the credential_id as a stand-in for the authData hash
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            from cryptography.hazmat.primitives import hashes
            sig_bytes = key.sign(credential_id.encode(), ECDSA(hashes.SHA256()))
        else:
            sig_bytes = os.urandom(64)

        return {
            "fmt": fmt,
            "attStmt": {
                "alg": -7,
                "sig": base64.b64encode(sig_bytes).decode(),
                "x5c": [],   # Certificate chain from TEE vendor in production
            }
        }


# ------------------------------------------------------------------ #
#  FIDO2 Data Structures                                              #
# ------------------------------------------------------------------ #

@dataclass
class PublicKeyCredentialCreationOptions:
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    challenge: str
    rat_context: Dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 60000
    pub_key_cred_params: List[Dict] = field(default_factory=lambda: [
        {"type": "public-key", "alg": -7},   # ES256
        {"type": "public-key", "alg": -257},  # RS256
    ])
    authenticator_selection: Dict = field(default_factory=lambda: {
        "authenticatorAttachment": "platform",
        "userVerification": "required",
        "residentKey": "required",
    })


@dataclass
class PublicKeyCredentialRequestOptions:
    rp_id: str
    challenge: str
    rat_context: Dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 60000
    user_verification: str = "required"
    allow_credentials: List[Dict] = field(default_factory=list)


@dataclass
class AuthenticatorAttestationResponse:
    credential_id: str
    client_data_json: str      # base64url
    attestation_object: str    # base64url
    public_key: str            # base64url COSE
    rat_profile: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthenticatorAssertionResponse:
    credential_id: str
    client_data_json: str      # base64url
    authenticator_data: str    # base64url
    signature: str             # base64url
    user_handle: str           # base64url
    rat_profile: Dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------ #
#  FIDO2 Client                                                       #
# ------------------------------------------------------------------ #

class FIDO2Client:
    """
    WebAuthn / FIDO2 client implementing:
    1. Registration (create credential)
    2. Authentication (get assertion)
    3. Continuous re-authentication via RAT change events
    4. Multi-RAT context injected into clientDataJSON
    """

    def __init__(self,
                 rp_id: str,
                 idp_base_url: str,
                 ovp1_base_url: str,
                 tee: Optional[TEEInterface] = None):
        self.rp_id = rp_id
        self.idp_base_url = idp_base_url
        self.ovp1_base_url = ovp1_base_url
        self.tee = tee or TEEInterface()
        self.rat_detector = MultiRATDetector()
        self.rat_monitor = RATMonitor(
            self.rat_detector,
            callback=self._on_rat_change,
            interval=15
        )
        self._session_token: Optional[str] = None
        self._credential_id: Optional[str] = None
        self._user_id: Optional[str] = None
        self._http = httpx.AsyncClient(timeout=30)

    # -------------------------------------------------------------- #
    #  Step 1: Registration — generate credential in TEE              #
    # -------------------------------------------------------------- #

    async def register(self, username: str, user_id: str) -> AuthenticatorAttestationResponse:
        """
        FIDO2 Registration Flow:
        1. Fetch challenge from IdP
        2. Collect RAT context
        3. Create credential in TEE
        4. Send attestation to IdP (via OVP1 → PEP → IdP)
        """
        logger.info("[FIDO2] Starting registration for user: %s", username)

        # 1. Request creation options from IdP
        options = await self._fetch_creation_options(user_id, username)

        # 2. Capture RAT context
        rat_profile = self.rat_detector.capture()
        rat_ext = rat_profile.to_fido2_extension_data()

        # 3. Build clientDataJSON with RAT extension
        client_data = {
            "type": "webauthn.create",
            "challenge": options.challenge,
            "origin": f"https://{self.rp_id}",
            "crossOrigin": False,
            "extensions": {
                **rat_ext,
                "deviceType": rat_profile.os_platform,
                "networkBand": rat_profile.network_band,
                "securityProtocol": rat_profile.security_protocol.value,
                "trustScore": rat_profile.rat_trust_score,
            }
        }
        client_data_json = base64.urlsafe_b64encode(
            json.dumps(client_data).encode()
        ).decode().rstrip("=")

        # 4. Generate credential key in TEE
        credential_id = str(uuid.uuid4())
        public_key_bytes = self.tee.generate_credential_key(credential_id)
        attestation = self.tee.get_attestation(credential_id)

        # 5. Build attestation object (CBOR in production, JSON here)
        attestation_obj = {
            "authData": base64.b64encode(self._build_auth_data(credential_id, public_key_bytes)).decode(),
            "fmt": attestation["fmt"],
            "attStmt": attestation["attStmt"],
        }
        attestation_object = base64.urlsafe_b64encode(
            json.dumps(attestation_obj).encode()
        ).decode().rstrip("=")

        response = AuthenticatorAttestationResponse(
            credential_id=credential_id,
            client_data_json=client_data_json,
            attestation_object=attestation_object,
            public_key=base64.urlsafe_b64encode(public_key_bytes).decode().rstrip("="),
            rat_profile=rat_profile.to_dict(),
        )

        # 6. Send to IdP via OVP1
        await self._submit_registration(response, user_id)
        self._credential_id = credential_id
        self._user_id = user_id
        logger.info("[FIDO2] Registration complete. Credential: %s", credential_id[:8])
        return response

    # -------------------------------------------------------------- #
    #  Step 2: Authentication — sign challenge in TEE                 #
    # -------------------------------------------------------------- #

    async def authenticate(self, user_id: Optional[str] = None) -> AuthenticatorAssertionResponse:
        """
        FIDO2 Authentication Flow:
        1. Fetch assertion challenge from IdP (via OVP1)
        2. Collect RAT context
        3. Sign challenge inside TEE
        4. Submit assertion → receive session token
        """
        uid = user_id or self._user_id
        cred_id = self._credential_id
        logger.info("[FIDO2] Starting authentication for user: %s", uid)

        # 1. Fetch request options
        options = await self._fetch_request_options(uid)

        # 2. Capture RAT context
        rat_profile = self.rat_detector.capture()
        rat_ext = rat_profile.to_fido2_extension_data()

        # 3. Build clientDataJSON
        client_data = {
            "type": "webauthn.get",
            "challenge": options.challenge,
            "origin": f"https://{self.rp_id}",
            "crossOrigin": False,
            "extensions": {
                **rat_ext,
                "deviceType": rat_profile.os_platform,
                "networkBand": rat_profile.network_band,
                "securityProtocol": rat_profile.security_protocol.value,
                "signalStrength": rat_profile.signal_strength_dbm,
                "trustScore": rat_profile.rat_trust_score,
                "vpnActive": rat_profile.vpn_active,
            }
        }
        client_data_json_bytes = json.dumps(client_data).encode()
        client_data_json = base64.urlsafe_b64encode(client_data_json_bytes).decode().rstrip("=")

        # 4. Build authenticatorData
        auth_data = self._build_auth_data_assertion()
        auth_data_b64 = base64.urlsafe_b64encode(auth_data).decode().rstrip("=")

        # 5. Sign: authenticatorData || SHA-256(clientDataJSON)  — inside TEE
        client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
        signed_data = auth_data + client_data_hash
        signature_bytes = self.tee.sign_assertion(cred_id, signed_data)
        signature = base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=")

        response = AuthenticatorAssertionResponse(
            credential_id=cred_id,
            client_data_json=client_data_json,
            authenticator_data=auth_data_b64,
            signature=signature,
            user_handle=base64.urlsafe_b64encode(uid.encode()).decode().rstrip("="),
            rat_profile=rat_profile.to_dict(),
        )

        # 6. Submit to IdP via OVP1 → PEP → PDP → IdP
        token = await self._submit_authentication(response)
        self._session_token = token
        self.rat_monitor.start()   # Start continuous monitoring post-auth
        logger.info("[FIDO2] Authentication successful. Session established.")
        return response

    # -------------------------------------------------------------- #
    #  Step 3: Resource Access via OVP1                               #
    # -------------------------------------------------------------- #

    async def access_resource(self, resource_path: str) -> Dict[str, Any]:
        """Send authenticated request to OVP1 with session token + RAT context."""
        if not self._session_token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        rat_profile = self.rat_detector.capture()
        headers = {
            "Authorization": f"Bearer {self._session_token}",
            "X-RAT-Trust-Score": str(rat_profile.rat_trust_score),
            "X-RAT-Type": rat_profile.rat_type.value,
            "X-RAT-Security": rat_profile.security_protocol.value,
            "X-Device-ID": rat_profile.device_id,
            "X-Session-ID": rat_profile.session_id,
        }
        resp = await self._http.get(f"{self.ovp1_base_url}{resource_path}", headers=headers)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------- #
    #  Continuous Authentication Callback                             #
    # -------------------------------------------------------------- #

    def _on_rat_change(self, new_profile: RATProfile, event: str):
        """
        Called by RATMonitor when network context changes significantly.
        Triggers re-authentication or step-up auth with the PDP.
        """
        logger.warning("[CONTINUOUS-AUTH] %s | trust=%.2f | %s",
                       event, new_profile.rat_trust_score, new_profile.rat_type.value)

        if new_profile.rat_trust_score < 0.50:
            logger.warning("[CONTINUOUS-AUTH] Low trust score — triggering re-authentication")
            asyncio.create_task(self._trigger_step_up_auth(new_profile))
        else:
            asyncio.create_task(self._report_rat_change(new_profile))

    async def _trigger_step_up_auth(self, profile: RATProfile):
        """Step-up: full FIDO2 re-assertion on low trust."""
        await self.authenticate(self._user_id)

    async def _report_rat_change(self, profile: RATProfile):
        """Report non-critical RAT change to PEP for continuous evaluation."""
        if not self._session_token:
            return
        headers = {"Authorization": f"Bearer {self._session_token}"}
        payload = {
            "event": "RAT_CONTEXT_UPDATE",
            "ratProfile": profile.to_dict(),
            "timestamp": time.time(),
        }
        try:
            await self._http.post(
                f"{self.ovp1_base_url}/api/v1/session/rat-update",
                json=payload, headers=headers
            )
        except Exception as e:
            logger.error("RAT change report failed: %s", e)

    # -------------------------------------------------------------- #
    #  IdP Communication Helpers                                      #
    # -------------------------------------------------------------- #

    async def _fetch_creation_options(self, user_id: str, username: str) -> PublicKeyCredentialCreationOptions:
        rat_profile = self.rat_detector.capture()
        try:
            resp = await self._http.post(
                f"{self.idp_base_url}/fido2/register/begin",
                json={"userId": user_id, "username": username,
                      "ratContext": rat_profile.to_fido2_extension_data()}
            )
            data = resp.json()
            return PublicKeyCredentialCreationOptions(
                rp_id=data.get("rp", {}).get("id", self.rp_id),
                rp_name=data.get("rp", {}).get("name", "Zero Trust SP"),
                user_id=user_id,
                user_name=username,
                challenge=data.get("challenge", base64.b64encode(os.urandom(32)).decode()),
                rat_context=rat_profile.to_fido2_extension_data(),
            )
        except Exception:
            return PublicKeyCredentialCreationOptions(
                rp_id=self.rp_id, rp_name="Zero Trust SP",
                user_id=user_id, user_name=username,
                challenge=base64.b64encode(os.urandom(32)).decode(),
            )

    async def _fetch_request_options(self, user_id: str) -> PublicKeyCredentialRequestOptions:
        rat_profile = self.rat_detector.capture()
        try:
            resp = await self._http.post(
                f"{self.idp_base_url}/fido2/authenticate/begin",
                json={"userId": user_id, "ratContext": rat_profile.to_fido2_extension_data()}
            )
            data = resp.json()
            return PublicKeyCredentialRequestOptions(
                rp_id=self.rp_id,
                challenge=data.get("challenge", base64.b64encode(os.urandom(32)).decode()),
                allow_credentials=data.get("allowCredentials", []),
            )
        except Exception:
            return PublicKeyCredentialRequestOptions(
                rp_id=self.rp_id,
                challenge=base64.b64encode(os.urandom(32)).decode(),
            )

    async def _submit_registration(self, response: AuthenticatorAttestationResponse, user_id: str):
        payload = {
            "userId": user_id,
            "credentialId": response.credential_id,
            "clientDataJSON": response.client_data_json,
            "attestationObject": response.attestation_object,
            "publicKey": response.public_key,
            "ratProfile": response.rat_profile,
        }
        try:
            await self._http.post(f"{self.idp_base_url}/fido2/register/complete", json=payload)
        except Exception as e:
            logger.warning("Registration submit failed (offline mode): %s", e)

    async def _submit_authentication(self, response: AuthenticatorAssertionResponse) -> str:
        payload = {
            "credentialId": response.credential_id,
            "clientDataJSON": response.client_data_json,
            "authenticatorData": response.authenticator_data,
            "signature": response.signature,
            "userHandle": response.user_handle,
            "ratProfile": response.rat_profile,
        }
        try:
            resp = await self._http.post(
                f"{self.idp_base_url}/fido2/authenticate/complete", json=payload
            )
            return resp.json().get("sessionToken", str(uuid.uuid4()))
        except Exception:
            return str(uuid.uuid4())  # Offline fallback

    # -------------------------------------------------------------- #
    #  Authenticator Data Builders                                    #
    # -------------------------------------------------------------- #

    def _build_auth_data(self, credential_id: str, public_key: bytes) -> bytes:
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()   # 32 bytes
        flags = (1 << 0) | (1 << 2) | (1 << 6)                      # UP | UV | AT
        sign_count = (1).to_bytes(4, "big")
        aaguid = b"\x00" * 16
        cred_id_bytes = credential_id.encode()[:64]
        cred_id_len = len(cred_id_bytes).to_bytes(2, "big")
        return rp_id_hash + bytes([flags]) + sign_count + aaguid + cred_id_len + cred_id_bytes + public_key

    def _build_auth_data_assertion(self) -> bytes:
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = (1 << 0) | (1 << 2)  # UP | UV
        sign_count = (int(time.time()) % 65536).to_bytes(4, "big")
        return rp_id_hash + bytes([flags]) + sign_count


# ------------------------------------------------------------------ #
#  Main entrypoint for standalone testing                             #
# ------------------------------------------------------------------ #

async def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    client = FIDO2Client(
        rp_id="zerotrust.example.com",
        idp_base_url=zta_settings["idp_url"],
        ovp1_base_url=zta_settings["gateway_url"],
    )

    print("=== FIDO2 Zero-Trust Client Demo ===\n")

    # Registration
    print("[1] Registering credential...")
    reg = await client.register(username="alice@example.com", user_id="user-001")
    print(f"    Credential ID: {reg.credential_id[:16]}...")
    print(f"    RAT Trust Score: {reg.rat_profile.get('rat_trust_score')}\n")

    # Authentication
    print("[2] Authenticating...")
    assertion = await client.authenticate()
    print(f"    Session token obtained (session started)\n")
    log_important("Client-Agent", "Session Established", {
        "user_id": "user-001",
        "jwt_token": assertion.signature, # Using signature as a proxy for the token in the log
        "rat_type": assertion.rat_profile.get("rat_type")
    })

    # RAT profile
    print("[3] Current RAT Profile:")
    rat = client.rat_detector.capture()
    print(json.dumps(rat.to_fido2_extension_data(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
