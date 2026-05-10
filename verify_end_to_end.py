import httpx
import asyncio
import json
import time

async def verify():
    print("=== Zero Trust End-to-End Verification ===\n")
    
    # 1. Get a token from IdP (mocking the client flow for simplicity)
    # We'll use the demo token builder from pep_server for speed, 
    # but normally we'd do the FIDO2 flow.
    # Actually, let's use a real token from the IdP if possible.
    
    user_id = "user-123"
    print(f"[1] Simulating FIDO2 Authentication for {user_id}...")
    
    # We use the 'demo token' logic to bypass the complex FIDO2 handshake 
    # but still verify the PEP -> PDP -> SDN flow.
    # In pep_server.py we added a jwt_validator.build_demo_token
    
    # To be totally real, we'll fetch the JWKS first to ensure PEP is ready
    async with httpx.AsyncClient() as client:
        try:
            jwks_resp = await client.get("http://localhost:8001/.well-known/jwks.json")
            print(f"    IdP JWKS reachable: {jwks_resp.status_code == 200}")
        except Exception as e:
            print(f"    IdP unreachable: {e}")
            return

    # Use a hardcoded demo token (the one pep_server.py can build)
    # The secret must match: b"CHANGE_ME_USE_RSA_OR_EC_IN_PRODUCTION"
    import base64
    import hmac
    import hashlib
    import uuid

    session_id = str(uuid.uuid4())
    def build_token(uid, jti):
        secret = b"CHANGE_ME_USE_RSA_OR_EC_IN_PRODUCTION"
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": uid,
            "iss": "localhost:8001",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": jti,
        }).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
        return f"{header}.{payload}.{sig}"

    token = build_token(user_id, session_id)
    print(f"    Token generated (session_id={session_id[:8]}...)")

    # 2. Access resource via PEP
    print(f"\n[2] Accessing resource via PEP (8081)...")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert": "MOCK_CERT_PEM", # Trigger mTLS middleware
        "X-RAT-Trust-Score": "0.85",
        "X-RAT-Type": "WiFi-5GHz",
        "X-RAT-Security": "WPA3-Personal"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get("http://localhost:8081/resource/api/v1/data", headers=headers)
            print(f"    PEP Response: {resp.status_code}")
            print(f"    Body: {resp.json() if resp.status_code == 200 else resp.text}")
        except Exception as e:
            print(f"    PEP request failed: {e}")

    # 3. Verify SDN flow was installed
    print(f"\n[3] Verifying SDN Flow Installation (8084)...")
    async with httpx.AsyncClient() as client:
        try:
            flow_resp = await client.get("http://localhost:8084/api/v1/flows")
            data = flow_resp.json()
            flows = data.get("flows", [])
            print(f"    Installed Flows: {json.dumps(flows, indent=2)}")
            # flows is a list of dicts: [{"session_id": "...", "action": "ALLOW", ...}]
            if any(session_id == f.get("session_id") for f in flows):
                print("    VERIFICATION SUCCESS: Flow installed for user!")
            else:
                print("    VERIFICATION FAILED: Flow not found.")
        except Exception as e:
            print(f"    SDN verify failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(verify())
