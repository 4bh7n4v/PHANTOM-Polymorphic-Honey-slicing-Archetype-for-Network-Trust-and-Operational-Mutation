import subprocess
import time
import sys
import os

def start_hub():
    print("=== STARTING ZERO TRUST SECURITY HUB (VM 2) ===")
    
    # 1. Start Docker (SDN / OVS)
    # Note: Requires Docker Desktop or Engine to be running
    print("[1] Starting SDN Data Plane (Docker)...")
    subprocess.Popen(["docker", "compose", "up", "-d", "ryu", "ovs"])

    # 2. Start SDP Controller (PE + PA)
    print("[2] Starting SDP Controller (Port 8002)...")
    pdp = subprocess.Popen([sys.executable, "SDP_Controller/sdp_controller.py"])

    # 3. Start IdP
    print("[3] Starting Identity Provider (Port 8001)...")
    idp = subprocess.Popen([sys.executable, "IDP_IAM/idp_server.py"])

    # 4. Start Gateway (PEP)
    # It will automatically find the local Controller and IdP
    print("[4] Starting PEP Gateway (Port 8081)...")
    pep = subprocess.Popen([sys.executable, "SDP_Gateway/pep_server.py"])

    print("\n>>> HUB IS ONLINE. Monitoring logs...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Hub...")
        pdp.terminate()
        idp.terminate()
        pep.terminate()

if __name__ == "__main__":
    start_hub()
