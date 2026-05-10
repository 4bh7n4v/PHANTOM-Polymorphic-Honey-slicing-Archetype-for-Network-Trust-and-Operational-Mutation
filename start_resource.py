import uvicorn
import sys
import os
from SDN_Controller.ovp_sdn import ovp2_app

def start_resource():
    print("=== STARTING PROTECTED RESOURCE (VM 3) ===")
    print("[1] Initializing OVP2 Resource Proxy (Port 8083)...")
    print("    Note: This resource is now hidden behind the Hub's ZTNA.")
    
    # Run OVP2 which hosts the mock resource data
    uvicorn.run(ovp2_app, host="0.0.0.0", port=8083, log_level="info")

if __name__ == "__main__":
    start_resource()
