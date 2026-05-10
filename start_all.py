#!/usr/bin/env python3
"""
Zero Trust FIDO2 — Start all services (local dev mode)
Runs all services in subprocesses using the renamed directory structure.

For production, use: docker compose up --build
"""

import subprocess
import sys
import time
import signal
import os

# Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ------------------------------------------------------------------ #
#  Service Definitions                                                 #
# ------------------------------------------------------------------ #

SERVICES = [
    (
        "IdP / IAM (FIDO2 Server)",
        ["python", "IDP_IAM/idp_server.py"],
        8001,
    ),
    (
        "SDP Controller (PE + PA)",
        ["python", "SDP_Controller/sdp_controller.py"],
        8002,
    ),
    (
        "SDP Gateway / PEP",
        ["python", "-c", 
         "import os; os.environ['SDN_URL']='http://localhost:8084'; "
         "import uvicorn; from SDP_Gateway.pep_server import app; "
         "uvicorn.run(app, host='0.0.0.0', port=8081)"],
        8081,
    ),
    (
        "OVP1 (Client-facing proxy)",
        ["python", "-c",
         "import uvicorn; from SDN_Controller.ovp_sdn import ovp1_app; "
         "uvicorn.run(ovp1_app, host='0.0.0.0', port=8080)"],
        8080,
    ),
    (
        "OVP2 (Resource-facing proxy)",
        ["python", "-c",
         "import uvicorn; from SDN_Controller.ovp_sdn import ovp2_app; "
         "uvicorn.run(ovp2_app, host='0.0.0.0', port=8083)"],
        8083,
    ),
    (
        "SDN Management API",
        ["python", "-c",
         "import uvicorn; from SDN_Controller.ovp_sdn import sdn_app; "
         "uvicorn.run(sdn_app, host='0.0.0.0', port=8084)"],
        8084,
    ),
]

# ------------------------------------------------------------------ #
#  Startup                                                             #
# ------------------------------------------------------------------ #

procs = []

def shutdown(sig=None, frame=None):
    print("\n\nShutting down all services...")
    for name, proc in procs:
        proc.terminate()
        print(f"  ✗ {name} stopped")
    sys.exit(0)


signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)


print("\n" + "=" * 55)
print("  Zero Trust ZTNA -- Local Dev Stack")
print("=" * 55)
print("  Note: Ryu + OVS require Docker.")
print("        Run `docker compose up ryu ovs` separately")
print("        or use `docker compose up --build` for full stack.")
print("=" * 55 + "\n")

for name, cmd, port in SERVICES:
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        procs.append((name, p))
        print(f"  [OK]  {name:<35} -> :{port}  (pid={p.pid})")
        time.sleep(0.6)
    except Exception as exc:
        print(f"  [ERR] {name:<35} FAILED: {exc}")

print(f"\n  All services started. Press Ctrl+C to stop.\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    shutdown()
