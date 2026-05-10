#!/usr/bin/env python3
"""
Zero Trust FIDO2 — Start all services
"""
import subprocess, sys, time

SERVICES = [
    ("IdP (FIDO2 Server)",    ["python", "idp_client/idp_server.py"],    8001),
    ("SDP Controller (PE+PA)",["python", "sdp_controller/sdp_controller.py"], 8002),
    ("PEP",                   ["python", "pep/pep_server.py"],           8081),
    ("OVP1",                  ["python", "-c",
      "import uvicorn; from ovp.ovp_sdn import ovp1_app; uvicorn.run(ovp1_app,host='0.0.0.0',port=8080)"], 8080),
    ("OVP2",                  ["python", "-c",
      "import uvicorn; from ovp.ovp_sdn import ovp2_app; uvicorn.run(ovp2_app,host='0.0.0.0',port=8083)"], 8083),
    ("SDN Controller",        ["python", "-c",
      "import uvicorn; from ovp.ovp_sdn import sdn_app; uvicorn.run(sdn_app,host='0.0.0.0',port=8084)"], 8084),
]

procs = []
for name, cmd, port in SERVICES:
    p = subprocess.Popen(cmd)
    procs.append(p)
    print(f"  ✓ {name} started on :{port}")
    time.sleep(0.5)

print("\nAll services running. Press Ctrl+C to stop.\n")
try:
    while True: time.sleep(1)
except KeyboardInterrupt:
    for p in procs: p.terminate()
    print("\nAll services stopped.")
