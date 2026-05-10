#!/usr/bin/env bash
# ================================================================== #
#  ovs_verify.sh — Verify OVS bridge and Ryu connection               #
#  Run inside the 'ovs' Docker container:                             #
#    docker compose exec ovs bash /app/ovs_verify.sh                  #
# ================================================================== #

set -e

echo "========================================"
echo "  OVS + Ryu ZTNA Verification Script"
echo "========================================"

# 1. Check OVS is running
echo ""
echo "[1] OVS daemon status:"
ovs-vsctl show

# 2. Check bridge exists
echo ""
echo "[2] Bridge br-ztna:"
ovs-vsctl list-br

# 3. Check controller connected
echo ""
echo "[3] Controller connection:"
ovs-vsctl get-controller br-ztna

# 4. Check OpenFlow version
echo ""
echo "[4] OpenFlow protocols:"
ovs-vsctl get bridge br-ztna protocols

# 5. Dump installed flow rules
echo ""
echo "[5] Current flow table (br-ztna):"
ovs-ofctl -O OpenFlow13 dump-flows br-ztna

# 6. Check controller connectivity via REST
echo ""
echo "[6] Ryu REST API health:"
curl -s http://ryu:8085/ztna/health | python3 -m json.tool

echo ""
echo "[7] Connected switches:"
curl -s http://ryu:8085/ztna/switches | python3 -m json.tool

echo ""
echo "[8] Active ZTNA session flows:"
curl -s http://ryu:8085/ztna/flows | python3 -m json.tool

echo ""
echo "========================================"
echo "  Verification complete"
echo "========================================"
