"""
SDP Controller — Entry Point
Zero Trust Architecture

Wires together the Policy Engine (PE) and Policy Administrator (PA)
and exposes a single FastAPI service.

Architecture:
  PEP → POST /api/v1/policy/evaluate  → PE  → returns decision
  PA  ← admin API for policy CRUD
  PE  ← PA hot-reloads rules on any mutation

Ports:
  :8002  — this service
"""

import logging
import uuid
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn

from policy_engine import PolicyEngine, Decision, PolicyRule, DEFAULT_RULES
from policy_administrator import PolicyAdministrator, SessionRegistry

# ------------------------------------------------------------------ #
#  Logging                                                             #
# ------------------------------------------------------------------ #

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Bootstrap — PE → PA → Sessions                                     #
# ------------------------------------------------------------------ #

pe               = PolicyEngine(DEFAULT_RULES)
pa               = PolicyAdministrator(pe)
session_registry = SessionRegistry()

# ------------------------------------------------------------------ #
#  FastAPI App                                                         #
# ------------------------------------------------------------------ #

app = FastAPI(
    title="SDP Controller (PE + PA)",
    version="2.0.0",
    description=(
        "Policy Engine (PE): real-time context evaluation → ALLOW/DENY/STEP_UP. "
        "Policy Administrator (PA): rule lifecycle management + PEP push notifications."
    ),
)

# ================================================================== #
#  Health                                                              #
# ================================================================== #

@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "component": "SDP-Controller",
        "timestamp": time.time(),
    }

# ================================================================== #
#  Policy Evaluation  (PE endpoint — called by PEP on every request)  #
# ================================================================== #

@app.post("/api/v1/policy/evaluate")
async def evaluate_policy(request: Request):
    """
    Called by PEP for every access request.
    Body: { subject, resource, environment, policy }
    Returns a policy decision with trust score, obligations, and rule matched.
    """
    try:
        context = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    decision = pe.evaluate(context)

    logger.info(
        "[PE] Decision: %s | Trust: %.2f | Risk: %.2f | Rule: %s",
        decision.decision.value,
        context.get("_trust_score", 0.0),
        decision.risk_score,
        decision.rule_id,
    )

    return {
        "decision":    decision.decision.value,
        "rule_id":     decision.rule_id,
        "reason":      decision.reason,
        "obligations": decision.obligations,
        "risk_score":  decision.risk_score,
        "trust_score": context.get("_trust_score", 0.0),
        "timestamp":   decision.timestamp,
        "session_id":  decision.session_id,
    }

# ================================================================== #
#  Policy Administration  (PA endpoints — admin/management plane)     #
# ================================================================== #

@app.get("/api/v1/policy/rules")
async def get_rules():
    """List all active policy rules ordered by priority."""
    return {"rules": pa.get_rules()}


@app.get("/api/v1/policy/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Fetch a single rule by ID."""
    rule = pa.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    from dataclasses import asdict
    return asdict(rule)


@app.post("/api/v1/policy/rules")
async def create_rule(request: Request):
    """Create a new policy rule."""
    body = await request.json()
    try:
        rule = PolicyRule(
            rule_id     = body.get("rule_id", f"R{uuid.uuid4().hex[:6].upper()}"),
            name        = body["name"],
            priority    = body.get("priority", 500),
            conditions  = body.get("conditions", {}),
            decision    = Decision(body.get("decision", "DENY")),
            obligations = body.get("obligations", []),
            description = body.get("description", ""),
        )
        pa.add_rule(rule)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    from dataclasses import asdict
    return {"status": "created", "rule": asdict(rule)}


@app.patch("/api/v1/policy/rules/{rule_id}")
async def update_rule(rule_id: str, request: Request):
    """Partially update an existing rule."""
    body = await request.json()
    try:
        rule = pa.update_rule(rule_id, body)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    from dataclasses import asdict
    return {"status": "updated", "rule": asdict(rule)}


@app.delete("/api/v1/policy/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a rule (default-deny R008 is protected)."""
    try:
        pa.delete_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "deleted", "rule_id": rule_id}


@app.post("/api/v1/policy/rules/{rule_id}/enable")
async def enable_rule(rule_id: str):
    """Enable a disabled rule."""
    try:
        pa.enable_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "enabled", "rule_id": rule_id}


@app.post("/api/v1/policy/rules/{rule_id}/disable")
async def disable_rule(rule_id: str):
    """Disable a rule without deleting it."""
    try:
        pa.disable_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "disabled", "rule_id": rule_id}


# ---- PEP subscriber management ---- #

@app.post("/api/v1/policy/subscribers")
async def register_pep_subscriber(request: Request):
    """Register a PEP URL to receive policy-update push notifications."""
    body = await request.json()
    url  = body.get("pep_url")
    if not url:
        raise HTTPException(status_code=400, detail="pep_url required")
    pa.register_pep(url)
    return {"status": "registered", "pep_url": url}


@app.post("/api/v1/policy/push")
async def push_policy_to_peps():
    """Manually trigger a policy-reload push to all registered PEPs."""
    await pa.push_to_all_peps()
    return {"status": "pushed", "timestamp": time.time()}

# ================================================================== #
#  Session Management                                                  #
# ================================================================== #

@app.post("/api/v1/sessions")
async def register_session(request: Request):
    body       = await request.json()
    session_id = body.get("session_id", str(uuid.uuid4()))
    session_registry.register(session_id, body)
    return {"status": "registered", "session_id": session_id}


@app.delete("/api/v1/sessions/{session_id}")
async def terminate_session(session_id: str, request: Request):
    body = await request.json() if request.headers.get("content-length") else {}
    session_registry.terminate(session_id, reason=body.get("reason", ""))
    return {"status": "terminated", "session_id": session_id}


@app.get("/api/v1/sessions/active")
async def list_active_sessions():
    return {"sessions": session_registry.get_active()}


@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    session = session_registry.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session

# ================================================================== #
#  Entry Point                                                         #
# ================================================================== #

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [SDP-Controller] %(levelname)s: %(message)s",
    )
    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
