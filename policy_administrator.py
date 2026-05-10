"""
Policy Administrator (PA) — Zero Trust Architecture
NIST SP 800-207 compliant policy lifecycle management.

Responsibilities:
  - CRUD operations on policy rules
  - Hot-reload rules into the Policy Engine without restart
  - Push policy update notifications to PEP(s)
  - Session registry — track and terminate active sessions
"""

import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from policy_engine import PolicyEngine, PolicyRule, PolicyDecision, Decision, DEFAULT_RULES

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Session Registry                                                    #
# ------------------------------------------------------------------ #

class SessionRegistry:
    """Tracks active authenticated sessions across the system."""

    def __init__(self):
        self._sessions: Dict[str, Dict] = {}

    def register(self, session_id: str, data: Dict):
        self._sessions[session_id] = {
            **data,
            "created_at": time.time(),
            "active": True,
        }
        logger.info("[SessionRegistry] Registered session: %s", session_id)

    def terminate(self, session_id: str, reason: str = ""):
        if session_id in self._sessions:
            self._sessions[session_id]["active"]             = False
            self._sessions[session_id]["terminated_reason"]  = reason
            self._sessions[session_id]["terminated_at"]      = time.time()
            logger.info("[SessionRegistry] Terminated session: %s | reason: %s",
                        session_id, reason or "unspecified")

    def get_active(self) -> List[Dict]:
        return [s for s in self._sessions.values() if s.get("active")]

    def get(self, session_id: str) -> Optional[Dict]:
        return self._sessions.get(session_id)


# ------------------------------------------------------------------ #
#  Policy Administrator                                                #
# ------------------------------------------------------------------ #

class PolicyAdministrator:
    """
    Manages the policy rule set.

    - Provides CRUD operations for rule management (admin API).
    - On every mutation, hot-reloads rules into the live PolicyEngine.
    - Notifies registered PEP endpoints of policy updates via HTTP push.
    """

    def __init__(self, engine: PolicyEngine):
        self._engine = engine
        self._rule_index: Dict[str, PolicyRule] = {
            r.rule_id: r for r in DEFAULT_RULES
        }
        self._pep_subscribers: List[str] = []   # PEP base URLs
        # Sync engine with initial rules
        self._reload_engine()

    # ---- Rule Queries ---- #

    def get_rules(self) -> List[Dict]:
        """Return all rules sorted by priority."""
        return [
            asdict(r)
            for r in sorted(self._rule_index.values(), key=lambda r: r.priority)
        ]

    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        return self._rule_index.get(rule_id)

    # ---- Rule Mutations ---- #

    def add_rule(self, rule: PolicyRule) -> PolicyRule:
        if rule.rule_id in self._rule_index:
            raise ValueError(f"Rule {rule.rule_id} already exists. Use update_rule() to modify.")
        self._rule_index[rule.rule_id] = rule
        self._reload_engine()
        logger.info("[PA] Rule added: %s (%s)", rule.rule_id, rule.name)
        return rule

    def update_rule(self, rule_id: str, updates: Dict) -> PolicyRule:
        if rule_id not in self._rule_index:
            raise KeyError(f"Rule {rule_id} not found")
        rule = self._rule_index[rule_id]
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
            else:
                logger.warning("[PA] Unknown field '%s' ignored for rule %s", key, rule_id)
        self._reload_engine()
        logger.info("[PA] Rule updated: %s", rule_id)
        return rule

    def delete_rule(self, rule_id: str):
        if rule_id == "R008":
            raise ValueError("Cannot delete the default-deny rule (R008).")
        if rule_id not in self._rule_index:
            raise KeyError(f"Rule {rule_id} not found")
        self._rule_index.pop(rule_id)
        self._reload_engine()
        logger.info("[PA] Rule deleted: %s", rule_id)

    def enable_rule(self, rule_id: str):
        self.update_rule(rule_id, {"enabled": True})

    def disable_rule(self, rule_id: str):
        self.update_rule(rule_id, {"enabled": False})

    # ---- PEP Subscriber Management ---- #

    def register_pep(self, pep_url: str):
        """Register a PEP endpoint to receive policy-reload notifications."""
        if pep_url not in self._pep_subscribers:
            self._pep_subscribers.append(pep_url)
            logger.info("[PA] PEP registered for push notifications: %s", pep_url)

    async def push_to_all_peps(self):
        """Notify all registered PEPs that the policy has been updated."""
        import httpx
        payload = {"timestamp": time.time(), "event": "POLICY_UPDATED"}
        async with httpx.AsyncClient(timeout=5) as client:
            for url in self._pep_subscribers:
                try:
                    await client.post(f"{url}/api/v1/policy/reload", json=payload)
                    logger.info("[PA] Policy push sent to PEP: %s", url)
                except Exception as exc:
                    logger.warning("[PA] Policy push failed for %s: %s", url, exc)

    # ---- Internal ---- #

    def _reload_engine(self):
        """Push current rule set into the live PolicyEngine (hot-reload, zero downtime)."""
        self._engine.reload_rules(list(self._rule_index.values()))
