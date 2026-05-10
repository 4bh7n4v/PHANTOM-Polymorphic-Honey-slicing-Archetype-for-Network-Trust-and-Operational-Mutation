"""
Policy Engine (PE) — Zero Trust Architecture
NIST SP 800-207 compliant real-time policy evaluation.

Responsibilities:
  - Evaluate incoming context (subject, resource, environment) against ordered rules
  - Calculate authoritative trust score from raw RAT telemetry
  - Return ALLOW / DENY / STEP_UP decisions with obligations
  - No policy management — read-only rule evaluation
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


# ------------------------------------------------------------------ #
#  Decision Types                                                      #
# ------------------------------------------------------------------ #

class Decision(str, Enum):
    ALLOW   = "ALLOW"
    DENY    = "DENY"
    STEP_UP = "STEP_UP"


# ------------------------------------------------------------------ #
#  Data Models                                                         #
# ------------------------------------------------------------------ #

@dataclass
class PolicyRule:
    """A single policy rule evaluated against request context."""
    rule_id:     str
    name:        str
    priority:    int                    # Lower = higher priority
    conditions:  Dict[str, Any]         # Field → matcher
    decision:    Decision
    obligations: List[str] = field(default_factory=list)
    enabled:     bool = True
    description: str = ""


@dataclass
class PolicyDecision:
    decision:    Decision
    rule_id:     str
    reason:      str
    obligations: List[str]
    risk_score:  float
    timestamp:   float = field(default_factory=time.time)
    session_id:  str = ""


# ------------------------------------------------------------------ #
#  Built-in Default Policy Rules                                       #
# ------------------------------------------------------------------ #

DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule(
        rule_id="R001",
        name="Block open/unencrypted WiFi",
        priority=10,
        conditions={"environment.security_protocol": {"in": ["Open", "Unknown"]}},
        decision=Decision.DENY,
        description="Deny access from open or unknown security protocol networks",
        obligations=["LOG_SECURITY_EVENT", "NOTIFY_ADMIN"],
    ),
    PolicyRule(
        rule_id="R002",
        name="Block captive portal sessions",
        priority=15,
        conditions={"environment.is_captive_portal": {"eq": True}},
        decision=Decision.DENY,
        description="Users behind captive portals cannot access resources",
        obligations=["LOG_SECURITY_EVENT"],
    ),
    PolicyRule(
        rule_id="R003",
        name="Step-up for low trust score",
        priority=20,
        conditions={"environment.rat_trust_score": {"lt": 0.50}},
        decision=Decision.STEP_UP,
        description="Require re-authentication when RAT trust score is below threshold",
        obligations=["TRIGGER_FIDO2_REAUTH"],
    ),
    PolicyRule(
        rule_id="R004",
        name="Step-up for sensitive ops on WPA2",
        priority=25,
        conditions={
            "resource.operation": {"in": ["sensitive", "admin"]},
            "environment.security_protocol": {"in": ["WPA2-Personal", "WPA"]},
        },
        decision=Decision.STEP_UP,
        description="Sensitive operations require WPA3 or higher",
        obligations=["REQUIRE_VPN", "TRIGGER_FIDO2_REAUTH"],
    ),
    PolicyRule(
        rule_id="R005",
        name="Require VPN for admin ops on cellular",
        priority=30,
        conditions={
            "resource.operation": {"eq": "admin"},
            "environment.rat_type": {"in": ["Cellular-4G/LTE", "Cellular-5G", "Cellular-3G"]},
            "environment.vpn_active": {"eq": False},
        },
        decision=Decision.STEP_UP,
        description="Admin operations on cellular require VPN",
        obligations=["REQUIRE_VPN"],
    ),
    PolicyRule(
        rule_id="R006",
        name="Allow WPA3 high trust",
        priority=100,
        conditions={
            "environment.security_protocol": {"in": ["WPA3-Personal", "WPA3-Enterprise"]},
            "environment.rat_trust_score": {"gte": 0.70},
        },
        decision=Decision.ALLOW,
        description="Allow access on WPA3 networks with acceptable trust score",
        obligations=[],
    ),
    PolicyRule(
        rule_id="R007",
        name="Allow WPA2 medium trust read-only",
        priority=110,
        conditions={
            "resource.operation": {"eq": "read"},
            "environment.rat_trust_score": {"gte": 0.55},
        },
        decision=Decision.ALLOW,
        description="Allow read-only access with moderate trust score",
        obligations=["LOG_ACCESS"],
    ),
    PolicyRule(
        rule_id="R008",
        name="Default deny",
        priority=9999,
        conditions={},   # Matches everything
        decision=Decision.DENY,
        description="Implicit deny-all (last rule)",
        obligations=["LOG_SECURITY_EVENT"],
    ),
]


# ------------------------------------------------------------------ #
#  Policy Engine                                                       #
# ------------------------------------------------------------------ #

class PolicyEngine:
    """
    Evaluates request context against ordered policy rules.
    First-match semantics (rules sorted by priority ascending).
    Trust score is calculated authoritatively here — never trusted from client.
    """

    def __init__(self, rules: List[PolicyRule]):
        self._rules = sorted(rules, key=lambda r: r.priority)

    def evaluate(self, context: Dict[str, Any]) -> PolicyDecision:
        """Main evaluation entry point."""
        # Calculate authoritative trust score (NIST SP 800-207)
        trust_score = self._calculate_trust_score(context)
        risk_score  = round(1.0 - trust_score, 3)

        # Inject authoritative values into context for rule matching
        if "environment" not in context:
            context["environment"] = {}
        context["environment"]["rat_trust_score"] = trust_score
        context["_risk_score"]  = risk_score
        context["_trust_score"] = trust_score

        for rule in self._rules:
            if not rule.enabled:
                continue
            if self._matches(rule.conditions, context):
                return PolicyDecision(
                    decision=rule.decision,
                    rule_id=rule.rule_id,
                    reason=f"{rule.rule_id}: {rule.name}",
                    obligations=rule.obligations,
                    risk_score=risk_score,
                    session_id=context.get("subject", {}).get("session_id", ""),
                )

        # Fallback (should not reach here due to R008)
        return PolicyDecision(
            decision=Decision.DENY,
            rule_id="R000",
            reason="No matching rule — implicit deny",
            obligations=["LOG_SECURITY_EVENT"],
            risk_score=risk_score,
        )

    # ---- Rule matching ---- #

    def _matches(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """All conditions in a rule must match (AND semantics)."""
        for field_path, matcher in conditions.items():
            value = self._get_nested(context, field_path)
            if not self._apply_matcher(value, matcher):
                return False
        return True

    def _get_nested(self, obj: Dict, path: str) -> Any:
        """Dot-notation field access: 'environment.rat_trust_score'"""
        keys = path.split(".")
        for key in keys:
            if isinstance(obj, dict):
                obj = obj.get(key)
            else:
                return None
        return obj

    def _apply_matcher(self, value: Any, matcher: Dict[str, Any]) -> bool:
        for op, operand in matcher.items():
            if op == "eq"  and value != operand:                          return False
            if op == "neq" and value == operand:                          return False
            if op == "lt"  and not (value is not None and value < operand):  return False
            if op == "lte" and not (value is not None and value <= operand): return False
            if op == "gt"  and not (value is not None and value > operand):  return False
            if op == "gte" and not (value is not None and value >= operand): return False
            if op == "in"  and value not in operand:                      return False
            if op == "nin" and value in operand:                          return False
        return True

    # ---- Authoritative Trust Score (NIST SP 800-207) ---- #

    def _calculate_trust_score(self, ctx: Dict) -> float:
        """
        Calculates a 0.0–1.0 trust score from raw environmental telemetry.
        Never uses a client-supplied trust score — always recomputed here.
        """
        env   = ctx.get("environment", {})
        score = 1.0

        # 1. Security Protocol
        sp = env.get("security_protocol", "Unknown")
        sp_penalties = {
            "WPA3-Personal":    0.0,
            "WPA3-Enterprise":  0.0,
            "WPA2-Enterprise": -0.05,
            "WPA2-Personal":   -0.15,
            "WPA":             -0.30,
            "Open":            -0.60,
            "Unknown":         -0.40,
        }
        score += sp_penalties.get(sp, -0.40)

        # 2. Encryption & Feature Penalties
        if env.get("encryption_type") == "TKIP":
            score -= 0.10
        if not env.get("pmf_enabled", True):
            score -= 0.05

        # 3. Network Type Bonuses
        rat_type = env.get("rat_type", "")
        if "Cellular" in rat_type or rat_type == "Ethernet":
            score += 0.05

        # 4. Risk Signals
        if env.get("is_captive_portal"):
            score -= 0.20
        if env.get("is_public_network"):
            score -= 0.15
        if env.get("vpn_active"):
            score += 0.10

        return round(max(0.0, min(1.0, score)), 3)

    def reload_rules(self, rules: List[PolicyRule]):
        """Hot-reload rules from PolicyAdministrator without restart."""
        self._rules = sorted(rules, key=lambda r: r.priority)
