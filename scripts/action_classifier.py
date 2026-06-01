#!/usr/bin/env python3
"""action_classifier.py — Layer 2: Action Guardrails"""

import re
import json
import time
from enum import IntEnum
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

class RiskTier(IntEnum):
    LOW = 0; MEDIUM = 1; HIGH = 2; CRITICAL = 3

_CRITICAL_TERMINAL = [
    re.compile(r"\brm\s+-[rfRF]+\b"),
    re.compile(r"\brm\s+.*\*"),
    re.compile(r"\bgit\s+rm\s+(-[rR]+\s+)+", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r"\bformat\b", re.IGNORECASE),
    re.compile(r"\bshred\b", re.IGNORECASE),
]
_HIGH_TERMINAL = [
    re.compile(r"\bgit\s+push\s+.*--force", re.IGNORECASE),
    re.compile(r"\bcurl\s+.*-d\s+.*http", re.IGNORECASE),
    re.compile(r"\bwget\s+.*http", re.IGNORECASE),
    re.compile(r"\bdocker\s+rm\s+(-[fF]+\s+)+", re.IGNORECASE),
    re.compile(r"\bkubectl\s+delete\b", re.IGNORECASE),
]
_MEDIUM_TERMINAL = [
    re.compile(r"\bgit\s+commit\b", re.IGNORECASE),
    re.compile(r"\bgit\s+push\b", re.IGNORECASE),
    re.compile(r"\bpip\s+(?:uninstall|install)\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(?:uninstall|install)\b", re.IGNORECASE),
    re.compile(r"\bapt(?:-get)?\s+(?:remove|install|purge)\b", re.IGNORECASE),
]

def classify_tool_call(tool_name, command="", path="", method=""):
    if tool_name == "terminal":
        for pat in _CRITICAL_TERMINAL:
            if pat.search(command): return RiskTier.CRITICAL
        for pat in _HIGH_TERMINAL:
            if pat.search(command): return RiskTier.HIGH
        for pat in _MEDIUM_TERMINAL:
            if pat.search(command): return RiskTier.MEDIUM
        return RiskTier.LOW
    if tool_name in ("write_file", "patch"):
        if _is_outside_workspace(path): return RiskTier.HIGH
        return RiskTier.LOW
    if tool_name in ("web_search", "read_file", "browser_navigate", "web_extract", "browser_snapshot"):
        return RiskTier.LOW
    if tool_name in ("delegate_task", "execute_code"):
        return RiskTier.MEDIUM
    return RiskTier.LOW

def _is_outside_workspace(path):
    if not path: return False
    return bool(re.match(r"^/(?:etc|usr|var|boot|sys|proc|dev|run|sbin)(?:/|$)", path))

@dataclass
class ContaminationWindow:
    original_goal: str = ""
    browsing_url: str = ""
    browsing_tier: int = 2
    browsing_time: float = 0.0
    turn_count_since_browse: int = 0
    max_turns: int = 3
    decay_seconds: float = 120.0
    _active: bool = False

    def start(self, goal, url, tier=2):
        self.original_goal = goal.lower(); self.browsing_url = url
        self.browsing_tier = tier; self.browsing_time = time.time()
        self.turn_count_since_browse = 0; self._active = True

    def turn(self): self.turn_count_since_browse += 1

    def reset(self): self._active = False; self.turn_count_since_browse = 0

    def is_active(self):
        if not self._active: return False
        if time.time() - self.browsing_time > self.decay_seconds: self._active = False; return False
        if self.turn_count_since_browse > self.max_turns: self._active = False; return False
        return True

    def should_escalate(self, current_action_desc):
        if not self.is_active(): return False
        action_lower = current_action_desc.lower()
        if self.browsing_tier >= 3:
            destructive = ["delete", "remove", "drop", "format", "wipe", "exfiltrate", "send", "post"]
            if any(kw in action_lower for kw in destructive): return True
        goal_words = set(re.findall(r"\b[a-z]{4,}\b", self.original_goal))
        action_words = set(re.findall(r"\b[a-z]{4,}\b", action_lower))
        if goal_words and action_words:
            similarity = len(goal_words & action_words) / max(len(goal_words), 1)
            if similarity < 0.2:
                destructive = ["delete", "remove", "drop", "exfiltrate", "send", "format"]
                if any(kw in action_lower for kw in destructive): return True
        return False

@dataclass
class EnforcementResult:
    allowed: bool; tier: RiskTier; original_tier: RiskTier
    reason: str; requires_confirmation: bool; source_url: str = ""; phase: str = "layer2"
    def to_dict(self):
        return {"allowed": self.allowed, "tier": self.tier.name, "original_tier": self.original_tier.name,
                "reason": self.reason, "requires_confirmation": self.requires_confirmation, "source_url": self.source_url}

class ActionGuard:
    def __init__(self, contamination_window=None):
        self.window = contamination_window or ContaminationWindow()

    def enforce(self, tool_name, command="", path="", method="", current_action_desc=""):
        base_tier = classify_tool_call(tool_name, command, path, method)
        original_tier = base_tier
        if self.window.should_escalate(current_action_desc) and base_tier < RiskTier.CRITICAL:
            base_tier = RiskTier(min(int(base_tier) + 1, 3))
            reason = f"Escalated from {original_tier.name} due to contamination window"
        else:
            reason = ""
        if base_tier == RiskTier.CRITICAL:
            return EnforcementResult(allowed=False, tier=base_tier, original_tier=original_tier,
                reason=reason or "CRITICAL: Destructive action blocked", requires_confirmation=True, source_url=self.window.browsing_url)
        elif base_tier == RiskTier.HIGH:
            return EnforcementResult(allowed=False, tier=base_tier, original_tier=original_tier,
                reason=reason or "HIGH: Potentially dangerous action", requires_confirmation=True, source_url=self.window.browsing_url)
        elif base_tier == RiskTier.MEDIUM:
            return EnforcementResult(allowed=True, tier=base_tier, original_tier=original_tier,
                reason=reason or "MEDIUM: Logged for audit", requires_confirmation=False, source_url=self.window.browsing_url)
        else:
            return EnforcementResult(allowed=True, tier=RiskTier.LOW, original_tier=original_tier, reason="LOW: Allowed", requires_confirmation=False)

def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--tool", required=True)
    parser.add_argument("--command", default=""); parser.add_argument("--path", default=""); parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    guard = ActionGuard()
    result = guard.enforce(args.tool, command=args.command, path=args.path)
    if args.json: print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"[ActionGuard] {args.tool}: {'ALLOWED' if result.allowed else 'BLOCKED'} (tier={result.tier.name})")
        print(f"  Reason: {result.reason}")

if __name__ == "__main__": main()
