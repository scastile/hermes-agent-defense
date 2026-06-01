#!/usr/bin/env python3
"""behavior_monitor.py — Layer 4: Behavioral Anomaly Detection"""

import re, json, time
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class ActionRecord:
    tool_name: str; command: str = ""; path: str = ""; url_context: str = ""; timestamp: float = 0.0; turn_number: int = 0
    def __post_init__(self):
        if not self.timestamp: self.timestamp = time.time()

@dataclass
class FingerprintMatch:
    pattern_name: str; severity: str; description: str; evidence: list = field(default_factory=list); recommended_action: str = "block_and_alert"
    def to_dict(self):
        return {"pattern": self.pattern_name, "severity": self.severity, "description": self.description, "evidence": self.evidence, "action": self.recommended_action}

class BehaviorMonitor:
    MAX_HISTORY = 50
    def __init__(self, state_path=None):
        self._history = []; self._turn = 0

    def record_action(self, tool_name, command="", path="", url_context=""):
        self._turn += 1
        self._history.append(ActionRecord(tool_name, command, path, url_context, turn_number=self._turn))
        if len(self._history) > self.MAX_HISTORY: self._history = self._history[-self.MAX_HISTORY:]

    def check_exfiltration(self):
        cred_read = None
        for rec in self._history[-10:]:
            if rec.tool_name in ("read_file", "terminal") and rec.command:
                if re.search(r"\b(?:cat|grep|head|tail)\s+.*(?:\.env|credentials|\.ssh|\.gnupg|\.aws|token|secret|key|password|\.pem)", rec.command, re.IGNORECASE):
                    cred_read = rec
            if cred_read and rec.tool_name == "terminal" and re.search(r"\b(?:curl|wget|nc|python)\s+.*http", rec.command, re.IGNORECASE):
                return FingerprintMatch("exfiltration", "CRITICAL", "Read credentials then made external request",
                    [f"read: {cred_read.command[:80]}", f"send: {rec.command[:80]}"])
        return None

    def check_destructive_chain(self):
        recent = [r for r in self._history[-15:] if r.tool_name == "terminal"]
        cmds = " ".join(r.command.lower() for r in recent)
        if "git log" in cmds and "git reset" in cmds and "--force" in cmds:
            return FingerprintMatch("destructive_chain", "CRITICAL", "git log -> reset --hard -> force push",
                [r.command[:80] for r in recent if r.command.strip()])
        return None

    def check_privilege_escalation(self):
        for rec in self._history[-5:]:
            if rec.tool_name == "terminal" and re.search(r"\bsudo\b", rec.command, re.IGNORECASE):
                return FingerprintMatch("privilege_escalation", "CRITICAL", "Agent requested sudo", [rec.command[:100]])
        return None

    def check_command_obfuscation(self):
        patterns = [(r"base64\s+-d", "base64_decode"), (r"\beval\s+", "eval"), (r"curl\s+.*\|\s*(?:sh|bash)", "curl_pipe_shell"), (r"exec\s*\(", "exec_call")]
        for rec in self._history[-5:]:
            if rec.tool_name == "terminal" and rec.command:
                for pat, name in patterns:
                    if re.search(pat, rec.command, re.IGNORECASE):
                        return FingerprintMatch("command_obfuscation", "CRITICAL", f"Obfuscated command: {name}", [rec.command[:100]])
        return None

    def check_memory_manipulation(self):
        browsed = False
        for rec in self._history[-10:]:
            if rec.tool_name in ("web_extract", "browser_navigate") and rec.url_context: browsed = True
            if browsed and rec.tool_name == "memory":
                return FingerprintMatch("memory_manipulation", "HIGH", "Wrote to memory after browsing", [f"browse: {rec.url_context[:80]}"])
        return None

    def check_human_exploitation(self, agent_output):
        urgency = re.compile(r"\b(?:urgent|immediately|critical|emergency|asap)\b", re.IGNORECASE)
        action_req = re.compile(r"(?:run|execute|type|copy|paste|visit|click|download|install)\s+(?:this|the following|below)", re.IGNORECASE)
        if urgency.search(agent_output) and action_req.search(agent_output):
            return FingerprintMatch("human_exploitation", "HIGH", "Urgency + action request in output", [agent_output[:200]])
        return None

    def check_current_state(self, agent_output=""):
        matches = []
        for fn in [self.check_exfiltration, self.check_destructive_chain, self.check_privilege_escalation, self.check_command_obfuscation, self.check_memory_manipulation]:
            r = fn()
            if r: matches.append(r)
        if agent_output:
            r = self.check_human_exploitation(agent_output)
            if r: matches.append(r)
        return matches

    @property
    def history(self): return list(self._history)
    @property
    def turn(self): return self._turn
    def reset(self): self._history = []; self._turn = 0

def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--record", nargs="+"); parser.add_argument("--check", action="store_true"); parser.add_argument("--output", default=""); parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    m = BehaviorMonitor()
    if args.record:
        tool = args.record[0] if args.record else ""
        cmd = args.record[1] if len(args.record) > 1 else ""
        url = args.record[2] if len(args.record) > 2 else ""
        m.record_action(tool, command=cmd, url_context=url)
    if args.check:
        matches = m.check_current_state(args.output)
        if matches:
            for match in matches: print(f"  {match.severity}: {match.pattern_name} — {match.description}")
        else: print("[BehaviorMonitor] No anomalies")

if __name__ == "__main__": main()
