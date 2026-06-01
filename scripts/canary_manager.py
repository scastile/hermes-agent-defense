#!/usr/bin/env python3
"""canary_manager.py — Layer 2C: Canary Token Management"""

import os, re, json, uuid, hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

@dataclass
class Canary:
    name: str; value: str; canary_type: str; triggered: bool = False

@dataclass
class LeakResult:
    leaked: bool; canary_name: str; canary_value: str; context: str; severity: str = "CRITICAL"
    def to_dict(self):
        return {"leaked": self.leaked, "canary_name": self.canary_name,
                "canary_value": self.canary_value[:20] + "...", "context": self.context[:100], "severity": self.severity}

class CanaryManager:
    CANARY_ENV_PREFIX = "CANARY_"
    CANARY_URL_DOMAIN = "canary.internal.paperlab.xyz"

    def __init__(self, state_path=None):
        self._canaries = []
        self._state_path = state_path or Path.home() / ".hermes/skills/agent-defense/references/canary_state.json"
        self._load_state()

    def plant(self, count=3):
        canaries = []
        for i in range(count):
            key = f"{self.CANARY_ENV_PREFIX}API_KEY_{i}_{uuid.uuid4().hex[:8]}"
            value = f"sk_test_{uuid.uuid4().hex}"
            canaries.append(Canary(name=key, value=value, canary_type="env_var"))
        for i in range(count):
            token = uuid.uuid4().hex[:12]
            url = f"https://{self.CANARY_URL_DOMAIN}/collect/{token}"
            canaries.append(Canary(name=f"CANARY_URL_{i}", value=url, canary_type="url"))
        for i, fp in enumerate(["/tmp/.canary_secrets.db", "/root/.canary_credentials.json", "/home/agent/.canary_api_keys.env"]):
            canaries.append(Canary(name=f"CANARY_FILE_{i}", value=fp, canary_type="file_path"))
        self._canaries = canaries; self._save_state(); return canaries

    def get_env_exports(self):
        return {c.name: c.value for c in self._canaries if c.canary_type == "env_var"}

    def check_leak(self, text, context=""):
        for canary in self._canaries:
            if canary.value and canary.value in text:
                canary.triggered = True; self._save_state()
                return LeakResult(True, canary.name, canary.value, context or text[:200])
            if canary.canary_type == "url" and self.CANARY_URL_DOMAIN in text:
                canary.triggered = True; self._save_state()
                return LeakResult(True, canary.name, canary.value, context or text[:200])
        return None

    def check_command(self, command): return self.check_leak(command, f"terminal: {command[:100]}")

    def _save_state(self):
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        data = [{"name": c.name, "value": c.value, "type": c.canary_type, "triggered": c.triggered} for c in self._canaries]
        self._state_path.write_text(json.dumps(data, indent=2))

    def _load_state(self):
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text())
                self._canaries = [Canary(d["name"], d["value"], d["type"], d.get("triggered", False)) for d in data]
            except: self._canaries = []

def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--plant", action="store_true"); parser.add_argument("--check", help="Check string"); parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    mgr = CanaryManager()
    if args.plant:
        canaries = mgr.plant()
        for c in canaries: print(f"  {c.canary_type}: {c.name} = {c.value[:30]}...")
    if args.check:
        result = mgr.check_leak(args.check)
        if result: print(f"[CanaryManager] LEAK: {result.canary_name}")
        else: print("[CanaryManager] No leak detected")

if __name__ == "__main__": main()
