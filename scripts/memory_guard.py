#!/usr/bin/env python3
"""memory_guard.py — Layer 3: Memory Integrity Validator"""

import re, json, time
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path
from hermes_web_guard import _INJECTION_PATTERNS, _domain_tier

ALLOWED_CATEGORIES = {"user_preference", "environment_fact", "project_convention", "tool_quirk", "procedural_knowledge", "session_temporary"}
BLOCKED_TIERS = {3}

@dataclass
class MemoryEntry:
    content: str; category: str; source: str = ""; source_tier: int = 2
    timestamp: float = 0.0; is_trusted: bool = False; is_web_derived: bool = False; warnings: list = field(default_factory=list)
    def __post_init__(self):
        if not self.timestamp: self.timestamp = time.time()
        if self.source and self.source.startswith("http"): self.is_web_derived = True
    def to_dict(self):
        return {"content": self.content[:200], "category": self.category, "source": self.source,
                "source_tier": self.source_tier, "is_trusted": self.is_trusted, "is_web_derived": self.is_web_derived, "warnings": self.warnings}

@dataclass
class ValidationResult:
    valid: bool; entry: Optional[MemoryEntry]; reason: str; warnings: list = field(default_factory=list)
    def to_dict(self): return {"valid": self.valid, "reason": self.reason, "warnings": self.warnings}

class MemoryGuard:
    def __init__(self, state_path=None):
        self._entries = []
        self._state_path = state_path or Path.home() / ".hermes/skills/agent-defense/references/memory_state.json"
        self._load_state()

    def validate_write(self, content, category="", source=""):
        warnings = []
        source_tier = 1 if source == "user_direct" else _domain_tier(source) if source else 2
        injection_hits = self._check_injection_patterns(content)
        if injection_hits:
            cats = ", ".join(set(h["category"] for h in injection_hits))
            return ValidationResult(False, None, f"BLOCKED: Injection patterns ({cats})", [f"Pattern: {h['matched']}" for h in injection_hits])
        if category and category not in ALLOWED_CATEGORIES:
            warnings.append(f"Unknown category"); category = "session_temporary"
        if source_tier in BLOCKED_TIERS and category not in ("session_temporary",):
            warnings.append(f"Tier {source_tier} — forcing session_temporary"); category = "session_temporary"
        if source.startswith("http"): warnings.append("Web-derived — session-scoped")
        is_trusted = source == "user_direct" or source_tier == 1
        entry = MemoryEntry(content, category or "session_temporary", source, source_tier, is_trusted=is_trusted, is_web_derived=source.startswith("http"), warnings=warnings)
        return ValidationResult(True, entry, "OK" if not warnings else "OK with warnings", warnings)

    def validate_read(self, entry):
        hits = self._check_injection_patterns(entry.content)
        if hits: return ValidationResult(False, entry, "BLOCKED: Injection patterns detected", [h["matched"] for h in hits])
        if entry.source_tier in BLOCKED_TIERS: return ValidationResult(True, entry, "WARNING: Tier 3 source", ["Untrusted source"])
        return ValidationResult(True, entry, "OK")

    def store(self, entry):
        result = self.validate_write(entry.content, entry.category, entry.source)
        if result.valid and result.entry: self._entries.append(result.entry); self._save_state(); return True
        return False

    def get_all(self):
        return [e for e in self._entries if self.validate_read(e).valid]

    def clear_session_temp(self):
        self._entries = [e for e in self._entries if e.category != "session_temporary"]; self._save_state()

    def _check_injection_patterns(self, text):
        hits = []
        for cat, pats in _INJECTION_PATTERNS.items():
            for pat in pats:
                for m in pat.finditer(text): hits.append({"category": cat, "matched": m.group(0)})
        return hits

    def _save_state(self):
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(json.dumps([e.to_dict() for e in self._entries], indent=2))

    def _load_state(self):
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text())
                self._entries = [MemoryEntry(d["content"], d["category"], d.get("source",""), d.get("source_tier",2), d.get("timestamp",0), d.get("is_trusted",False), d.get("is_web_derived",False), d.get("warnings",[])) for d in data]
            except: self._entries = []

def main():
    import argparse
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="cmd")
    p1 = sub.add_parser("validate"); p1.add_argument("--content", required=True); p1.add_argument("--source", default=""); p1.add_argument("--category", default="")
    p2 = sub.add_parser("store"); p2.add_argument("--content", required=True); p2.add_argument("--source", default=""); p2.add_argument("--category", default="")
    sub.add_parser("list"); sub.add_parser("clear"); sub.add_parser("session-clear")
    parser.add_argument("--json", action="store_true"); args = parser.parse_args()
    guard = MemoryGuard()
    if args.cmd == "validate":
        r = guard.validate_write(args.content, args.category, args.source)
        print(f"[MemoryGuard] {'OK' if r.valid else 'BLOCKED'}: {r.reason}")
    elif args.cmd == "store":
        e = MemoryEntry(args.content, args.category, args.source); print(f"[MemoryGuard] {'stored' if guard.store(e) else 'rejected'}")
    elif args.cmd == "list":
        for e in guard.get_all(): print(f"  [{e.category}] {e.content[:60]} (src={e.source}, tier={e.source_tier})")
    elif args.cmd == "clear": guard._entries = []; guard._save_state(); print("Cleared")
    elif args.cmd == "session-clear": guard.clear_session_temp(); print("Session cleared")

if __name__ == "__main__": main()
