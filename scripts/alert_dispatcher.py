#!/usr/bin/env python3
"""alert_dispatcher.py — Layer 5: User Alert System + Defense Event Log"""

import json, time, sqlite3
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

class Severity(str, Enum):
    INFO = "INFO"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"

@dataclass
class DefenseEvent:
    severity: Severity; layer: str; action: str; url: str = ""; snippet: str = ""; details: dict = field(default_factory=dict); timestamp: float = 0.0
    def __post_init__(self):
        if not self.timestamp: self.timestamp = time.time()
    def to_dict(self):
        return {"severity": self.severity.value, "layer": self.layer, "action": self.action, "url": self.url, "snippet": self.snippet[:200], "details": self.details, "timestamp": self.timestamp}

@dataclass
class AlertMessage:
    severity: Severity; title: str; body: str; source_url: str = ""; action_required: bool = False
    def format_discord(self):
        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔍", "INFO": "ℹ️"}.get(self.severity.value, "ℹ️")
        msg = f"{emoji} **AGENT DEFENSE: {self.title}**\n{self.body}"
        if self.source_url: msg += f"\nSource: {self.source_url}"
        if self.action_required: msg += "\n⏸ Session paused — review and confirm to continue."
        return msg
    def format_cli(self):
        label = {"CRITICAL": "🚨 CRITICAL", "HIGH": "⚠️ HIGH", "MEDIUM": "🔍 MEDIUM", "INFO": "ℹ️ INFO"}.get(self.severity.value, "ℹ️")
        msg = f"[{label}] {self.title}\n  {self.body}"
        if self.source_url: msg += f"\n  Source: {self.source_url}"
        if self.action_required: msg += "\n  ⏸ Session paused — review and confirm to continue."
        return msg

class DefenseLog:
    def __init__(self, db_path=None):
        self._db_path = db_path or Path.home() / ".hermes/skills/agent-defense/references/defense_events.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("CREATE TABLE IF NOT EXISTS defense_events (id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT, layer TEXT, action TEXT, url TEXT, snippet TEXT, details TEXT, timestamp REAL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        self._conn.commit()

    def log_event(self, event):
        self._conn.execute("INSERT INTO defense_events (severity, layer, action, url, snippet, details, timestamp) VALUES (?,?,?,?,?,?,?)",
            (event.severity.value, event.layer, event.action, event.url, event.snippet[:500], json.dumps(event.details), event.timestamp))
        self._conn.commit()

    def get_events(self, severity=None, layer=None, since=0, limit=100):
        q = "SELECT * FROM defense_events WHERE timestamp >= ?"; p = [since]
        if severity: q += " AND severity = ?"; p.append(severity.value)
        if layer: q += " AND layer = ?"; p.append(layer)
        q += " ORDER BY timestamp DESC LIMIT ?"; p.append(limit)
        c = self._conn.execute(q, p)
        cols = [d[0] for d in c.description]
        return [dict(zip(cols, row)) for row in c.fetchall()]

    def get_stats(self, since=0):
        c = self._conn.execute("SELECT severity, COUNT(*) FROM defense_events WHERE timestamp >= ? GROUP BY severity", (since,))
        by_sev = dict(c.fetchall())
        c = self._conn.execute("SELECT layer, COUNT(*) FROM defense_events WHERE timestamp >= ? GROUP BY layer", (since,))
        by_layer = dict(c.fetchall())
        c = self._conn.execute("SELECT COUNT(*) FROM defense_events WHERE timestamp >= ?", (since,))
        return {"total": c.fetchone()[0], "by_severity": by_sev, "by_layer": by_layer}

    def close(self): self._conn.close()

class AlertDispatcher:
    def __init__(self, discord_webhook="", log=None):
        self._discord_webhook = discord_webhook; self._log = log or DefenseLog()

    def dispatch(self, event):
        self._log.log_event(event)
        msg = AlertMessage(event.severity, f"Layer {event.layer}: {event.action}", event.details.get("reason", ""), event.url, event.severity in (Severity.CRITICAL, Severity.HIGH))
        print(msg.format_cli())
        if event.severity in (Severity.CRITICAL, Severity.HIGH) and self._discord_webhook:
            self._push_discord(msg)
        return msg

    def _push_discord(self, msg):
        import urllib.request
        payload = json.dumps({"content": msg.format_discord()}).encode()
        req = urllib.request.Request(self._discord_webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp: pass
        except: pass

    @property
    def log(self): return self._log

def main():
    import argparse
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="cmd")
    p1 = sub.add_parser("dispatch"); p1.add_argument("--severity", choices=["INFO","MEDIUM","HIGH","CRITICAL"], required=True); p1.add_argument("--layer", required=True); p1.add_argument("--action", required=True); p1.add_argument("--url", default=""); p1.add_argument("--snippet", default="")
    p2 = sub.add_parser("stats"); p2.add_argument("--days", type=int, default=7)
    p3 = sub.add_parser("list"); p3.add_argument("--severity", choices=["INFO","MEDIUM","HIGH","CRITICAL"]); p3.add_argument("--limit", type=int, default=20)
    parser.add_argument("--json", action="store_true"); args = parser.parse_args()
    d = AlertDispatcher()
    if args.cmd == "dispatch":
        e = DefenseEvent(Severity(args.severity), args.layer, args.action, args.url, args.snippet)
        d.dispatch(e)
    elif args.cmd == "stats":
        s = d.log.get_stats(time.time() - args.days * 86400)
        print(f"Total: {s['total']}, By severity: {s['by_severity']}, By layer: {s['by_layer']}")
    elif args.cmd == "list":
        for e in d.log.get_events(severity=Severity(args.severity) if args.severity else None, limit=args.limit):
            print(f"  [{e['severity']}] Layer {e['layer']} — {e['action']}")

if __name__ == "__main__": main()
