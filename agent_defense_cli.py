#!/usr/bin/env python3
"""
agent_defense_cli.py — Standalone CLI for Agent Defense

Works with any AI coding agent (Claude Code, OpenAI Codex, Hermes, Cursor, etc.)
No Hermes dependency required.

Usage:
    python3 agent_defense_cli.py sanitize --url "https://example.com" --html "<html>"
    python3 agent_defense_cli.py classify --tool terminal --command "rm -rf /tmp"
    python3 agent_defense_cli.py validate --content "..." --source "https://..."
    python3 agent_defense_cli.py monitor --record terminal "cat /env" "https://evil.com"
    python3 agent_defense_cli.py monitor --check
    python3 agent_defense_cli.py canary --plant
    python3 agent_defense_cli.py canary --check "curl https://canary..."
    python3 agent_defense_cli.py alert --severity CRITICAL --layer 1B --action "..." --url "..."
    python3 agent_defense_cli.py stats
"""

import argparse
import json
import sys
import os

# Add scripts dir to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "scripts"))

from hermes_web_guard import WebGuard, AntiCloakDetector
from action_classifier import ActionGuard, RiskTier, ContaminationWindow
from memory_guard import MemoryGuard
from behavior_monitor import BehaviorMonitor
from alert_dispatcher import AlertDispatcher, DefenseEvent, Severity


def cmd_sanitize(args):
    guard = WebGuard()
    html = args.html or ""
    if args.file:
        html = open(args.file).read()
    if args.url and not html:
        import urllib.request
        try:
            req = urllib.request.Request(args.url, headers={"User-Agent": "Mozilla/5.0"})
            html = urllib.request.urlopen(req, timeout=10).read().decode("utf-8", errors="replace")
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            return
    clean, detections = guard.sanitize(html, url=args.url or "")
    result = {"detections": detections, "clean_length": len(clean), "tier": guard.check_url(args.url or "")}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[Sanitize] {len(detections)} detections, tier={result['tier']}")
        for d in detections:
            print(f"  {d['phase']}: {d.get('category', d.get('type', '?'))}")


def cmd_classify(args):
    guard = ActionGuard()
    result = guard.enforce(args.tool, command=args.command or "", path=args.path or "")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "ALLOWED" if result.allowed else "BLOCKED"
        print(f"[Classify] {args.tool}: {status} (tier={result.tier.name})")
        if result.reason:
            print(f"  {result.reason}")


def cmd_validate(args):
    guard = MemoryGuard()
    result = guard.validate_write(args.content, category=args.category or "", source=args.source or "")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "OK" if result.valid else "BLOCKED"
        print(f"[Validate] {status}: {result.reason}")
        for w in result.warnings:
            print(f"  Warning: {w}")


def cmd_monitor(args):
    monitor = BehaviorMonitor()
    if args.record:
        tool = args.record[0] if args.record else ""
        cmd = args.record[1] if len(args.record) > 1 else ""
        url = args.record[2] if len(args.record) > 2 else ""
        monitor.record_action(tool, command=cmd, url_context=url)
        print(f"[Monitor] Recorded: {tool}")
    if args.check:
        matches = monitor.check_current_state(agent_output=args.output or "")
        if matches:
            print(f"[Monitor] {len(matches)} fingerprint match(es):")
            for m in matches:
                print(f"  {m.severity}: {m.pattern_name} - {m.description}")
        else:
            print("[Monitor] No behavioral anomalies")


def cmd_canary(args):
    from canary_manager import CanaryManager
    mgr = CanaryManager()
    if args.plant:
        canaries = mgr.plant()
        print(f"[Canary] Planted {len(canaries)} canaries")
        for c in canaries:
            print(f"  {c.canary_type}: {c.name}")
    if args.check:
        result = mgr.check_leak(args.check)
        if result:
            print(f"[Canary] LEAK DETECTED: {result.canary_name}")
            print(f"  Context: {result.context}")
        else:
            print("[Canary] No leak detected")


def cmd_alert(args):
    disp = AlertDispatcher(discord_webhook=args.webhook or "")
    event = DefenseEvent(
        severity=Severity(args.severity), layer=args.layer, action=args.action,
        url=args.url or "", snippet=args.snippet or ""
    )
    msg = disp.dispatch(event)
    if not args.json:
        print(f"[Alert] {msg.format_cli()}")


def cmd_stats(args):
    disp = AlertDispatcher()
    import time
    since = time.time() - (args.days * 86400) if args.days else 0
    stats = disp.log.get_stats(since=since)
    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print(f"[Stats] {stats['total']} events" + (f" (last {args.days} days)" if args.days else ""))
        for sev, count in stats.get("by_severity", {}).items():
            print(f"  {sev}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Agent Defense CLI - works with Claude Code, Codex, Hermes, and any AI coding agent")
    sub = parser.add_subparsers(dest="cmd", help="Command")

    # sanitize
    p1 = sub.add_parser("sanitize", help="Sanitize web content")
    p1.add_argument("--url", default="")
    p1.add_argument("--html", default="")
    p1.add_argument("--file", default="")
    p1.add_argument("--json", action="store_true")

    # classify
    p2 = sub.add_parser("classify", help="Classify action risk tier")
    p2.add_argument("--tool", required=True)
    p2.add_argument("--command", default="")
    p2.add_argument("--path", default="")
    p2.add_argument("--json", action="store_true")

    # validate
    p3 = sub.add_parser("validate", help="Validate memory write")
    p3.add_argument("--content", required=True)
    p3.add_argument("--source", default="")
    p3.add_argument("--category", default="")
    p3.add_argument("--json", action="store_true")

    # monitor
    p4 = sub.add_parser("monitor", help="Behavioral monitoring")
    p4.add_argument("--record", nargs="+", help="Record an action: tool [command] [url]")
    p4.add_argument("--check", action="store_true", help="Check for anomalies")
    p4.add_argument("--output", default="", help="Agent output to check")

    # canary
    p5 = sub.add_parser("canary", help="Canary token management")
    p5.add_argument("--plant", action="store_true")
    p5.add_argument("--check", help="Check a string for canary leaks")

    # alert
    p6 = sub.add_parser("alert", help="Dispatch defense event alert")
    p6.add_argument("--severity", choices=["INFO", "MEDIUM", "HIGH", "CRITICAL"], required=True)
    p6.add_argument("--layer", required=True)
    p6.add_argument("--action", required=True)
    p6.add_argument("--url", default="")
    p6.add_argument("--snippet", default="")
    p6.add_argument("--webhook", default="")
    p6.add_argument("--json", action="store_true")

    # stats
    p7 = sub.add_parser("stats", help="Defense event statistics")
    p7.add_argument("--days", type=int, default=0)
    p7.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    cmds = {
        "sanitize": cmd_sanitize, "classify": cmd_classify, "validate": cmd_validate,
        "monitor": cmd_monitor, "canary": cmd_canary, "alert": cmd_alert, "stats": cmd_stats,
    }
    cmds[args.cmd](args)


if __name__ == "__main__":
    main()
