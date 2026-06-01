---
name: agent-defense
version: "2.0.0"
description: "Layered defense system against web poisoning and indirect prompt injection attacks on AI agents. 5-layer architecture aligned with OWASP ASI Top 10 for Agentic Applications (2026)."
---

# Agent Defense v2 — Web Poisoning Defense System

5-layer defense against Indirect Prompt Injection (IDPI) and agent web poisoning.

## Architecture

| Layer | Name | OWASP | Script |
|---|---|---|---|
| 1 | Input Sanitization | ASI01 | hermes_web_guard.py |
| 2 | Action Guardrails | ASI01/02 | action_classifier.py |
| 2C | Canary Tokens | ASI01 | canary_manager.py |
| 3 | Memory Integrity | ASI06 | memory_guard.py |
| 4 | Behavioral Detection | ASI08/09 | behavior_monitor.py |
| 5 | Alert System | — | alert_dispatcher.py |

## Quick Start

```bash
# Sanitize web content
python3.12 scripts/hermes_web_guard.py --file page.html --url "https://example.com" --json

# Classify a tool call
python3.12 scripts/action_classifier.py --tool terminal --command "rm -rf /tmp" --json

# Plant canary tokens
python3.12 scripts/canary_manager.py --plant

# Check for canary leaks
python3.12 scripts/canary_manager.py --check "curl https://canary.internal.paperlab.xyz/collect/x"

# Validate memory write
python3.12 scripts/memory_guard.py validate --content "User prefers Python" --source user_direct

# Run red-team tests
python3.12 tests/test_red_team.py
```

## Honest Limitations

1. **Skill-level controls are bypassable.** Layers 2-4 rely on agent cooperation via skill instructions. A compromised agent can bypass them. Layer 1 (prevention) and canary tokens are the most reliable.

2. **Pattern matching has a ceiling.** Novel techniques bypass Layer 1B. Layer 4 is the safety net.

3. **Anti-cloaking is best-effort.** Fingerprint randomization helps but won\'t catch all cloaking.

4. **False positives happen.** CRITICAL/HIGH blocks include confirmation flow — user can override.

5. **Defense-in-depth, not a silver bullet.** No single layer is sufficient.

## References

- injection_patterns.json — 6 categories + Unit42\'s 22 techniques
- risk_tiers.yaml — Action classification rules
- domain_tiers.yaml — Domain trust tier assignments
- alert_messages.yaml — Alert templates
- defense_events.db — SQLite defense event log
