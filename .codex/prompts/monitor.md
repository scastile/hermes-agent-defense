# Behavioral Monitor

You are helping detect agent compromise through behavioral analysis. After each significant action, record it and check for anomalies.

## Task
Record the agent's action and run fingerprint checks to detect compromise patterns.

## Record Action
```bash
python3 ~/.agent-defense/scripts/behavior_monitor.py record "<tool_name>" "<command>" "<url_context>"
```

## Check for Anomalies
```bash
python3 ~/.agent-defense/scripts/behavior_monitor.py check
```

## Detected Fingerprint Patterns
- **exfiltration**: Read credentials → external network request
- **destructive_chain**: git log → reset --hard → force push
- **privilege_escalation**: sudo when not in original task
- **command_obfuscation**: base64 decode, eval, curl|sh
- **memory_manipulation**: Writing to memory after browsing
- **human_exploitation**: Urgency + action request in output

## Response Format
Report to the agent:
1. Number of fingerprint matches
2. For each match: pattern name, severity, description
3. Recommended action (block_and_alert, flag_for_review)
