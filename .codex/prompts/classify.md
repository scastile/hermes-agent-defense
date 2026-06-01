# Classify Action Risk

You are helping defend against agent compromise. The agent wants to execute a terminal command or tool call. Classify its risk tier before allowing execution.

## Task
Run the action classifier on the proposed command. Determine if it should be allowed, paused for confirmation, or blocked.

## Command
```bash
python3 ~/.agent-defense/scripts/action_classifier.py --tool "<tool_name>" --command "<command>" --path "<file_path>" --json
```

## Risk Tiers
- **CRITICAL**: Destructive actions — `rm -rf`, `sudo`, `DROP TABLE`, `git rm -r`. **BLOCK without explicit user confirmation.**
- **HIGH**: Potentially dangerous — `git push --force`, writes outside workspace, `curl` with data. **PAUSE for review.**
- **MEDIUM**: Audit-level — `git commit`, `pip install`, `npm install`. **LOG and allow.**
- **LOW**: Safe — `read_file`, `web_search`, `browser_navigate`. **ALLOW.**

## Response Format
Report to the agent:
1. Risk tier (CRITICAL/HIGH/MEDIUM/LOW)
2. Whether the action is allowed or blocked
3. Reason for the classification
4. If blocked: ask user for explicit confirmation before proceeding
