# Agent Defense — OpenAI Codex Integration

This directory contains defense configuration for [OpenAI Codex](https://openai.com/codex/).

## Quick Start

```bash
# Clone the repo
git clone https://github.com/scastile/hermes-agent-defense.git ~/.agent-defense

# Copy Codex config to your project
cp -r ~/.agent-defense/.codex ./.codex
```

## How It Works

When Codex is working in a project with `.codex/`, it will:

1. **Before browsing**: Run `hermes_web_guard.py` on web content
2. **Before destructive actions**: Check commands against `action_classifier.py`
3. **Before saving web-derived info**: Validate with `memory_guard.py`
4. **Continuously**: Monitor behavior via `behavior_monitor.py`

## Files

| File | Purpose |
|---|---|
| `config.yaml` | Defense configuration (domains, thresholds, alerting) |
| `prompts/sanitize.md` | Prompt template for web content sanitization |
| `prompts/classify.md` | Prompt template for action classification |
| `prompts/validate.md` | Prompt template for memory validation |
| `prompts/monitor.md` | Prompt template for behavioral monitoring |

## Configuration

Edit `config.yaml` to customize defense behavior for your project.

## Integration Pattern

### 1. Sanitize Web Content (Layer 1)
Before processing web content, run:
```bash
python3 ~/.agent-defense/scripts/hermes_web_guard.py --url "<url>" --json
```

### 2. Check Destructive Actions (Layer 2)
Before executing terminal commands:
```bash
python3 ~/.agent-defense/scripts/action_classifier.py --tool terminal --command "<cmd>" --json
```

### 3. Validate Memory Writes (Layer 3)
Before saving web-derived information:
```bash
python3 ~/.agent-defense/scripts/memory_guard.py validate --content "<text>" --source "<url>"
```

### 4. Monitor Behavior (Layer 4)
Record actions for anomaly detection:
```bash
python3 ~/.agent-defense/scripts/behavior_monitor.py record terminal "<cmd>" "<url>"
```

### 5. Alert on Detection (Layer 5)
Log defense events:
```bash
python3 ~/.agent-defense/scripts/alert_dispatcher.py dispatch --severity CRITICAL --layer 1B --action "<what>" --url "<url>"
```

## Testing

```bash
cd ~/.agent-defense && python3.12 tests/test_red_team.py
```
