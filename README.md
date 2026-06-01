# Agent Defense v2.0.0

**Layered defense system for AI agents against web poisoning and indirect prompt injection attacks.**

5-layer architecture aligned with [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Supported Platforms

| Platform | Integration | Status |
|---|---|---|
| **Claude Code** | `CLAUDE.md` + slash commands | ✅ |
| **OpenAI Codex** | `.codex/` config + prompts | ✅ |
| **Hermes Agent** | `SKILL.md` skill | ✅ |
| **Cursor** | `agent_defense_cli.py` standalone CLI | ✅ |
| **Any AI agent** | `agent_defense_cli.py` standalone CLI | ✅ |

## The Problem

Autonomous AI agents that browse the web are vulnerable to **Indirect Prompt Injection (IDPI)** — malicious instructions embedded in web content that get ingested during summarization and override the agent's original goals.

This isn't theoretical. Real-world attacks confirmed in 2025-2026:

| Attack | Source | Impact |
|---|---|---|
| **AI Agent Traps** | Google DeepMind (Mar 2026) — Franklin et al. | Content injection success up to **86%**; data exfiltration **>80%** across 5 agent architectures; sub-agent spawning hijack **58–93%** |
| **In-the-wild IDPI** | Palo Alto Unit 42 (Mar 2026) | **22 distinct techniques** observed in production — SEO poisoning, data destruction, unauthorized transactions, system prompt leakage |
| **Parallel-Poisoned Web** | Zychlinski (Sep 2025) | Cloaking attacks serve different content to AI agents vs humans — **completely invisible** to users and conventional security tools |
| **Memory Poisoning** | Palo Alto Unit 42 (Oct 2025) | Injected instructions persist via agent memory across sessions, enabling **delayed data exfiltration** |
| **jqwik supply-chain** | jqwik Issue #708 (May 2026) | A Java testing library shipped a hidden ANSI-concealed prompt injection telling agents to **delete code** |

The core issue: **web content is untrusted input, but agents treat it as instruction.** The attack surface is bigger than hidden HTML — it includes cloaked pages, poisoned memory, steganographic payloads, and compromised dependencies.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Content (untrusted)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Layer 1: Input Sanitization (Web Content Firewall)          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │ 1A: DOM    │ │ 1B: Pattern│ │ 1C: Anti-  │ │ 1D: Domain│ │
│  │ Stripping  │ │ Detection  │ │ Cloaking   │ │ Tiers    │ │
│  └────────────┘ └────────────┘ └────────────┘ └──────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ (clean content)
┌──────────────────────────▼──────────────────────────────────┐
│  Layer 2: Action Guardrails                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│  │ 2A: Risk   │ │ 2B: Contam │ │ 2C: Canary │               │
│  │ Tiers      │ │ Window     │ │ Tokens     │               │
│  └────────────┘ └────────────┘ └────────────┘               │
└──────────────────────────┬──────────────────────────────────┘
┌──────────────────────────▼──────────────────────────────────┐
│  Layer 3: Memory Integrity                                   │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│  │ 3A: Memory │ │ 3B: Valid- │ │ 3C: Session│               │
│  │ Contracts  │ │ ation      │ │ Isolation  │               │
│  └────────────┘ └────────────┘ └────────────┘               │
└──────────────────────────┬──────────────────────────────────┘
┌──────────────────────────▼──────────────────────────────────┐
│  Layer 4: Behavioral Anomaly Detection                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│  │ 4A: Finger │ │ 4B: Human  │ │ 4C: Multi- │               │
│  │ prints     │ │ Exploit    │ │ Agent      │               │
│  └────────────┘ └────────────┘ └────────────┘               │
└──────────────────────────┬──────────────────────────────────┘
┌──────────────────────────▼──────────────────────────────────┐
│  Layer 5: Alert System + SQLite Event Log                    │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Option 1: Standalone CLI (any platform)

```bash
git clone https://github.com/scastile/hermes-agent-defense.git ~/.agent-defense

# Sanitize web content
python3 ~/.agent-defense/agent_defense_cli.py sanitize --url "https://example.com" --json

# Classify a command
python3 ~/.agent-defense/agent_defense_cli.py classify --tool terminal --command "rm -rf /tmp" --json

# Validate memory write
python3 ~/.agent-defense/agent_defense_cli.py validate --content "User prefers Python" --source user_direct

# Plant canary tokens
python3 ~/.agent-defense/agent_defense_cli.py canary --plant

# Check stats
python3 ~/.agent-defense/agent_defense_cli.py stats
```

### Option 2: Claude Code

```bash
cp ~/.agent-defense/CLAUDE.md ./CLAUDE.md
```

See [`CLAUDE.md`](CLAUDE.md) for Claude Code integration details.

### Option 3: OpenAI Codex

```bash
cp -r ~/.agent-defense/.codex ./.codex
```

See [`.codex/README.md`](.codex/README.md) for Codex integration details.

### Option 4: Hermes Agent

```bash
cp -r ~/.agent-defense ~/.hermes/skills/agent-defense
```

See [`SKILL.md`](SKILL.md) for Hermes Agent integration details.

## Layer Details

### Layer 1: Input Sanitization (MOST IMPORTANT)

**Before** web content enters the LLM context.

- **1A — DOM Stripping**: Removes `display:none`, `visibility:hidden`, off-screen positioned elements, `aria-hidden="true"`, HTML comments, `<script>`/`<style>` tags, zero-width Unicode characters, and bi-directional overrides
- **1B — Pattern Detection**: Scans visible text for injection signatures across 6 categories (instruction override, system prompt injection, role hijacking, data exfiltration, tool abuse, agent spawning). Matched content is replaced with `[REDACTED: category]`
- **1C — Anti-Cloaking Detection**: Compares page content across different browser fingerprints to detect if a site serves different content to AI agents vs humans
- **1D — Domain Trust Tiers**: Trusted domains (github.com, arxiv.org) get light sanitization. Unknown/URL-shortener domains get maximum paranoia.

### Layer 2: Action Guardrails

**Before** the agent executes destructive actions.

- **2A — Risk Tiers**: Classifies tool calls as CRITICAL (`rm -rf`, `sudo`, `DROP TABLE`), HIGH (`git push --force`, writes outside workspace), MEDIUM (`git commit`, `pip install`), or LOW (`read_file`, `web_search`)
- **2B — Contamination Window**: Tracks whether the agent's goal shifted after web browsing. Destructive actions within the window get auto-escalated one tier. Context-aware, not a fixed turn count.
- **2C — Canary Tokens**: Fake API keys and URLs planted in the agent's environment. If the agent ever tries to use them, compromise is confirmed.

### Layer 3: Memory Integrity

**Protects** the agent's long-term memory from injected false beliefs.

- **3A — Memory Contracts**: Only allowed categories (user_preference, environment_fact, etc.) can be stored. Injection patterns are blocked.
- **3B — Validation**: Re-scans stored memories on read. Tier 3 sources require re-validation.
- **3C — Session Isolation**: Web-derived context is session-scoped by default. Promoting to long-term memory requires explicit user confirmation.

### Layer 4: Behavioral Anomaly Detection

**Monitors** agent behavior for compromise patterns, even from novel attacks.

- **4A — Behavioral Fingerprints**: Detects exfiltration chains (read `.env` → `curl` to external URL), destructive git sequences, privilege escalation, command obfuscation (`base64 -d`, `eval`, `curl|sh`)
- **4B — Human Exploitation Detection**: Flags agent output that combines urgency language ("urgent", "immediately") with action requests — per OWASP ASI09
- **4C — Multi-Agent Cascade**: Sub-agent instructions must be a strict subset of parent scope

### Layer 5: Alert System

**Notifies** the user immediately when any layer triggers.

- **CRITICAL**: Discord push + session halt
- **HIGH**: Discord push
- **MEDIUM**: Session annotation
- **INFO**: Defense log only (SQLite)

All events are persisted to `references/defense_events.db` for trend analysis.

## Testing

```bash
python3 tests/test_red_team.py
```

20 tests covering:
- All 6 DeepMind attack categories
- DOM stripping (hidden CSS, off-screen, ARIA-hidden, comments, zero-width chars)
- Domain trust tiers
- False positive checks (normal content should not be flagged)

## OWASP Alignment

| OWASP Risk | Our Layer |
|---|---|
| ASI01: Agent Goal Hijack | Layers 1 + 2 |
| ASI02: Tool Misuse & Exploitation | Layer 2 |
| ASI06: Memory & Context Poisoning | Layer 3 |
| ASI08: Cascading Agent Failures | Layers 2 + 4 |
| ASI09: Human-Agent Trust Exploitation | Layer 4 |

## Honest Limitations

1. **Skill-level controls are bypassable.** Layers 2-4 are implemented as Python modules called via skill instructions or CLI. They're effective against *accidental* injection but a determined attacker who fully compromises the agent's reasoning could bypass them. **Layer 1 (input sanitization) and canary tokens are the most reliable defenses** because they don't require the agent to cooperate.

2. **Pattern matching has a ceiling.** Novel injection techniques that don't match known patterns will bypass Layer 1B. Layer 4 (behavioral detection) is the safety net, but it has its own blind spots.

3. **Anti-cloaking is best-effort.** Fingerprint randomization helps but won't catch all cloaking attacks.

4. **False positives happen.** The contamination window can escalate legitimate actions. All CRITICAL/HIGH blocks include a confirmation flow — the user can override.

5. **This is defense-in-depth, not a silver bullet.** No single layer is sufficient. The goal is to make attacks progressively harder and detect compromise even when prevention fails.

## Recommended Reading

- [Google DeepMind: "AI Agent Traps"](https://arxiv.org/abs/2603.15714) (Franklin et al., Mar 2026) — 6 attack categories, benchmark results
- [Palo Alto Unit42: "Web-Based IDPI in the Wild"](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) (Mar 2026) — 22 real-world techniques
- [Palo Alto Unit42: "When AI Remembers Too Much"](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/) (Oct 2025) — Memory poisoning PoC
- [Zychlinski: "Parallel-Poisoned Web"](https://arxiv.org/abs/2509.00124) (Sep 2025) — Cloaking attacks
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — Industry risk framework
- [jqwik Issue #708](https://github.com/jqwik-team/jqwik/issues/708) (May 2026) — Real supply-chain injection via ANSI concealment

## License

MIT
