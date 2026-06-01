\
#!/usr/bin/env python3
"""
hermes_web_guard.py — Layer 1: Web Content Firewall

Sanitizes web content before it enters the agent's LLM context.
Handles:
  1A: DOM stripping (CSS-hidden, off-screen, ARIA-hidden, comments, zero-width chars)
  1B: Pattern detection (injection signatures across 6 categories)
  1C: Anti-cloaking detection (fingerprint comparison)
  1D: Domain trust tiers (light/standard/maximum paranoia)
"""

import re
import json
import hashlib
import difflib
from html.parser import HTMLParser
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional


_HIDDEN_CSS_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0*)?(?:\s|;|$)", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0(?:\s|;|$)", re.IGNORECASE),
    re.compile(r"(?:width|height)\s*:\s*0(?:\s|;|$)", re.IGNORECASE),
    re.compile(r"overflow\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"position\s*:\s*(?:absolute|fixed|relative)\s*;\s*(?:left|top|right|bottom)\s*:\s*-\d{3,}", re.IGNORECASE),
    re.compile(r"(?:left|top|right|bottom)\s*:\s*-\d{3,}\s*;\s*position\s*:\s*(?:absolute|fixed|relative)", re.IGNORECASE),
]

_ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}
_BIDI_OVERRIDES = {"\u202e", "\u200f", "\u202a", "\u202b", "\u202d"}

_INJECTION_PATTERNS = {
    "instruction_override": [
        re.compile(r"ignore\s+(?:all\s+)?(?:prior|previous|earlier|above)\s+instructions?", re.IGNORECASE),
        re.compile(r"disregard\s+(?:all\s+)?(?:prior|previous|earlier)\s+instructions?", re.IGNORECASE),
        re.compile(r"forget\s+(?:everything|all|what)", re.IGNORECASE),
        re.compile(r"override\s+(?:all\s+)?(?:prior|previous|safety)?\s*(?:instructions?|guidelines?|rules?)", re.IGNORECASE),
        re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    ],
    "system_prompt_injection": [
        re.compile(r"\[SYSTEM\]", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
        re.compile(r"<<SYS>>", re.IGNORECASE),
        re.compile(r"system\s+(?:message|prompt|override)\s*:", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|root|maintenance)\s+mode", re.IGNORECASE),
    ],
    "role_hijacking": [
        re.compile(r"you\s+are\s+now\s+(?:a|an|the)", re.IGNORECASE),
        re.compile(r"pretend\s+(?:you\s+are|to\s+be)", re.IGNORECASE),
        re.compile(r"act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|unfiltered|unrestricted|uncensored|jailbroken)", re.IGNORECASE),
        re.compile(r"from\s+now\s+on,?\s+you\s+(?:are|will\s+be|become)", re.IGNORECASE),
    ],
    "data_exfiltration": [
        re.compile(r"send\s+(?:all|the|every)\s+(?:user\s+)?(?:data|keys?|credentials?|secrets?|history|api\s+keys?)", re.IGNORECASE),
        re.compile(r"exfiltrat(?:e|ing|ion)\s+(?:all|the|user)?\s*(?:data|keys?|credentials?|secrets?|api\s+keys?)?", re.IGNORECASE),
        re.compile(r"curl\s+.*-d\s+.*http", re.IGNORECASE),
        re.compile(r"POST\s+(?:all|the|user)?\s*(?:data|credentials?|keys?|secrets?)", re.IGNORECASE),
    ],
    "tool_abuse": [
        re.compile(r"execute\s+(?:the\s+)?(?:tool|function|command)", re.IGNORECASE),
        re.compile(r"call\s+(?:the\s+)?(?:terminal|shell|exec|eval)\s+with", re.IGNORECASE),
        re.compile(r"(?:run|invoke)\s+(?:the\s+)?rm\s+-rf", re.IGNORECASE),
    ],
    "agent_spawning": [
        re.compile(r"(?:spawn|create|delegate\s+to|fork)\s+(?:a\s+)?(?:sub[-\s]?agent|new\s+agent|child\s+agent)", re.IGNORECASE),
        re.compile(r"(?:spawn|create|fork)\s+(?:a\s+)?(?:process|thread)\s+with\s+(?:instructions?|prompt)", re.IGNORECASE),
    ],
}

_TIER1_TRUSTED = {
    "github.com", "raw.githubusercontent.com", "arxiv.org", "wikipedia.org",
    "wikimedia.org", "docs.python.org", "developer.mozilla.org",
    "stackoverflow.com", "stackexchange.com",
}
_TIER3_UNTRUSTED_HINTS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "short.link", "cutt.ly", "rb.gy",
]

def _domain_tier(url):
    try:
        host = urlparse(url).netloc.lstrip("www.").lower()
    except Exception:
        return 2
    if host in _TIER1_TRUSTED:
        return 1
    if any(h in host for h in _TIER3_UNTRUSTED_HINTS):
        return 3
    return 2


class DOMStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._output = []
        self._skip_depth = 0
        self._removed = []
        self._tag_stack = []

    def _attrs_to_str(self, attrs):
        parts = []
        for k, v in attrs:
            if v is None:
                parts.append(k)
            else:
                parts.append(k + '="' + v + '"')
        return " ".join(parts)

    def _style_of(self, attrs):
        for k, v in attrs:
            if k.lower() == "style" and v:
                return v.lower()
        return ""

    def _is_hidden(self, tag, attrs):
        style = self._style_of(attrs)
        for pat in _HIDDEN_CSS_PATTERNS:
            if pat.search(style):
                return f"hidden_css"
        for k, v in attrs:
            if k.lower() == "aria-hidden" and v and v.lower() == "true":
                return "aria_hidden"
        if tag in ("script", "style", "noscript", "template"):
            return f"non_visible_tag ({tag})"
        return None

    def handle_starttag(self, tag, attrs):
        self._tag_stack.append((tag, self._attrs_to_str(attrs)))
        if self._skip_depth > 0:
            self._skip_depth += 1
            return
        reason = self._is_hidden(tag, attrs)
        if reason:
            self._skip_depth = 1
            self._removed.append({"type": "hidden_element", "tag": tag, "reason": reason})

    def handle_endtag(self, tag):
        if self._tag_stack and self._tag_stack[-1][0] == tag:
            self._tag_stack.pop()
        if self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        cleaned = "".join(ch for ch in data if ch not in _ZERO_WIDTH_CHARS and ch not in _BIDI_OVERRIDES)
        if cleaned.strip():
            self._output.append(cleaned)

    def handle_comment(self, data):
        self._removed.append({"type": "html_comment", "content_preview": data[:80].strip()})

    def error(self, message):
        pass

    def strip(self, html):
        self._output = []
        self._removed = []
        self._skip_depth = 0
        self._tag_stack = []
        try:
            self.feed(html)
        except Exception:
            pass
        return " ".join(self._output), self._removed


class PatternScanner:
    def __init__(self, extra_patterns=None):
        self._cats = dict(_INJECTION_PATTERNS)
        if extra_patterns:
            for cat, pats in extra_patterns.items():
                self._cats.setdefault(cat, []).extend(pats)

    def scan(self, text):
        detections = []
        seen_spans = set()
        for cat, pats in self._cats.items():
            for pat in pats:
                for m in pat.finditer(text):
                    span = (m.start(), m.end())
                    if span not in seen_spans:
                        seen_spans.add(span)
                        detections.append({"category": cat, "matched": m.group(0), "start": m.start(), "end": m.end()})
        return detections

    def redact(self, text):
        detections = self.scan(text)
        if not detections:
            return text, []
        detections.sort(key=lambda d: (d["start"], -(d["end"] - d["start"])))
        result_parts = []
        cursor = 0
        for d in detections:
            if d["start"] < cursor:
                continue
            result_parts.append(text[cursor:d["start"]])
            result_parts.append(f"[REDACTED: {d['category']}]")
            cursor = d["end"]
        result_parts.append(text[cursor:])
        return "".join(result_parts), detections


class AntiCloakDetector:
    AGENT_HEADERS = {"User-Agent": "Mozilla/5.0 (Hermes-Agent)", "X-Agent-Request": "true"}
    HUMAN_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}

    def __init__(self, threshold=0.3):
        self._threshold = threshold
        self._cache = {}

    def compare_fetches(self, human_html, agent_html):
        stripper = DOMStripper()
        human_text, _ = stripper.strip(human_html)
        agent_text, _ = stripper.strip(agent_html)
        matcher = difflib.SequenceMatcher(None, human_text, agent_text)
        similarity = matcher.ratio()
        diff_ratio = 1.0 - similarity
        verdict = {
            "similarity": round(similarity, 3), "diff_ratio": round(diff_ratio, 3),
            "cloaking_detected": diff_ratio > self._threshold,
            "human_text_length": len(human_text), "agent_text_length": len(agent_text),
        }
        if verdict["cloaking_detected"]:
            diff_blocks = []
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag != "equal":
                    diff_blocks.append({"type": tag, "human_excerpt": human_text[i1:i2][:100], "agent_excerpt": agent_text[j1:j2][:100]})
            verdict["diff_blocks"] = diff_blocks[:10]
        return verdict

    def check_content_hash(self, html, url):
        stripper = DOMStripper()
        text, _ = stripper.strip(html)
        content_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        cached = self._cache.get(url)
        if cached:
            changed = cached != content_hash
            return {"hash": content_hash, "previous_hash": cached, "changed": changed, "verdict": "dynamic_content" if changed else "static"}
        self._cache[url] = content_hash
        return {"hash": content_hash, "previous_hash": None, "changed": False, "verdict": "first_fetch"}

    def generate_report(self, url, human_html, agent_html):
        comparison = self.compare_fetches(human_html, agent_html)
        hash_check = self.check_content_hash(agent_html, url)
        return {
            "url": url, "cloaking_detected": comparison["cloaking_detected"],
            "similarity": comparison["similarity"], "content_dynamic": hash_check["changed"],
            "details": comparison,
            "recommendation": "BLOCK: Cloaking detected" if comparison["cloaking_detected"] else "OK: No cloaking detected",
        }


class WebGuard:
    def __init__(self, config_path=None, custom_patterns=None):
        self._stripper = DOMStripper()
        self._scanner = PatternScanner(extra_patterns=custom_patterns)

    def sanitize(self, html, url=""):
        detections = []
        tier = _domain_tier(url)
        text, removals = self._stripper.strip(html)
        for r in removals:
            r["phase"] = "1A_dom_strip"
            detections.append(r)
        text, pattern_hits = self._scanner.redact(text)
        for h in pattern_hits:
            h["phase"] = "1B_pattern_detect"
            detections.append(h)
        if tier == 3:
            for d in detections:
                d["tier"] = 3
        return text, detections

    def check_url(self, url):
        return _domain_tier(url)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Hermes Web Guard")
    parser.add_argument("--file", help="HTML file to sanitize")
    parser.add_argument("--url", default="")
    parser.add_argument("--html", help="Raw HTML string")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.file and not args.html:
        parser.error("Provide --file or --html")
    html = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file else args.html
    guard = WebGuard()
    clean, detections = guard.sanitize(html, url=args.url)
    if args.json:
        print(json.dumps({"detections": detections, "clean_length": len(clean)}, indent=2))
    else:
        tier = _domain_tier(args.url)
        print(f"[WebGuard] URL={args.url} tier={tier} detections={len(detections)}")
        for d in detections:
            print(f"  {d['phase']}: {d.get('category', d.get('type', '?'))} — {d.get('matched', d.get('reason', ''))[:60]}")
        print(f"\\n[CLEAN TEXT — {len(clean)} chars]\\n{clean[:500]}")

if __name__ == "__main__":
    main()
