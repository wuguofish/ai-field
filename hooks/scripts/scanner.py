#!/usr/bin/env python3
"""
A.I. Field — Core Security Scanner
Agent Integrity Field: Scans skill/plugin content for behavioral security risks.

10 Security Categories:
  1. Telemetry / Local Logging
  2. Remote Data Transmission
  3. Credentials Handling
  4. CLAUDE.md Injection          [BLOCKING]
  5. External Promotion / Platform Lock-in
  6. Proactive Workflow Takeover
  7. Tool Blocking / Hijacking    [BLOCKING]
  8. Hooks Safety                 [BLOCKING]
  9. Settings.json Manipulation
 10. Recursive Installation / Supply Chain
"""

import re
import json
import os
import sys
import io
from dataclasses import dataclass, field
from typing import List

# Fix Windows encoding for emoji output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ═══════════════════════════════════════════════════════
#  Data Structures
# ═══════════════════════════════════════════════════════

LEVEL_SAFE = "safe"
LEVEL_WARNING = "warning"
LEVEL_CRITICAL = "critical"

LEVEL_ICON = {
    LEVEL_SAFE: "\U0001f7e2",      # 🟢
    LEVEL_WARNING: "\U0001f7e1",   # 🟡
    LEVEL_CRITICAL: "\U0001f534",  # 🔴
}


@dataclass
class Finding:
    line_number: int
    matched_text: str
    pattern: str
    source_file: str = ""


@dataclass
class CategoryResult:
    id: int
    name: str
    level: str = LEVEL_SAFE
    blocking: bool = False
    findings: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════
#  Category Definitions
# ═══════════════════════════════════════════════════════

CATEGORIES = [
    {
        "id": 1,
        "name": "Telemetry / Local Logging",
        "blocking": False,
        "red_patterns": [
            r"always\s.*log",
            r"write\s.*log\s+regardless",
            r"off\s+setting\s+has\s+no\s+effect",
            r"unconditional.*log",
        ],
        "yellow_patterns": [
            r"timeline\.jsonl",
            r"\.jsonl",
            r"telemetry",
            r"analytics",
            r"log.*write",
            r"write.*log",
        ],
    },
    {
        "id": 2,
        "name": "Remote Data Transmission",
        "blocking": False,
        "red_patterns": [
            r"fetch\s*\(",
            r"axios\s*[.\(]",
            r"send.*data.*remote",
            r"upload.*(?:error|file.?path|branch)",
            r"report.*remote",
        ],
        "yellow_patterns": [
            r"https?://(?!.*(?:github\.com|docs\.|documentation|example\.com|claude\.ai|anthropic\.com))",
            r"remote.*api",
            r"upload",
        ],
    },
    {
        "id": 3,
        "name": "Credentials Handling",
        "blocking": False,
        "red_patterns": [
            r"(?:service_role|private_key|secret_key)\s*[:=]",
            r"bearer\s+[A-Za-z0-9\-_\.]{20,}",
            r"password\s*[:=]\s*['\"][^'\"]+['\"]",
        ],
        "yellow_patterns": [
            r"api[_\-]?key",
            r"secret",
            r"\btoken\b",
            r"bearer",
            r"password",
            r"credentials",
            r"private_key",
            r"service_role",
        ],
    },
    {
        "id": 4,
        "name": "CLAUDE.md Injection",
        "blocking": True,
        "red_patterns": [
            r"ALWAYS\s+invoke.*(?:Skill|skill)\s+tool",
            r"Do\s+NOT\s+answer\s+directly",
            r"Do\s+NOT\s+use\s+other\s+tools\s+first",
            r"(?:^|\s)FIRST\s+action",
            r"(?:write|append|create|inject)\s.*CLAUDE\.md",
            r"git\s+add\s+.*CLAUDE\.md",
            r"git\s+commit.*CLAUDE\.md",
            r"routing\s+rule",
            r"MUST\s+(?:always\s+)?(?:use|invoke|call)\s+(?:this|the)\s+skill",
        ],
        "yellow_patterns": [
            r"modify.*CLAUDE\.md",
            r"update.*CLAUDE\.md",
            r"works\s+best\s+when",
            r"we\s+suggest",
            r"recommended.*install",
        ],
    },
    {
        "id": 5,
        "name": "External Promotion / Platform Lock-in",
        "blocking": False,
        "red_patterns": [
            r"(?:ref|utm_\w+)=",
            r"sponsored",
            r"affiliate",
            r"auto.*open.*(?:url|browser|link)",
            r"window\.open\s*\(",
        ],
        "yellow_patterns": [
            r"ycombinator",
            r"open.*apply",
            r"powered\s+by",
        ],
    },
    {
        "id": 6,
        "name": "Proactive Workflow Takeover",
        "blocking": False,
        "red_patterns": [
            r"proactive.*(?:true|enabled|on)\b.*default",
            r"default.*proactive.*true",
            r"We\s+recommend\s+keeping",
            r"recommended.*(?:\bon\b|enabled)",
            r"auto[_\-]?enable",
        ],
        "yellow_patterns": [
            r"proactive",
            r"auto.*activate",
            r"opt[_\-]?out",
        ],
    },
    {
        "id": 7,
        "name": "Tool Blocking / Claude Hijacking",
        "blocking": True,
        "red_patterns": [
            r"NEVER\s+use\s+mcp__",
            r"[Nn]ever\s+use.*tools?\b",
            r"Do\s+NOT\s+use.*tool",
            r"avoid\s.*mcp__",
            r"block\s.*tool",
            r"disable\s.*tool",
            r"\u7981\u6b62\u4f7f\u7528",   # 禁止使用
            r"\u4e0d\u5f97\u4f7f\u7528",   # 不得使用
            r"MUST\s+NOT\s+use",
        ],
        "yellow_patterns": [
            r"prefer\s+\w+\s+over",
            r"instead\s+of\s+(?:using\s+)?mcp__",
            r"\u4e0d\u5efa\u8b70\u4f7f\u7528",  # 不建議使用
        ],
    },
    {
        "id": 8,
        "name": "Hooks Safety",
        "blocking": True,
        "red_patterns": [
            r"rm\s+-rf\b",
            r"rm\s+-r\s",
            r"del\s+/[sfq]",
            r"format\s+[a-zA-Z]:",
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"os\.system\s*\(",
            r"subprocess\.(?:call|run|Popen)\s*\(",
            r"__import__\s*\(",
            r"curl\s.*\|\s*(?:ba)?sh",
            r"wget\s.*\|\s*(?:ba)?sh",
            r"base64\s+(?:-d|--decode)",
            r"powershell.*-(?:enc|encodedcommand)\b",
            r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}",
        ],
        "yellow_patterns": [
            r"\bcurl\s",
            r"\bwget\s",
            r"npm\s+(?:run|exec)\b",
            r"\bnpx\s",
            r"pip\s+install\b",
            r"chmod\s",
            r"chown\s",
        ],
    },
    {
        "id": 9,
        "name": "Settings.json Manipulation",
        "blocking": False,
        "red_patterns": [
            r"(?:write|modify|overwrite|append)\s.*settings\.json",
            r"(?:write|modify|overwrite|append)\s.*settings\.local\.json",
            r"enabledPlugins",
            r"disabledPlugins",
        ],
        "yellow_patterns": [
            r"settings\.json",
            r"settings\.local\.json",
            r"\.claude[/\\]settings",
        ],
    },
    {
        "id": 10,
        "name": "Recursive Installation / Supply Chain",
        "blocking": False,
        "red_patterns": [
            r"git\s+clone\s.*(?:skill|plugin)",
            r"curl\s.*\.(?:sh|py|js)\s*\|",
            r"wget\s.*\.(?:sh|py|js)\s*\|",
            r"(?:install|download)\s.*(?:skill|plugin)\s.*(?:from|via)",
            r"npm\s+install\s.*(?:claude|skill|plugin)",
        ],
        "yellow_patterns": [
            r"git\s+clone\b",
            r"npm\s+install\b",
            r"pip\s+install\b",
            r"download.*(?:script|code)",
        ],
    },
]


# ═══════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════

def _is_in_comment_or_example(line: str) -> bool:
    """Check if a line is likely a comment, example, or documentation."""
    stripped = line.strip()
    # Markdown comments
    if stripped.startswith("<!--"):
        return True
    # Code block markers
    if stripped.startswith("```"):
        return True
    # "Before (problematic)" / "After (safe)" example blocks
    if re.search(r"#\s*(Before|After)\s*[\(\u2014\-]", stripped):
        return True
    return False


def scan_content(content: str, source_file: str = "") -> List[CategoryResult]:
    """Scan content against all 10 security categories."""
    lines = content.split("\n")
    results = []

    # Track if we're inside a code example block
    in_example_block = False

    for cat_def in CATEGORIES:
        result = CategoryResult(
            id=cat_def["id"],
            name=cat_def["name"],
            blocking=cat_def["blocking"],
        )

        # Track which lines already have findings (for dedup)
        seen_lines = set()

        # --- Check RED patterns ---
        for pattern in cat_def["red_patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                if regex.search(line) and i not in seen_lines:
                    seen_lines.add(i)
                    # Context-aware: downgrade if inside comment/example
                    is_example = _is_in_comment_or_example(line)

                    result.findings.append(Finding(
                        line_number=i,
                        matched_text=line.strip()[:120],
                        pattern=pattern,
                        source_file=source_file,
                    ))

                    if is_example:
                        if result.level == LEVEL_SAFE:
                            result.level = LEVEL_WARNING
                    else:
                        result.level = LEVEL_CRITICAL

        # --- Check YELLOW patterns (only if no RED found) ---
        if result.level != LEVEL_CRITICAL:
            for pattern in cat_def["yellow_patterns"]:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    continue

                for i, line in enumerate(lines, 1):
                    if regex.search(line):
                        already = any(f.line_number == i for f in result.findings)
                        if not already:
                            result.findings.append(Finding(
                                line_number=i,
                                matched_text=line.strip()[:120],
                                pattern=pattern,
                                source_file=source_file,
                            ))
                            if result.level == LEVEL_SAFE:
                                result.level = LEVEL_WARNING

        results.append(result)

    return results


def scan_files(paths: List[str]) -> List[CategoryResult]:
    """Scan multiple files and merge results."""
    merged = {cat["id"]: CategoryResult(
        id=cat["id"], name=cat["name"], blocking=cat["blocking"]
    ) for cat in CATEGORIES}

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            continue

        file_results = scan_content(content, source_file=path)
        for fr in file_results:
            target = merged[fr.id]
            target.findings.extend(fr.findings)
            # Escalate level
            if fr.level == LEVEL_CRITICAL:
                target.level = LEVEL_CRITICAL
            elif fr.level == LEVEL_WARNING and target.level == LEVEL_SAFE:
                target.level = LEVEL_WARNING

    return list(merged.values())


# ═══════════════════════════════════════════════════════
#  Report Formatting
# ═══════════════════════════════════════════════════════

def format_report(results: List[CategoryResult], target_name: str = "unknown") -> str:
    """Format scan results into a readable report."""
    has_blocking_red = any(
        r.level == LEVEL_CRITICAL and r.blocking for r in results
    )
    has_red = any(r.level == LEVEL_CRITICAL for r in results)
    has_yellow = any(r.level == LEVEL_WARNING for r in results)

    if has_blocking_red:
        verdict = "\U0001f6ab BLOCKED \u2014 Critical issues in blocking categories"
    elif has_red:
        verdict = "\u26a0\ufe0f WARNING \u2014 Critical issues found (non-blocking)"
    elif has_yellow:
        verdict = "\u26a0\ufe0f PASS WITH NOTES \u2014 Review recommended"
    else:
        verdict = "\u2705 PASS \u2014 No security issues detected"

    lines = []
    lines.append("\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510")
    lines.append("\u2502  \U0001f6e1\ufe0f  A.I. Field \u2014 Security Scan Report                       \u2502")
    target_display = target_name[:50]
    lines.append(f"\u2502  Target: {target_display:<53}\u2502")
    lines.append("\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518")
    lines.append("")

    header = f"{'#':<4} {'Category':<42} {'Score':<6} {'Findings'}"
    lines.append(header)
    lines.append("\u2500" * 70)

    for r in results:
        icon = LEVEL_ICON[r.level]
        blocking_tag = " \u26a0\ufe0f" if r.blocking else ""
        name = f"{r.name}{blocking_tag}"
        note = f"{len(r.findings)} finding(s)" if r.findings else "Clean"
        lines.append(f"{r.id:<4} {name:<42} {icon:<6} {note}")

    lines.append("")
    lines.append(f"Verdict: {verdict}")

    # Detail: critical findings
    critical = [(r, f) for r in results if r.level == LEVEL_CRITICAL for f in r.findings]
    if critical:
        lines.append("")
        lines.append("\u2550" * 3 + " \U0001f534 Critical Issues " + "\u2550" * 3)
        for r, f in critical:
            src = f" ({f.source_file})" if f.source_file else ""
            lines.append(f"  [{r.id}. {r.name}] Line {f.line_number}{src}")
            lines.append(f"    \u2192 {f.matched_text}")

    # Detail: warnings (limit 15)
    warnings = [(r, f) for r in results if r.level == LEVEL_WARNING for f in r.findings]
    if warnings:
        lines.append("")
        lines.append("\u2550" * 3 + " \U0001f7e1 Warnings " + "\u2550" * 3)
        for r, f in warnings[:15]:
            src = f" ({f.source_file})" if f.source_file else ""
            lines.append(f"  [{r.id}. {r.name}] Line {f.line_number}{src}")
            lines.append(f"    \u2192 {f.matched_text}")
        if len(warnings) > 15:
            lines.append(f"  ... and {len(warnings) - 15} more")

    return "\n".join(lines)


def results_to_json(results: List[CategoryResult]) -> str:
    """Convert results to JSON for programmatic use."""
    data = []
    for r in results:
        data.append({
            "id": r.id,
            "name": r.name,
            "level": r.level,
            "blocking": r.blocking,
            "findings": [
                {
                    "line": f.line_number,
                    "text": f.matched_text,
                    "pattern": f.pattern,
                    "file": f.source_file,
                }
                for f in r.findings
            ],
        })
    return json.dumps(data, ensure_ascii=False, indent=2)


def has_blocking_critical(results: List[CategoryResult]) -> bool:
    """Check if any blocking category has critical findings."""
    return any(r.level == LEVEL_CRITICAL and r.blocking for r in results)


def has_any_critical(results: List[CategoryResult]) -> bool:
    """Check if any category has critical findings."""
    return any(r.level == LEVEL_CRITICAL for r in results)


# ═══════════════════════════════════════════════════════
#  CLI Entry Point
# ═══════════════════════════════════════════════════════

def main():
    """CLI: python scanner.py [--json] <path> [path2 ...]"""
    args = sys.argv[1:]
    output_json = False

    if "--json" in args:
        output_json = True
        args.remove("--json")

    if not args:
        print("Usage: python scanner.py [--json] <path-to-skill-or-plugin>", file=sys.stderr)
        sys.exit(1)

    # Collect files to scan
    files_to_scan = []
    for path in args:
        if os.path.isfile(path):
            files_to_scan.append(path)
        elif os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for f in files:
                    if f.lower().endswith((".md", ".json", ".yaml", ".yml", ".sh", ".py", ".js", ".ts")):
                        files_to_scan.append(os.path.join(root, f))

    if not files_to_scan:
        print(f"No scannable files found at: {args}", file=sys.stderr)
        sys.exit(1)

    target_name = os.path.basename(args[0])
    results = scan_files(files_to_scan)

    if output_json:
        print(results_to_json(results))
    else:
        print(format_report(results, target_name))

    # Exit code: 2 = blocking critical, 1 = non-blocking critical, 0 = clean
    if has_blocking_critical(results):
        sys.exit(2)
    elif has_any_critical(results):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
