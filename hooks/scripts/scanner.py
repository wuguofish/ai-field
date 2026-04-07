#!/usr/bin/env python3
"""
A.I. Field — Core Security Scanner v2
Agent Integrity Field: Scans skill/plugin content for behavioral security risks.

v2 improvements:
  - Context-aware: tracks code blocks, frontmatter, comments
  - File-type awareness: skips doc files (README, LICENSE, etc.)
  - Confidence scoring: reduces false positives with weighted scores
  - Findings below confidence threshold are auto-dismissed

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
from typing import List, Tuple

# Fix Windows encoding for emoji output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ═══════════════════════════════════════════════════════
#  Constants & Data Structures
# ═══════════════════════════════════════════════════════

LEVEL_SAFE = "safe"
LEVEL_WARNING = "warning"
LEVEL_CRITICAL = "critical"

LEVEL_ICON = {
    LEVEL_SAFE: "\U0001f7e2",      # 🟢
    LEVEL_WARNING: "\U0001f7e1",   # 🟡
    LEVEL_CRITICAL: "\U0001f534",  # 🔴
}

# Confidence thresholds
CONF_HIGH = 0.6       # Keep original severity
CONF_MEDIUM = 0.4     # Downgrade one level (red→yellow, yellow→dismiss)
# Below CONF_MEDIUM: auto-dismiss

# File classification
FTYPE_SKIP = "skip"         # Skip entirely (README, LICENSE, etc.)
FTYPE_DOC = "doc"           # Documentation — low confidence
FTYPE_CODE = "code"         # Source code — medium confidence
FTYPE_CONFIG = "config"     # Config files — higher confidence
FTYPE_SKILL = "skill"       # SKILL.md, COMMAND.md — high confidence
FTYPE_HOOK = "hook"         # hooks.json, hook scripts — high confidence

# Line context
CTX_INSTRUCTION = "instruction"
CTX_CODE_BLOCK = "code_block"
CTX_COMMENT = "comment"
CTX_FRONTMATTER = "frontmatter"
CTX_EXAMPLE = "example"

# Files to skip entirely — documentation that never contains real instructions
SKIP_FILENAMES = {
    "readme.md", "changelog.md", "changes.md", "history.md",
    "license", "license.md", "license.txt",
    "code_of_conduct.md", "contributing.md", "contributors.md",
    "security.md", "support.md",
    ".gitignore", ".npmignore", ".eslintignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ".prettierrc", ".prettierrc.json", ".eslintrc.json",
}

# Base confidence by file type
FTYPE_BASE_CONFIDENCE = {
    FTYPE_SKIP: 0.0,
    FTYPE_DOC: 0.2,
    FTYPE_CODE: 0.55,
    FTYPE_CONFIG: 0.7,
    FTYPE_SKILL: 0.9,
    FTYPE_HOOK: 0.9,
}

# Context confidence modifiers
CTX_MODIFIERS = {
    CTX_INSTRUCTION: 0.0,
    CTX_CODE_BLOCK: -0.35,
    CTX_COMMENT: -0.4,
    CTX_FRONTMATTER: 0.0,
    CTX_EXAMPLE: -0.35,
}


@dataclass
class Finding:
    line_number: int
    matched_text: str
    pattern: str
    source_file: str = ""
    confidence: float = 0.8
    context: str = CTX_INSTRUCTION


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
            r"always\s+(?:write|log|record|track)",
            r"write\s.*log\s+regardless",
            r"off\s+setting\s+has\s+no\s+effect",
            r"unconditional.*(?:log|track|record)",
            r"(?:This|this)\s+is\s+a\s+logging\s+parameter",
        ],
        "yellow_patterns": [
            r"timeline\.jsonl",
            r"(?<!\.)\.jsonl\b",
            r"\btelemetry\b",
            r"\banalytics\b",
        ],
    },
    {
        "id": 2,
        "name": "Remote Data Transmission",
        "blocking": False,
        "red_patterns": [
            r"(?<!function\s)fetch\s*\(['\"]https?://",
            r"axios\.(?:get|post|put|delete)\s*\(",
            r"send.*(?:user\s*)?data.*(?:to\s+)?remote",
            r"upload.*(?:error|file.?path|branch|source)",
            r"report.*(?:to\s+)?remote",
            r"exfiltrat",
        ],
        "yellow_patterns": [
            r"remote.*api\b",
        ],
    },
    {
        "id": 3,
        "name": "Credentials Handling",
        "blocking": False,
        "red_patterns": [
            r"(?:service_role|private_key|secret_key)\s*[:=]\s*['\"]",
            r"bearer\s+[A-Za-z0-9\-_\.]{30,}",
            r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        ],
        "yellow_patterns": [
            r"(?:api[_\-]?key|secret|credentials|private_key|service_role)\s*[:=]",
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
            r"(?:write|append|create|inject)\s+.*(?:to\s+)?CLAUDE\.md",
            r"git\s+(?:add|commit).*CLAUDE\.md",
            r"MUST\s+(?:always\s+)?(?:use|invoke|call)\s+(?:this|the)\s+(?:skill|tool|workflow)",
            r"as\s+your\s+FIRST\s+action",
        ],
        "yellow_patterns": [
            r"(?:modify|update|edit)\s+.*CLAUDE\.md",
            r"works\s+best\s+when",
            r"we\s+(?:strongly\s+)?suggest",
            r"routing\s+rule",
        ],
    },
    {
        "id": 5,
        "name": "External Promotion / Platform Lock-in",
        "blocking": False,
        "red_patterns": [
            r"utm_\w+=",
            r"\bsponsored\b.*\bcontent\b",
            r"\baffiliate\b.*\blink",
            r"auto.*open.*(?:url|browser|link)",
            r"window\.open\s*\(",
        ],
        "yellow_patterns": [
            r"\bref=\w+",
            r"powered\s+by",
        ],
    },
    {
        "id": 6,
        "name": "Proactive Workflow Takeover",
        "blocking": False,
        "red_patterns": [
            r"proactive\s*[:=]\s*(?:true|enabled|on)\b",
            r"default\s*[:=].*proactive.*true",
            r"We\s+recommend\s+keeping\s+(?:this|it)\s+on",
            r"auto[_\-]?enable\s*[:=]\s*true",
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
            r"(?:NEVER|Never|never)\s+use\s+mcp__\w+",
            r"(?:NEVER|Never)\s+use\s+(?:the\s+)?(?:Read|Write|Edit|Bash|Grep|Glob)\s+tool",
            r"Do\s+NOT\s+use\s+(?:the\s+)?\w+\s+tool",
            r"(?:avoid|block|disable)\s+(?:the\s+)?mcp__\w+",
            r"\u7981\u6b62\u4f7f\u7528.*(?:tool|\u5de5\u5177)",   # 禁止使用...工具
            r"\u4e0d\u5f97\u4f7f\u7528.*(?:tool|\u5de5\u5177)",   # 不得使用...工具
            r"MUST\s+NOT\s+(?:ever\s+)?use\s+\w+",
        ],
        "yellow_patterns": [
            r"prefer\s+\w+\s+over\s+mcp__",
            r"instead\s+of\s+(?:using\s+)?mcp__",
            r"\u4e0d\u5efa\u8b70\u4f7f\u7528",  # 不建議使用
        ],
    },
    {
        "id": 8,
        "name": "Hooks Safety",
        "blocking": True,
        "red_patterns": [
            r"rm\s+-rf\s+[~/\$]",
            r"rm\s+-rf\s+\*",
            r"del\s+/[sfq]",
            r"format\s+[a-zA-Z]:",
            r"os\.system\s*\(",
            r"subprocess\.(?:call|run|Popen)\s*\(",
            r"__import__\s*\(",
            r"curl\s+.*\|\s*(?:ba)?sh",
            r"wget\s+.*\|\s*(?:ba)?sh",
            r"base64\s+(?:-d|--decode)\s*\|",
            r"powershell\s.*-(?:enc|encodedcommand)\b",
        ],
        "yellow_patterns": [
            r"\bcurl\s+-[^s]",
            r"\bwget\s+",
            r"chmod\s+[0-7]{3,4}\s",
        ],
    },
    {
        "id": 9,
        "name": "Settings.json Manipulation",
        "blocking": False,
        "red_patterns": [
            r"(?:write|overwrite|append)\s+(?:to\s+)?.*settings\.(?:local\.)?json",
            r"\"enabledPlugins\"",
            r"\"disabledPlugins\"",
        ],
        "yellow_patterns": [
            r"settings\.json",
            r"settings\.local\.json",
        ],
    },
    {
        "id": 10,
        "name": "Recursive Installation / Supply Chain",
        "blocking": False,
        "red_patterns": [
            r"git\s+clone\s+.*(?:skill|plugin)",
            r"curl\s+.*\.(?:sh|py|js)\s*\|\s*(?:ba)?sh",
            r"wget\s+.*\.(?:sh|py|js)\s*\|\s*(?:ba)?sh",
            r"(?:install|download)\s+.*(?:skill|plugin)\s+.*(?:from|via)\b",
        ],
        "yellow_patterns": [
            r"git\s+clone\b",
            r"npm\s+install\b",
            r"pip\s+install\b",
        ],
    },
]


# ═══════════════════════════════════════════════════════
#  File & Context Classification
# ═══════════════════════════════════════════════════════

def classify_file(filepath: str) -> str:
    """Classify a file by its role in the skill/plugin."""
    basename = os.path.basename(filepath).lower()
    _name, ext = os.path.splitext(basename)

    # Skip documentation / boilerplate files
    if basename in SKIP_FILENAMES:
        return FTYPE_SKIP

    # Skill / command definitions
    if basename in ("skill.md", "command.md"):
        return FTYPE_SKILL

    # Hook configurations and scripts
    if basename == "hooks.json":
        return FTYPE_HOOK
    if "hook" in filepath.lower() and ext in (".sh", ".py", ".js", ".ts"):
        return FTYPE_HOOK

    # Config files
    if ext in (".json", ".yaml", ".yml"):
        if basename in ("plugin.json", ".mcp.json", "settings.json"):
            return FTYPE_CONFIG
        return FTYPE_CONFIG

    # Agent / other markdown definitions
    if ext == ".md":
        # Agent definitions
        if "agent" in filepath.lower():
            return FTYPE_SKILL
        return FTYPE_CONFIG  # Other .md files in plugins are usually meaningful

    # Source code
    if ext in (".py", ".js", ".ts", ".sh", ".bash"):
        return FTYPE_CODE

    return FTYPE_DOC


def build_context_map(lines: List[str]) -> List[str]:
    """Build a context map for each line: instruction, code_block, comment, frontmatter, example."""
    n = len(lines)
    contexts = [CTX_INSTRUCTION] * n

    in_code_block = False
    in_frontmatter = False
    frontmatter_dashes = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # YAML frontmatter: --- at very beginning of file
        if stripped == "---":
            if i == 0 or (frontmatter_dashes == 1 and in_frontmatter):
                frontmatter_dashes += 1
                in_frontmatter = frontmatter_dashes == 1
                if frontmatter_dashes == 2:
                    in_frontmatter = False
                contexts[i] = CTX_FRONTMATTER
                continue

        if in_frontmatter:
            contexts[i] = CTX_FRONTMATTER
            continue

        # Code fences
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            contexts[i] = CTX_CODE_BLOCK
            continue

        if in_code_block:
            contexts[i] = CTX_CODE_BLOCK
            continue

        # HTML comments
        if stripped.startswith("<!--"):
            contexts[i] = CTX_COMMENT
            continue

        # Example headers and nearby content
        if re.search(r"#\s*(?:Before|After|Bad|Wrong|Problematic|Example)\b", stripped, re.IGNORECASE):
            contexts[i] = CTX_EXAMPLE
            continue

        # Lines starting with # (markdown headers) that mention fix/example
        if stripped.startswith("#") and re.search(r"(?:fix|example|incorrect|wrong)", stripped, re.IGNORECASE):
            contexts[i] = CTX_EXAMPLE
            continue

    return contexts


# ═══════════════════════════════════════════════════════
#  Confidence Scoring
# ═══════════════════════════════════════════════════════

def calculate_confidence(file_type: str, context: str) -> float:
    """Calculate confidence score for a finding based on file type and context."""
    base = FTYPE_BASE_CONFIDENCE.get(file_type, 0.5)
    modifier = CTX_MODIFIERS.get(context, 0.0)
    return max(0.0, min(1.0, base + modifier))


def apply_confidence(level: str, confidence: float) -> str:
    """Apply confidence threshold to adjust severity level."""
    if confidence >= CONF_HIGH:
        return level  # Keep as-is
    elif confidence >= CONF_MEDIUM:
        # Downgrade one level
        if level == LEVEL_CRITICAL:
            return LEVEL_WARNING
        else:
            return LEVEL_SAFE
    else:
        return LEVEL_SAFE  # Auto-dismiss


# ═══════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════

def scan_content(content: str, source_file: str = "", file_type: str = "") -> List[CategoryResult]:
    """Scan content against all 10 security categories with context awareness."""
    if not file_type:
        file_type = classify_file(source_file) if source_file else FTYPE_CONFIG

    # Skip files that shouldn't be scanned
    if file_type == FTYPE_SKIP:
        return [CategoryResult(id=c["id"], name=c["name"], blocking=c["blocking"]) for c in CATEGORIES]

    lines = content.split("\n")
    context_map = build_context_map(lines)
    results = []

    for cat_def in CATEGORIES:
        result = CategoryResult(
            id=cat_def["id"],
            name=cat_def["name"],
            blocking=cat_def["blocking"],
        )

        seen_lines = set()
        effective_level = LEVEL_SAFE

        # --- Check RED patterns ---
        for pattern in cat_def["red_patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            for i, line in enumerate(lines):
                line_num = i + 1
                if regex.search(line) and line_num not in seen_lines:
                    seen_lines.add(line_num)
                    ctx = context_map[i]
                    conf = calculate_confidence(file_type, ctx)
                    adj_level = apply_confidence(LEVEL_CRITICAL, conf)

                    if adj_level == LEVEL_SAFE:
                        continue  # Auto-dismissed

                    result.findings.append(Finding(
                        line_number=line_num,
                        matched_text=line.strip()[:120],
                        pattern=pattern,
                        source_file=source_file,
                        confidence=round(conf, 2),
                        context=ctx,
                    ))

                    if adj_level == LEVEL_CRITICAL and effective_level != LEVEL_CRITICAL:
                        effective_level = LEVEL_CRITICAL
                    elif adj_level == LEVEL_WARNING and effective_level == LEVEL_SAFE:
                        effective_level = LEVEL_WARNING

        # --- Check YELLOW patterns (only if no effective RED) ---
        if effective_level != LEVEL_CRITICAL:
            for pattern in cat_def["yellow_patterns"]:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    continue

                for i, line in enumerate(lines):
                    line_num = i + 1
                    if regex.search(line) and line_num not in seen_lines:
                        seen_lines.add(line_num)
                        ctx = context_map[i]
                        conf = calculate_confidence(file_type, ctx)
                        adj_level = apply_confidence(LEVEL_WARNING, conf)

                        if adj_level == LEVEL_SAFE:
                            continue

                        result.findings.append(Finding(
                            line_number=line_num,
                            matched_text=line.strip()[:120],
                            pattern=pattern,
                            source_file=source_file,
                            confidence=round(conf, 2),
                            context=ctx,
                        ))

                        if effective_level == LEVEL_SAFE:
                            effective_level = LEVEL_WARNING

        result.level = effective_level
        results.append(result)

    return results


def scan_files(paths: List[str]) -> List[CategoryResult]:
    """Scan multiple files and merge results, with file-type awareness."""
    merged = {cat["id"]: CategoryResult(
        id=cat["id"], name=cat["name"], blocking=cat["blocking"]
    ) for cat in CATEGORIES}

    for path in paths:
        ftype = classify_file(path)
        if ftype == FTYPE_SKIP:
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            continue

        file_results = scan_content(content, source_file=path, file_type=ftype)
        for fr in file_results:
            target = merged[fr.id]
            target.findings.extend(fr.findings)
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
    has_blocking_red = any(r.level == LEVEL_CRITICAL and r.blocking for r in results)
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

    out = []
    out.append("\u250c" + "\u2500" * 62 + "\u2510")
    out.append("\u2502  \U0001f6e1\ufe0f  A.I. Field \u2014 Security Scan Report                       \u2502")
    out.append(f"\u2502  Target: {target_name[:50]:<53}\u2502")
    out.append("\u2514" + "\u2500" * 62 + "\u2518")
    out.append("")

    out.append(f"{'#':<4} {'Category':<42} {'Score':<6} {'Findings'}")
    out.append("\u2500" * 70)

    for r in results:
        icon = LEVEL_ICON[r.level]
        btag = " \u26a0\ufe0f" if r.blocking else ""
        name = f"{r.name}{btag}"
        note = f"{len(r.findings)} finding(s)" if r.findings else "Clean"
        out.append(f"{r.id:<4} {name:<42} {icon:<6} {note}")

    out.append("")
    out.append(f"Verdict: {verdict}")

    # Critical findings detail
    critical = [(r, f) for r in results if r.level == LEVEL_CRITICAL for f in r.findings]
    if critical:
        out.append("")
        out.append("\u2550" * 3 + " \U0001f534 Critical Issues " + "\u2550" * 3)
        for r, f in critical:
            src = f" ({os.path.basename(f.source_file)})" if f.source_file else ""
            conf_str = f" [conf:{f.confidence:.0%}]"
            out.append(f"  [{r.id}. {r.name}] Line {f.line_number}{src}{conf_str}")
            out.append(f"    \u2192 {f.matched_text}")

    # Warning findings detail (limit 15)
    warnings = [(r, f) for r in results if r.level == LEVEL_WARNING for f in r.findings]
    if warnings:
        out.append("")
        out.append("\u2550" * 3 + " \U0001f7e1 Warnings " + "\u2550" * 3)
        for r, f in warnings[:15]:
            src = f" ({os.path.basename(f.source_file)})" if f.source_file else ""
            conf_str = f" [conf:{f.confidence:.0%}]"
            out.append(f"  [{r.id}. {r.name}] Line {f.line_number}{src}{conf_str}")
            out.append(f"    \u2192 {f.matched_text}")
        if len(warnings) > 15:
            out.append(f"  ... and {len(warnings) - 15} more")

    # LLM review hint
    needs_review = [f for r in results for f in r.findings if CONF_MEDIUM <= f.confidence < CONF_HIGH]
    if needs_review:
        out.append("")
        out.append(f"\U0001f4a1 {len(needs_review)} finding(s) have medium confidence and may benefit from LLM review.")
        out.append("   Run /ai-field-scan for a deep analysis with AI-assisted judgment.")

    return "\n".join(out)


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
                    "confidence": f.confidence,
                    "context": f.context,
                }
                for f in r.findings
            ],
        })
    return json.dumps(data, ensure_ascii=False, indent=2)


def has_blocking_critical(results: List[CategoryResult]) -> bool:
    return any(r.level == LEVEL_CRITICAL and r.blocking for r in results)


def has_any_critical(results: List[CategoryResult]) -> bool:
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

    if has_blocking_critical(results):
        sys.exit(2)
    elif has_any_critical(results):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
