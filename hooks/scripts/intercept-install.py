#!/usr/bin/env python3
"""
A.I. Field — PreToolUse Hook for Write / Edit
Intercepts file writes targeting skill/plugin/agent directories.
If critical issues are found in blocking categories, the write is denied.
"""

import sys
import json
import os

# Add script directory to path so we can import scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import scan_content, has_blocking_critical, has_any_critical, format_report, LEVEL_CRITICAL

# Patterns that indicate a protected directory
PROTECTED_PATTERNS = [
    "/.claude/skills/",
    "/.claude/plugins/",
    "/.claude/agents/",
    "\\.claude\\skills\\",
    "\\.claude\\plugins\\",
    "\\.claude\\agents\\",
    "/.claude/commands/",
    "\\.claude\\commands\\",
]

# Files that always trigger scanning regardless of directory
PROTECTED_FILENAMES = {".mcp.json", "mcp.json"}


def is_protected_path(file_path: str) -> bool:
    """Check if the file path is in a protected Claude directory or is a sensitive file."""
    normalized = file_path.replace("\\", "/").lower()

    # Check directory patterns
    for pattern in PROTECTED_PATTERNS:
        if pattern.replace("\\", "/").lower() in normalized:
            return True

    # Check sensitive filenames (e.g., .mcp.json anywhere)
    basename = os.path.basename(file_path).lower()
    if basename in PROTECTED_FILENAMES:
        return True

    return False


def get_content_from_input(tool_input: dict, tool_name: str) -> str:
    """Extract content to scan from tool input."""
    if tool_name == "Write":
        return tool_input.get("content", "")
    elif tool_name == "Edit":
        # For Edit, scan the new_string being inserted
        return tool_input.get("new_string", "")
    return ""


def make_deny_response(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def make_ask_response(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)  # Can't parse input, allow

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")

    # Fast path: not a protected directory → allow immediately
    if not is_protected_path(file_path):
        sys.exit(0)

    # Protected path detected — run security scan
    content = get_content_from_input(tool_input, tool_name)
    if not content:
        sys.exit(0)

    target_name = os.path.basename(file_path)
    results = scan_content(content, source_file=file_path)

    if has_blocking_critical(results):
        # Critical issue in blocking category → DENY
        report = format_report(results, target_name)
        response = make_deny_response(
            f"\U0001f6e1\ufe0f A.I. Field \u2014 Installation BLOCKED\n\n"
            f"Attempted write to: {file_path}\n\n"
            f"{report}\n\n"
            f"Fix the critical issues above, or use /ai-field-scan for a detailed audit."
        )
        json.dump(response, sys.stdout, ensure_ascii=False)
        sys.exit(0)

    elif has_any_critical(results):
        # Critical but non-blocking → ASK user
        report = format_report(results, target_name)
        response = make_ask_response(
            f"\U0001f6e1\ufe0f A.I. Field \u2014 Security warnings detected\n\n"
            f"Attempted write to: {file_path}\n\n"
            f"{report}\n\n"
            f"Proceed with caution. Consider running /ai-field-scan for full audit."
        )
        json.dump(response, sys.stdout, ensure_ascii=False)
        sys.exit(0)

    else:
        # All clear or only yellow warnings → allow (stderr info only)
        yellow_count = sum(1 for r in results if r.level == "warning")
        if yellow_count > 0:
            print(
                f"\U0001f6e1\ufe0f A.I. Field: {yellow_count} minor warning(s) noted for {target_name}. "
                f"Use /ai-field-scan for details.",
                file=sys.stderr,
            )
        sys.exit(0)


if __name__ == "__main__":
    main()
