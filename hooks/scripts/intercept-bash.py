#!/usr/bin/env python3
"""
A.I. Field — PreToolUse Hook for Bash
Intercepts shell commands that may install skills/plugins or execute dangerous operations.
"""

import sys
import json
import re


# Commands that suggest skill/plugin installation
INSTALL_PATTERNS = [
    # git clone targeting skill/plugin repos
    (r"git\s+clone\s.*(?:skill|plugin|mcp)", "Git clone of skill/plugin repository"),
    # cp/copy to protected directories
    (r"(?:cp|copy)\s.*\.claude[/\\](?:skills|plugins|agents)", "Copy to Claude protected directory"),
    # curl/wget piped to shell
    (r"curl\s.*\|\s*(?:ba)?sh", "Remote script execution (curl | sh)"),
    (r"wget\s.*\|\s*(?:ba)?sh", "Remote script execution (wget | sh)"),
    # Downloading and executing scripts
    (r"curl\s.*-o\s.*\.(?:sh|py|js)", "Downloading executable script"),
    (r"wget\s.*\.(?:sh|py|js)", "Downloading executable script"),
]

# Dangerous commands that should always be flagged
DANGEROUS_PATTERNS = [
    (r"rm\s+-rf\s+[~/]", "Recursive force delete on home/root"),
    (r"rm\s+-rf\s+\*", "Recursive force delete wildcard"),
    (r":()\s*\{\s*:\|:\s*&\s*\}", "Fork bomb"),
    (r">\s*/dev/sd[a-z]", "Direct disk write"),
    (r"mkfs\.", "Filesystem format"),
    (r"dd\s+if=.*of=/dev/", "Direct device write with dd"),
    (r"chmod\s+-R\s+777\s+/", "Recursive world-writable permission on root"),
]


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
        sys.exit(0)

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    # Check dangerous commands first → DENY
    for pattern, desc in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            response = make_deny_response(
                f"\U0001f6e1\ufe0f A.I. Field \u2014 Dangerous command BLOCKED\n\n"
                f"Command: {command[:200]}\n"
                f"Reason: {desc}\n\n"
                f"This command could cause irreversible damage."
            )
            json.dump(response, sys.stdout, ensure_ascii=False)
            sys.exit(0)

    # Check installation-related commands → ASK
    for pattern, desc in INSTALL_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            response = make_ask_response(
                f"\U0001f6e1\ufe0f A.I. Field \u2014 Installation activity detected\n\n"
                f"Command: {command[:200]}\n"
                f"Detected: {desc}\n\n"
                f"After installation, run /ai-field-scan to audit the installed content."
            )
            json.dump(response, sys.stdout, ensure_ascii=False)
            sys.exit(0)

    # No match → allow
    sys.exit(0)


if __name__ == "__main__":
    main()
