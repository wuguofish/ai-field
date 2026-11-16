#!/usr/bin/env python3
"""
A.I. Field — PreToolUse Hook for Bash and PowerShell
Intercepts shell commands that may install skills/plugins or execute dangerous operations.
"""

import sys
import json
import re


PS_DOWNLOAD = r"\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b"
PS_EXPRESSION = r"\b(?:iex|invoke-expression)\b"

# Commands that suggest skill/plugin installation
INSTALL_PATTERNS = [
    # git clone targeting skill/plugin repos
    (r"git\s+clone\s.*(?:skill|plugin|mcp)", "Git clone of skill/plugin repository"),
    # cp/copy to protected directories
    (r"(?:cp|copy)\s.*\.claude[/\\](?:skills|plugins|agents)", "Copy to Claude protected directory"),
    # curl/wget piped to shell
    (r"curl\s.*\|\s*(?:ba)?sh\b", "Remote script execution (curl | sh)"),
    (r"wget\s.*\|\s*(?:ba)?sh\b", "Remote script execution (wget | sh)"),
    # PowerShell: Copy-Item to protected directories
    (r"\b(?:copy-item|cpi)\s.*\.claude[/\\](?:skills|plugins|agents)", "Copy to Claude protected directory"),
    # PowerShell: downloaded text handed to Invoke-Expression, piped or nested
    (PS_DOWNLOAD + r".*\|\s*" + PS_EXPRESSION, "Remote script execution (download | iex)"),
    (PS_EXPRESSION + r".*(?:" + PS_DOWNLOAD + r"|\bdownloadstring\b)", "Remote script execution (iex of a download)"),
]

# The extension must end the name, so .json, .jsp and .shtml are not scripts
SCRIPT_EXTENSION = r"\.(?:sh|py|js|ps1|psm1)(?=[\"'?#]|\s|$)"

# Checked one shell segment at a time: a script run by a later command in the
# chain is not a download
DOWNLOAD_PATTERNS = [
    (r"\bcurl\b.*\s(?:-[a-z]*o|--output)[\s=]+[\"']?\S*" + SCRIPT_EXTENSION, "Downloading executable script"),
    (r"\bwget\b.*" + SCRIPT_EXTENSION, "Downloading executable script"),
    (PS_DOWNLOAD + r".*\s-outfile[\s:]+[\"']?\S*" + SCRIPT_EXTENSION, "Downloading executable script"),
]

# Quoted strings are consumed whole, so only separators outside quotes split
SHELL_SEPARATOR = re.compile(r"""("[^"]*"|'[^']*')|[;&|\n]+""")

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

# PowerShell's Remove-Item and its aliases, at the start of a pipeline segment
PS_DELETE = re.compile(r"^[\s({]*(?:remove-item|rm|del|rd|ri|rmdir|erase)\s", re.IGNORECASE)
PS_RECURSE = re.compile(r"\s-r(?:e(?:c(?:u(?:r(?:se?)?)?)?)?)?(?=[\s:]|$)", re.IGNORECASE)
PS_FORCE = re.compile(r"\s-fo(?:r(?:ce?)?)?(?=[\s:]|$)", re.IGNORECASE)
# The home directory or a drive root itself (optionally with a trailing
# wildcard), not a path below it
PS_ROOT_TARGET = re.compile(
    r"(?:^|[\s\"',=(])"
    r"(?:(?:~|\$home|\$env:userprofile)(?:[/\\]\*?)?|[a-z]:[/\\]\*?)"
    r"(?=[\s\"',;)]|$)",
    re.IGNORECASE,
)


def command_segments(command: str) -> list[str]:
    """Split a command line on ;, &, | and newlines that sit outside quotes."""
    segments, start = [], 0
    for match in SHELL_SEPARATOR.finditer(command):
        if match.group(1):
            continue
        segments.append(command[start:match.start()])
        start = match.end()
    segments.append(command[start:])
    return segments


def find_install_activity(command: str) -> str | None:
    """Return the description of the first install rule the command matches."""
    for pattern, desc in INSTALL_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return desc
    for segment in command_segments(command):
        for pattern, desc in DOWNLOAD_PATTERNS:
            if re.search(pattern, segment, re.IGNORECASE):
                return desc
    return None


def find_dangerous_command(command: str) -> str | None:
    """Return the description of the first dangerous rule the command matches."""
    for pattern, desc in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return desc
    for segment in command_segments(command):
        if (
            PS_DELETE.search(segment)
            and PS_RECURSE.search(segment)
            and PS_FORCE.search(segment)
            and PS_ROOT_TARGET.search(segment)
        ):
            return "Recursive force delete of home directory or drive root"
    return None


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
    # Claude Code exchanges UTF-8; the console code page on Windows is not
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")

    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    # Check dangerous commands first → DENY
    desc = find_dangerous_command(command)
    if desc:
        response = make_deny_response(
            f"\U0001f6e1\ufe0f A.I. Field \u2014 Dangerous command BLOCKED\n\n"
            f"Command: {command[:200]}\n"
            f"Reason: {desc}\n\n"
            f"This command could cause irreversible damage."
        )
        json.dump(response, sys.stdout, ensure_ascii=False)
        sys.exit(0)

    # Check installation-related commands → ASK
    desc = find_install_activity(command)
    if desc:
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
