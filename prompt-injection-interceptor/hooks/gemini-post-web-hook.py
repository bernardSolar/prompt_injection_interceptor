#!/usr/bin/env python3
"""
AfterTool hook for Gemini CLI - Prompt Injection Interception.

Intercepts google_web_search and web fetch results to scan for prompt injection
attempts before content reaches Gemini's context window.

Exit codes:
  0 - Allow the content (clean or below threshold)
  2 - Block the content (prompt injection detected)

Gemini CLI Hook Schema (AfterTool):
  Input (stdin):
    - session_id: string
    - hook_event_name: "AfterTool"
    - tool_name: string
    - tool_input: object
    - tool_output: object

  Output (stdout):
    - JSON with optional: decision, reason, systemMessage
"""

import json
import os
import sys
from datetime import datetime, timezone

# Add the prompt-injection-interceptor src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PII_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PII_DIR)

from src.injection_detector import InjectionDetector


# Initialize detector once
detector = InjectionDetector()

# Log file for security audit
AUDIT_LOG = os.path.join(PII_DIR, "security-audit.log")

# Gemini CLI web-related tool names
GEMINI_WEB_TOOLS = {
    "google_web_search",
    "web_fetch",
    "fetch_url",
    "browse_web",
}


def log_scan(
    tool_name: str,
    url: str,
    decision: str,
    score: int,
    detections: list[str],
    content_length: int,
    session_id: str = ""
) -> None:
    """Log scan result to security audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "web_content_scan",
        "cli": "gemini",
        "session_id": session_id,
        "tool": tool_name,
        "url": url,
        "decision": decision,
        "score": score,
        "detections": detections,
        "content_length": content_length,
    }

    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def extract_content(tool_name: str, tool_input: dict, tool_output) -> tuple[str, str]:
    """Extract content and URL from Gemini tool response."""
    url = "unknown"
    content = ""

    # Handle string output directly
    if isinstance(tool_output, str):
        if tool_name == "google_web_search":
            query = tool_input.get("query", "") if isinstance(tool_input, dict) else ""
            return tool_output, f"search:{query}"
        else:
            input_url = ""
            if isinstance(tool_input, dict):
                input_url = tool_input.get("url", tool_input.get("uri", ""))
            return tool_output, input_url or "unknown"

    # Handle dict output
    if not isinstance(tool_output, dict):
        return "", url

    if tool_name == "google_web_search":
        query = tool_input.get("query", "") if isinstance(tool_input, dict) else ""
        url = f"search:{query}"

        content = tool_output.get("response", "")
        if not content:
            content = tool_output.get("result", "")
        if not content:
            content = tool_output.get("summary", "")
        if not content:
            content = tool_output.get("text", "")

        return content, url

    elif tool_name in ("web_fetch", "fetch_url", "browse_web"):
        if isinstance(tool_input, dict):
            url = tool_input.get("url", tool_input.get("uri", "unknown"))

        content = tool_output.get("content", "")
        if not content:
            content = tool_output.get("body", "")
        if not content:
            content = tool_output.get("html", "")
        if not content:
            content = tool_output.get("text", "")

        return content, url

    # Generic extraction for other tools
    for field in ("content", "response", "result", "text", "body"):
        if field in tool_output:
            content = tool_output[field]
            if isinstance(content, str):
                return content, url

    return "", url


def output_block_response(url: str, score: int, detections: list[str]) -> None:
    """Output structured block response for Gemini CLI."""
    response = {
        "decision": "deny",
        "reason": f"Prompt injection detected (score: {score})",
        "systemMessage": (
            f"\n{'=' * 60}\n"
            f"CONTENT BLOCKED: Potential prompt injection detected\n"
            f"{'=' * 60}\n\n"
            f"Source: {url}\n"
            f"Risk Score: {score}\n\n"
            f"Detections:\n" +
            "\n".join(f"  - {d}" for d in detections) +
            f"\n\nThe content has been blocked for your safety.\n"
            f"The raw content has NOT been passed to Gemini.\n"
            f"{'=' * 60}"
        )
    }
    print(json.dumps(response))


def output_stderr_message(url: str, score: int, detections: list[str]) -> None:
    """Output block message to stderr for visibility."""
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("CONTENT BLOCKED: Potential prompt injection detected", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"Source: {url}", file=sys.stderr)
    print(f"Risk Score: {score}", file=sys.stderr)
    print("Detections:", file=sys.stderr)
    for detection in detections:
        print(f"  - {detection}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


def main():
    """Main hook entry point."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    session_id = data.get("session_id", "")
    hook_event = data.get("hook_event_name", "")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_output = data.get("tool_output", {})

    if hook_event != "AfterTool":
        sys.exit(0)

    if tool_name not in GEMINI_WEB_TOOLS:
        sys.exit(0)

    content, url = extract_content(tool_name, tool_input, tool_output)

    if not content:
        sys.exit(0)

    result = detector.scan(content)

    log_scan(
        tool_name=tool_name,
        url=url,
        decision="block" if not result.is_safe else "allow",
        score=result.score,
        detections=result.detections,
        content_length=len(content),
        session_id=session_id,
    )

    if not result.is_safe:
        output_block_response(url, result.score, result.detections)
        output_stderr_message(url, result.score, result.detections)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
