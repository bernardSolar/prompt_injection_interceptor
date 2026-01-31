#!/usr/bin/env python3
"""
PostToolUse hook for Claude Code - Prompt Injection Interception.

Intercepts WebFetch and WebSearch results to scan for prompt injection
attempts before content reaches Claude's context window.

Exit codes:
  0 - Allow the content (clean or below threshold)
  2 - Block the content (prompt injection detected)
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


def log_scan(
    tool_name: str,
    url: str,
    decision: str,
    score: int,
    detections: list[str],
    content_length: int
) -> None:
    """Log scan result to security audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "web_content_scan",
        "cli": "claude",
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
        # Don't fail the hook if logging fails
        pass


def extract_content(tool_name: str, tool_response: dict) -> tuple[str, str]:
    """Extract content and URL from tool response."""
    url = "unknown"

    if tool_name == "WebFetch":
        content = tool_response.get("content", "")
        url = tool_response.get("url", "unknown")
        return content, url

    elif tool_name == "WebSearch":
        results = tool_response.get("results", [])
        snippets = []
        for result in results:
            if "snippet" in result:
                snippets.append(result["snippet"])
            if "title" in result:
                snippets.append(result["title"])
        content = "\n".join(snippets)
        url = "search_results"
        return content, url

    return "", url


def output_block_message(url: str, score: int, detections: list[str]) -> None:
    """Output the block message to stderr."""
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("CONTENT BLOCKED: Potential prompt injection detected", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Source: {url}", file=sys.stderr)
    print(f"Risk Score: {score}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Detections:", file=sys.stderr)
    for detection in detections:
        print(f"  - {detection}", file=sys.stderr)
    print("", file=sys.stderr)
    print("The content has been blocked for your safety.", file=sys.stderr)
    print("The raw content has NOT been passed to Claude.", file=sys.stderr)
    print("", file=sys.stderr)
    print("If you believe this is a false positive, you can:", file=sys.stderr)
    print("  1. Review the source URL manually", file=sys.stderr)
    print("  2. Check the security-audit.log for details", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


def main():
    """Main hook entry point."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_response = data.get("tool_response", {})

    if tool_name not in ("WebFetch", "WebSearch"):
        sys.exit(0)

    content, url = extract_content(tool_name, tool_response)

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
    )

    if not result.is_safe:
        output_block_message(url, result.score, result.detections)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
