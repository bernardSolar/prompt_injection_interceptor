#!/bin/bash
#
# Admin Setup Script for Prompt Injection Interceptor
#
# This script installs PII with root-locked settings so that
# regular users cannot disable the security protection.
#
# Usage:
#   sudo ./admin-setup.sh /path/to/project
#
# After running:
#   - PII hooks are configured and locked
#   - Users cannot modify settings.json
#   - Claude Code / Gemini CLI will have prompt injection protection
#

set -e

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: sudo $0 /path/to/project"
    echo ""
    echo "This will install the Prompt Injection Interceptor with"
    echo "root-locked settings in the specified project directory."
    exit 1
fi

PROJECT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PII_SOURCE="$(dirname "$SCRIPT_DIR")/prompt-injection-interceptor"

echo "=== Prompt Injection Interceptor - Admin Setup ==="
echo ""
echo "Project directory: $PROJECT_DIR"
echo "PII source: $PII_SOURCE"
echo ""

# Verify source exists
if [ ! -d "$PII_SOURCE" ]; then
    echo "Error: PII source not found at $PII_SOURCE"
    exit 1
fi

# Create project directory if needed
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Creating project directory..."
    mkdir -p "$PROJECT_DIR"
fi

# Copy PII to project
echo "Installing PII..."
cp -r "$PII_SOURCE" "$PROJECT_DIR/"

# Create .claude directory
echo "Configuring Claude Code hooks..."
mkdir -p "$PROJECT_DIR/.claude"

cat > "$PROJECT_DIR/.claude/settings.json" << EOF
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"\$CLAUDE_PROJECT_DIR/prompt-injection-interceptor/hooks/claude-post-web-hook.py\""
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"\$CLAUDE_PROJECT_DIR/prompt-injection-interceptor/hooks/prompt-guard-hook.py\""
          }
        ]
      }
    ]
  }
}
EOF

# Create .gemini directory
echo "Configuring Gemini CLI hooks..."
mkdir -p "$PROJECT_DIR/.gemini"

cat > "$PROJECT_DIR/.gemini/settings.json" << EOF
{
  "hooks": {
    "enabled": true,
    "AfterTool": [
      {
        "name": "prompt-injection-interceptor",
        "type": "command",
        "command": "python3 \"\$GEMINI_PROJECT_DIR/prompt-injection-interceptor/hooks/gemini-post-web-hook.py\"",
        "matcher": "google_web_search|web_fetch|fetch_url|browse_web"
      }
    ],
    "UserPromptSubmit": [
      {
        "name": "prompt-guard",
        "type": "command",
        "command": "python3 \"\$GEMINI_PROJECT_DIR/prompt-injection-interceptor/hooks/prompt-guard-hook.py\""
      }
    ]
  }
}
EOF

# Lock down settings files
echo "Locking settings files (root ownership, read-only)..."
chown root:wheel "$PROJECT_DIR/.claude/settings.json" 2>/dev/null || \
chown root:root "$PROJECT_DIR/.claude/settings.json"
chmod 444 "$PROJECT_DIR/.claude/settings.json"

chown root:wheel "$PROJECT_DIR/.gemini/settings.json" 2>/dev/null || \
chown root:root "$PROJECT_DIR/.gemini/settings.json"
chmod 444 "$PROJECT_DIR/.gemini/settings.json"

# Verify setup
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Installed files:"
ls -la "$PROJECT_DIR/.claude/settings.json"
ls -la "$PROJECT_DIR/.gemini/settings.json"
echo ""
echo "Protection enabled:"
echo "  ✓ PostToolUse hook - scans web content for prompt injection"
echo "  ✓ UserPromptSubmit hook - prevents bypass suggestions"
echo "  ✓ Settings locked - only root can modify"
echo ""
echo "Users should restart Claude Code / Gemini CLI to activate."
echo ""
