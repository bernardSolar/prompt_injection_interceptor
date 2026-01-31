#!/bin/bash
#
# Enterprise Setup Script for Prompt Injection Interceptor
#
# Installs PII at the SYSTEM level using Claude Code's managed settings.
# This ensures ALL projects on the machine are protected, and users
# cannot override or disable the protection.
#
# Usage:
#   sudo ./enterprise-setup.sh
#
# Supports: macOS, Linux
#
# After running:
#   - PII is installed system-wide
#   - All Claude Code sessions will have prompt injection protection
#   - Users cannot disable via project or user settings
#

set -e

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "=== Prompt Injection Interceptor - Enterprise Setup ==="
echo ""

# Detect OS and set paths
case "$(uname -s)" in
    Darwin)
        OS="macOS"
        MANAGED_DIR="/Library/Application Support/ClaudeCode"
        GEMINI_MANAGED_DIR="/Library/Application Support/GeminiCLI"
        PII_INSTALL_DIR="/Library/Application Support/PromptInjectionInterceptor"
        ;;
    Linux)
        OS="Linux"
        MANAGED_DIR="/etc/claude-code"
        GEMINI_MANAGED_DIR="/etc/gemini-cli"
        PII_INSTALL_DIR="/opt/prompt-injection-interceptor"
        ;;
    *)
        echo "Error: Unsupported operating system"
        exit 1
        ;;
esac

echo "Detected OS: $OS"
echo "Claude Code managed settings: $MANAGED_DIR"
echo "PII installation directory: $PII_INSTALL_DIR"
echo ""

# Get the source directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PII_SOURCE="$(dirname "$SCRIPT_DIR")/prompt-injection-interceptor"

# Verify source exists
if [ ! -d "$PII_SOURCE" ]; then
    echo "Error: PII source not found at $PII_SOURCE"
    exit 1
fi

# Step 1: Install PII to system location
echo "Installing PII to $PII_INSTALL_DIR..."
rm -rf "$PII_INSTALL_DIR"
mkdir -p "$PII_INSTALL_DIR"
cp -r "$PII_SOURCE"/* "$PII_INSTALL_DIR/"

# Make hooks executable
chmod +x "$PII_INSTALL_DIR/hooks/"*.py

# Step 2: Create Claude Code managed settings directory
echo "Configuring Claude Code managed settings..."
mkdir -p "$MANAGED_DIR"

cat > "$MANAGED_DIR/managed-settings.json" << EOF
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$PII_INSTALL_DIR/hooks/claude-post-web-hook.py\""
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$PII_INSTALL_DIR/hooks/prompt-guard-hook.py\""
          }
        ]
      }
    ]
  },
  "allowManagedHooksOnly": true
}
EOF

# Set permissions on Claude Code managed settings
chmod 644 "$MANAGED_DIR/managed-settings.json"
echo "  Created: $MANAGED_DIR/managed-settings.json"

# Step 3: Create Gemini CLI managed settings directory (if supported)
echo "Configuring Gemini CLI managed settings..."
mkdir -p "$GEMINI_MANAGED_DIR"

cat > "$GEMINI_MANAGED_DIR/managed-settings.json" << EOF
{
  "hooks": {
    "enabled": true,
    "AfterTool": [
      {
        "name": "prompt-injection-interceptor",
        "type": "command",
        "command": "python3 \"$PII_INSTALL_DIR/hooks/gemini-post-web-hook.py\"",
        "matcher": "google_web_search|web_fetch|fetch_url|browse_web"
      }
    ],
    "UserPromptSubmit": [
      {
        "name": "prompt-guard",
        "type": "command",
        "command": "python3 \"$PII_INSTALL_DIR/hooks/prompt-guard-hook.py\""
      }
    ]
  },
  "allowManagedHooksOnly": true
}
EOF

# Set permissions on Gemini CLI managed settings
chmod 644 "$GEMINI_MANAGED_DIR/managed-settings.json"
echo "  Created: $GEMINI_MANAGED_DIR/managed-settings.json"

# Step 4: Create system-wide audit log directory
AUDIT_LOG_DIR="/var/log/prompt-injection-interceptor"
echo "Creating audit log directory..."
mkdir -p "$AUDIT_LOG_DIR"
chmod 755 "$AUDIT_LOG_DIR"

# Update hooks to use system audit log
sed -i.bak "s|AUDIT_LOG = .*|AUDIT_LOG = \"$AUDIT_LOG_DIR/security-audit.log\"|" "$PII_INSTALL_DIR/hooks/claude-post-web-hook.py" 2>/dev/null || \
sed -i '' "s|AUDIT_LOG = .*|AUDIT_LOG = \"$AUDIT_LOG_DIR/security-audit.log\"|" "$PII_INSTALL_DIR/hooks/claude-post-web-hook.py"

sed -i.bak "s|AUDIT_LOG = .*|AUDIT_LOG = \"$AUDIT_LOG_DIR/security-audit.log\"|" "$PII_INSTALL_DIR/hooks/gemini-post-web-hook.py" 2>/dev/null || \
sed -i '' "s|AUDIT_LOG = .*|AUDIT_LOG = \"$AUDIT_LOG_DIR/security-audit.log\"|" "$PII_INSTALL_DIR/hooks/gemini-post-web-hook.py"

# Clean up backup files
rm -f "$PII_INSTALL_DIR/hooks/"*.bak

# Make audit log writable by all users
touch "$AUDIT_LOG_DIR/security-audit.log"
chmod 666 "$AUDIT_LOG_DIR/security-audit.log"

# Step 5: Verify installation
echo ""
echo "=== Enterprise Setup Complete ==="
echo ""
echo "Installation summary:"
echo ""
echo "  PII installed to:"
echo "    $PII_INSTALL_DIR"
echo ""
echo "  Claude Code managed settings:"
echo "    $MANAGED_DIR/managed-settings.json"
echo ""
echo "  Gemini CLI managed settings:"
echo "    $GEMINI_MANAGED_DIR/managed-settings.json"
echo ""
echo "  Audit logs:"
echo "    $AUDIT_LOG_DIR/security-audit.log"
echo ""
echo "Protection enabled:"
echo "  ✓ PostToolUse/AfterTool hook - scans web content for prompt injection"
echo "  ✓ UserPromptSubmit hook - prevents bypass suggestions"
echo "  ✓ allowManagedHooksOnly - users cannot override with their own hooks"
echo "  ✓ System-level installation - applies to ALL projects"
echo ""
echo "Users must restart Claude Code / Gemini CLI to activate protection."
echo ""
echo "To verify installation:"
echo "  cat \"$MANAGED_DIR/managed-settings.json\""
echo ""
echo "To view audit logs:"
echo "  tail -f \"$AUDIT_LOG_DIR/security-audit.log\""
echo ""
