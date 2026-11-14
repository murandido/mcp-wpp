#!/bin/bash
# wpp-mcp SessionStart hook for Claude Code (optional).
#
# Copy to .claude/hooks/setup.sh. When a Claude Code session starts it makes
# sure the daemon is running, and tells you how to pair if it is not paired
# yet. Not needed when the daemon runs under systemd, launchd or Docker.

set -e

BIN="${WPP_MCP_BIN:-wpp-mcp}"
STORE="${WPP_MCP_STORE:-$HOME/.local/share/wpp-mcp}"
LOG="${WPP_MCP_LOG:-${XDG_STATE_HOME:-$HOME/.local/state}/wpp-mcp.log}"
mkdir -p "$(dirname "$LOG")"

if "$BIN" healthcheck >/dev/null 2>&1; then
    exit 0
fi

if ! pgrep -f "wpp-mcp .*serve" >/dev/null 2>&1; then
    nohup "$BIN" -store "$STORE" serve >>"$LOG" 2>&1 &
    disown
    sleep 2
fi

if ! "$BIN" healthcheck >/dev/null 2>&1; then
    echo "wpp-mcp is running but not paired. Pair with: $BIN -store \"$STORE\" pair -phone +<number>"
fi
