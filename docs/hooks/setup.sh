#!/bin/bash
# wpp-mcp SessionStart hook for Claude Code.
#
# Place a copy in your project's .claude/hooks/setup.sh. On Claude Code
# session start, this ensures the wpp-mcp daemon is listening on
# 127.0.0.1:8765 (or $WPP_MCP_ADDR) and opens the pairing page in
# your default browser if no valid session exists yet.

set -e

BIN="${WPP_MCP_BIN:-{{PATH_TO_REPO}}/bin/wpp-mcp}"
STORE="${WPP_MCP_STORE:-{{PATH_TO_REPO}}/store}"
ADDR="${WPP_MCP_ADDR:-127.0.0.1:8765}"
LOG="${WPP_MCP_LOG:-/tmp/wpp-mcp.log}"
DB="$STORE/whatsapp.db"

# Already listening? No-op (idempotent; safe to run alongside launchd/systemd).
if lsof -iTCP:"${ADDR##*:}" -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "wpp-mcp: already listening on $ADDR"
    exit 0
fi

# Start the daemon, detached and fully headless.
nohup "$BIN" -store "$STORE" serve -addr "$ADDR" >>"$LOG" 2>&1 &
disown
echo "wpp-mcp: started (pid $!) → $LOG"

# Open pairing page if no session or session likely stale (~20 day rotation).
if [ ! -f "$DB" ] || [ -n "$(find "$DB" -mtime +18 2>/dev/null)" ]; then
    sleep 1
    if command -v open >/dev/null 2>&1; then
        open "http://$ADDR/pair" 2>/dev/null || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://$ADDR/pair" 2>/dev/null || true
    else
        echo "wpp-mcp: open http://$ADDR/pair in a browser to pair"
    fi
fi
