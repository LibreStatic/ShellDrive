#!/bin/sh
# Stops the fixture sshd started by start.sh. Keys stay for the next run; "stop.sh --purge" also
# deletes them (and ./state/).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-wsl-sshd"
if [ -f "$RUN/sshd.pid" ]; then
  PID="$(cat "$RUN/sshd.pid")"
  if kill -0 "$PID" 2>/dev/null; then kill "$PID"; echo "stopped fixture sshd (pid $PID)"; fi
  rm -f "$RUN/sshd.pid"
else
  echo "fixture sshd not running"
fi
rm -f "$HERE/state/env"
if [ "${1:-}" = "--purge" ]; then
  rm -rf "$RUN" "$HERE/state"
  echo "purged fixture state"
fi
