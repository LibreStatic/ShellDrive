#!/bin/sh
# Fault injection for the fixture sshd started by start.sh (M1 resilience tests; decisions.md D21:
# test infrastructure only). Only processes of the fixture instance are touched: the listener from
# $RUN/sshd.pid and the per-connection sshd processes below it.
#
#   ctl.sh kill      kill -9 every session process, then the listener ("sshd crashed"); keys stay
#   ctl.sh start     start the fixture again (start.sh)
#   ctl.sh restart   kill, then start
#   ctl.sh drop      kill -9 the session processes only: established TCP connections drop, the
#                    listener keeps accepting new ones
#   ctl.sh freeze    SIGSTOP the session processes: connections stay open but silent (a dead link
#                    only keepalives and the liveness probe can detect)
#   ctl.sh reap      kill -9 the stopped (frozen) session processes
#   ctl.sh thaw      SIGCONT the stopped session processes
#   ctl.sh status    print the listener and session pids
#
# Windows: wsl.exe -e sh <wsl path>/ctl.sh <command>   (or ctl.ps1 <command>)
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-wsl-sshd"

listener() {
  if [ -f "$RUN/sshd.pid" ]; then
    p="$(cat "$RUN/sshd.pid")"
    if kill -0 "$p" 2>/dev/null; then echo "$p"; fi
  fi
}

# Every process below the listener (privsep monitors and their session children).
sessions() {
  root="$(listener)"
  [ -n "$root" ] || return 0
  ps -eo pid=,ppid= | awk -v root="$root" '
    { parent[$1] = $2 }
    END {
      for (p in parent) {
        x = p; n = 0
        while ((x in parent) && x != root && x > 1 && n < 64) { x = parent[x]; n++ }
        if (x == root && p != root) print p
      }
    }'
}

stopped_sessions() {
  for p in $(sessions); do
    st="$(ps -o stat= -p "$p" 2>/dev/null || true)"
    case "$st" in T*) echo "$p" ;; esac
  done
}

signal_all() {
  sig="$1"; shift
  for p in "$@"; do kill "-$sig" "$p" 2>/dev/null || true; done
}

cmd="${1:-status}"
case "$cmd" in
  kill)
    l="$(listener)"
    s="$(sessions)"
    # stop the listener first so it cannot fork new sessions, then kill everything
    [ -n "$l" ] && kill -STOP "$l" 2>/dev/null || true
    signal_all KILL $s
    [ -n "$l" ] && kill -KILL "$l" 2>/dev/null || true
    rm -f "$RUN/sshd.pid"
    echo "killed fixture sshd (listener ${l:-none}, sessions: $(echo $s))"
    ;;
  start)
    sh "$HERE/start.sh"
    ;;
  restart)
    sh "$0" kill
    sh "$HERE/start.sh"
    ;;
  drop)
    s="$(sessions)"
    signal_all KILL $s
    echo "dropped sessions: $(echo $s)"
    ;;
  freeze)
    s="$(sessions)"
    signal_all STOP $s
    echo "froze sessions: $(echo $s)"
    ;;
  reap)
    s="$(stopped_sessions)"
    signal_all KILL $s
    echo "reaped frozen sessions: $(echo $s)"
    ;;
  thaw)
    s="$(stopped_sessions)"
    signal_all CONT $s
    echo "thawed sessions: $(echo $s)"
    ;;
  status)
    echo "listener: $(listener)"
    echo "sessions: $(echo $(sessions))"
    ;;
  *)
    echo "usage: ctl.sh kill|start|restart|drop|freeze|reap|thaw|status" >&2
    exit 2
    ;;
esac
