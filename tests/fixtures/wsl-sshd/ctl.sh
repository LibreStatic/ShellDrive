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
# An optional second argument names an M2 fixture instance (tests/fixtures/matrix/README.md), e.g.
# "ctl.sh drop ossh10" or "ctl.sh freeze socks5"; without it (or with "modern") this M1 fixture is meant.
# For a proxy instance the "listener" is the proxy process itself (it has no session processes).
#
# Windows: wsl.exe -e sh <wsl path>/ctl.sh <command> [instance]   (or ctl.ps1 <command> [-Instance <name>])
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-wsl-sshd"
FIX="${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-fixtures"
INSTANCE="${2:-modern}"
case "$INSTANCE" in
  modern) PIDFILE="$RUN/sshd.pid" ;;
  http|http-auth|socks5|socks5-auth|squid|dante) PIDFILE="$FIX/proxy-$INSTANCE/pid" ;;
  *[!a-z0-9-]*) echo "bad instance name: $INSTANCE" >&2; exit 2 ;;
  *) PIDFILE="$FIX/$INSTANCE/sshd.pid" ;;
esac

start_instance() {
  if [ "$INSTANCE" = modern ]; then sh "$HERE/start.sh"
  else sh "$HERE/../matrix/fixture.sh" start "$INSTANCE"; fi
}

listener() {
  if [ -f "$PIDFILE" ]; then
    p="$(cat "$PIDFILE")"
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
    rm -f "$PIDFILE"
    echo "killed fixture $INSTANCE (listener ${l:-none}, sessions: $(echo $s))"
    ;;
  start)
    start_instance
    ;;
  restart)
    sh "$0" kill "$INSTANCE"
    start_instance
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
    echo "usage: ctl.sh kill|start|restart|drop|freeze|reap|thaw|status [instance]" >&2
    exit 2
    ;;
esac
