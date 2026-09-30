#!/usr/bin/env bash
# Stops the private-chain node started by start-node.sh. The chain database is kept.
#   --wipe   also delete the chain database and logs (the jar is kept), so the next start is a fresh chain
#            (scripts/align-chain.mjs must then run again; `yarn test` does it automatically).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE_DIR="${NODE_DIR:-$HERE/data}"
WIPE=0
[ "${1:-}" = "--wipe" ] && WIPE=1

stop_pid() {
  local pid="$1"
  kill "$pid" 2>/dev/null || return 0
  for _ in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
  done
  echo "pid $pid did not exit after SIGTERM; sending SIGKILL" >&2
  kill -9 "$pid" 2>/dev/null || true
}

if [ -f "$NODE_DIR/node.pid" ]; then
  PID="$(cat "$NODE_DIR/node.pid")"
  if kill -0 "$PID" 2>/dev/null; then
    echo "stopping java-tron pid $PID"
    stop_pid "$PID"
  else
    echo "no running node for $NODE_DIR (stale pid file)"
  fi
  rm -f "$NODE_DIR/node.pid"
else
  # Fallback: a node started from this NODE_DIR without a pid file.
  for PID in $(pgrep -f "FullNode-aarch64.jar -c private-net.conf" || true); do
    if [ "$(lsof -a -p "$PID" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')" = "$NODE_DIR" ]; then
      echo "stopping java-tron pid $PID (no pid file)"
      stop_pid "$PID"
    fi
  done
fi

if [ "$WIPE" = 1 ]; then
  echo "wiping chain data in $NODE_DIR"
  rm -rf "$NODE_DIR/output-directory" "$NODE_DIR/logs" "$NODE_DIR/node-stdout.log"
fi
