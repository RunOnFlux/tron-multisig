#!/usr/bin/env bash
# Starts the single-SR java-tron private chain used by the integration tests.
#   NODE_DIR  jar, chain db and logs (default: node/data, gitignored)
#   JAVA      JDK 17 java binary (arm64 java-tron needs 17)
#   TRON_HOST HTTP API probed for readiness (default http://127.0.0.1:8090)
# Idempotent: exits 0 if a node started from this NODE_DIR is already running.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE_DIR="${NODE_DIR:-$HERE/data}"
JAVA="${JAVA:-/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home/bin/java}"
TRON_HOST="${TRON_HOST:-http://127.0.0.1:8090}"
JAR_URL=https://github.com/tronprotocol/java-tron/releases/download/GreatVoyage-v4.8.2.2/FullNode-aarch64.jar
JAR_SHA256=82fc2ce15dd7197541d2f9e2ececf4005c0cb30dfb7e190d035d04c57141c201

mkdir -p "$NODE_DIR"
cd "$NODE_DIR"

if [ -f node.pid ] && kill -0 "$(cat node.pid)" 2>/dev/null; then
  echo "java-tron already running (pid $(cat node.pid))"
  exit 0
fi

if [ ! -f FullNode-aarch64.jar ]; then
  echo "downloading FullNode-aarch64.jar (GreatVoyage-v4.8.2.2)…"
  curl -sL -o FullNode-aarch64.jar.part "$JAR_URL"
  mv FullNode-aarch64.jar.part FullNode-aarch64.jar
fi
echo "$JAR_SHA256  FullNode-aarch64.jar" | shasum -a 256 -c -

cp "$HERE/private-net.conf" "$NODE_DIR/private-net.conf"
nohup "$JAVA" -Xms1g -Xmx4g -XX:+UseG1GC -jar FullNode-aarch64.jar -c private-net.conf --witness -d output-directory > node-stdout.log 2>&1 &
echo $! > node.pid
echo "java-tron pid $(cat node.pid)  (logs: $NODE_DIR/logs/tron.log)"

for _ in $(seq 1 90); do
  if curl -s -m 2 "$TRON_HOST/wallet/getnowblock" >/dev/null 2>&1; then
    echo "HTTP API up at $TRON_HOST"
    exit 0
  fi
  if ! kill -0 "$(cat node.pid)" 2>/dev/null; then
    echo "java-tron exited early; see $NODE_DIR/node-stdout.log and $NODE_DIR/logs/tron.log" >&2
    exit 1
  fi
  sleep 2
done
echo "node did not come up within 180 s" >&2
exit 1
