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
JAVA_TRON_VERSION=GreatVoyage-v4.8.2.3   # mandatory mainnet upgrade, 2026-09-30
JAR_URL=https://github.com/tronprotocol/java-tron/releases/download/$JAVA_TRON_VERSION/FullNode-aarch64.jar
JAR_SHA256=a3f0d01fb20d456dcaf1b361638f046ba8396fa2f4e8e494b3a07c5d6f7d4819   # = GitHub release asset digest
JAR="FullNode-aarch64-$JAVA_TRON_VERSION.jar"   # versioned name: an old jar can never be picked up

mkdir -p "$NODE_DIR"
cd "$NODE_DIR"

if [ -f node.pid ] && kill -0 "$(cat node.pid)" 2>/dev/null; then
  echo "java-tron already running (pid $(cat node.pid))"
  exit 0
fi

if [ ! -f "$JAR" ]; then
  echo "downloading FullNode-aarch64.jar ($JAVA_TRON_VERSION)…"
  curl -fsSL -o "$JAR.part" "$JAR_URL"
  echo "$JAR_SHA256  $JAR.part" | shasum -a 256 -c -
  mv "$JAR.part" "$JAR"
fi
echo "$JAR_SHA256  $JAR" | shasum -a 256 -c -

cp "$HERE/private-net.conf" "$NODE_DIR/private-net.conf"
nohup "$JAVA" -Xms1g -Xmx4g -XX:+UseG1GC -jar "$JAR" -c private-net.conf --witness -d output-directory > node-stdout.log 2>&1 &
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
