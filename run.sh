#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print() { echo -e "${BLUE}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

API_PORT="${API_PORT:-8000}"
API_PID=""
ADB_REVERSE_SET=false

cleanup() {
    echo ""
    print "Shutting down..."
    if [ -n "$API_PID" ] && kill -0 "$API_PID" 2>/dev/null; then
        kill "$API_PID" 2>/dev/null || true
        ok "API server stopped"
    fi
    if [ "$ADB_REVERSE_SET" = true ]; then
        adb reverse --remove tcp:$API_PORT 2>/dev/null || true
        ok "adb reverse removed"
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

cd "$APP_DIR"
echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    ${GREEN}ScanAPK — Backend + Android${BLUE}      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── prerequisites ─────────────────────────────────────
print "Checking prerequisites..."

VENV_DIR="$APP_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    print "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet -e packages/scanapk-backend
    "$VENV_DIR/bin/pip" install --quiet -r packages/api-server/requirements.txt
    "$VENV_DIR/bin/pip" install --quiet -e packages/api-server
    ok "Virtual environment ready"
fi

if [ ! -f packages/api-server/.env ]; then
    cp packages/api-server/.env.example packages/api-server/.env
    print "Created packages/api-server/.env from .env.example — edit your API keys"
fi
ok "Environment ready"

if ! command -v java &>/dev/null; then
    err "Java not found. Install JDK 17+: sudo apt install openjdk-17-jdk"
    exit 1
fi
ok "Java: $(java -version 2>&1 | head -1)"

if ! command -v adb &>/dev/null; then
    err "adb not found. Install: sudo apt install adb"
    exit 1
fi
DEVICES=$(adb devices | grep -v "List of devices" | grep "device$" | wc -l)
if [ "$DEVICES" -eq 0 ]; then
    err "No Android device connected via USB debugging."
    exit 1
fi
ok "Android device connected ($DEVICES device(s))"

# ── adb reverse ─────────────────────────────────────────
print "Setting up adb reverse port tcp:$API_PORT..."
adb reverse tcp:$API_PORT tcp:$API_PORT
ADB_REVERSE_SET=true
ok "Phone localhost:$API_PORT → laptop localhost:$API_PORT"

# ── start API server ───────────────────────────────────
print "Starting API server on port $API_PORT..."
PYTHONPATH="${PYTHONPATH:-}:$(realpath packages/scanapk-backend)" \
    "$VENV_DIR/bin/uvicorn" api_server.main:app \
    --host 0.0.0.0 --port "$API_PORT" --reload --reload-dir packages/api_server --reload-dir packages/scanapk-backend \
    > /dev/null 2>&1 &
API_PID=$!

for i in $(seq 1 30); do
    if curl -s "http://localhost:$API_PORT/docs" >/dev/null 2>&1; then
        ok "API server ready at http://localhost:$API_PORT"
        break
    fi
    if [ "$i" -eq 30 ]; then
        err "API server failed to start"
        exit 1
    fi
    sleep 1
done

# ── build & deploy Android app ─────────────────────────
print "Building Android app..."
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_HOME

cd apps/android
./gradlew assembleDebug --no-daemon 2>&1 | tail -5
APK="app/build/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK" ]; then
    err "APK not found at $APK"
    exit 1
fi
ok "Build complete"

print "Installing on device..."
adb install -r "$APK" 2>&1 | tail -5
ok "Install complete"

print "Launching ScanAPK..."
adb shell am start -n "com.scanapk.app/.MainActivity" 2>&1 | tail -3
ok "ScanAPK is running on your device"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ${BLUE}Backend running — Ctrl+C to stop  ${GREEN} ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

wait "$API_PID"
