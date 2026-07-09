#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$APP_DIR"
APP_NAME="ScanAPK"
PACKAGE="com.scanapk.app"
WATCH_MODE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

cleanup() {
    print_status "Cleaning up..."
    if [ -n "$WATCH_PID" ]; then
        kill "$WATCH_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

check_prerequisites() {
    print_status "Checking prerequisites..."

    if ! command -v java &>/dev/null; then
        print_error "Java is not installed. Install JDK 17+: sudo apt install openjdk-17-jdk"
        exit 1
    fi
    print_success "Java found: $(java -version 2>&1 | head -1)"

    if [ -z "$ANDROID_HOME" ]; then
        if [ -f "$PROJECT_DIR/local.properties" ]; then
            ANDROID_HOME=$(grep "sdk.dir" "$PROJECT_DIR/local.properties" | cut -d= -f2)
        fi
        if [ -z "$ANDROID_HOME" ]; then
            ANDROID_HOME="$HOME/Android/Sdk"
        fi
        if [ ! -d "$ANDROID_HOME" ]; then
            for candidate in "$HOME/android" "/usr/lib/android-sdk" "/opt/android-sdk"; do
                if [ -d "$candidate" ]; then
                    ANDROID_HOME="$candidate"
                    break
                fi
            done
        fi
        if [ ! -d "$ANDROID_HOME" ]; then
            print_error "Android SDK not found. Set ANDROID_HOME or install the SDK."
            exit 1
        fi
        export ANDROID_HOME
    fi
    print_success "Android SDK: $ANDROID_HOME"

    BUILD_TOOLS="$ANDROID_HOME/build-tools"
    if [ -d "$BUILD_TOOLS" ]; then
        LATEST_BUILD_TOOLS=$(ls -1 "$BUILD_TOOLS" 2>/dev/null | sort -V | tail -1)
        if [ -n "$LATEST_BUILD_TOOLS" ]; then
            export PATH="$BUILD_TOOLS/$LATEST_BUILD_TOOLS:$PATH"
        fi
    fi

    export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

    if ! command -v adb &>/dev/null; then
        print_error "adb not found. Install: sudo apt install adb"
        exit 1
    fi
    print_success "adb found"

    DEVICES=$(adb devices | grep -v "List of devices" | grep "device$" | wc -l)
    if [ "$DEVICES" -eq 0 ]; then
        print_error "No Android device connected via USB debugging."
        print_status "Connect your device and enable USB debugging."
        exit 1
    fi
    print_success "Device connected ($DEVICES device(s))"
}

setup_gradle_wrapper() {
    WRAPPER_JAR="$PROJECT_DIR/gradle/wrapper/gradle-wrapper.jar"
    HAS_MAIN=$(unzip -p "$WRAPPER_JAR" META-INF/MANIFEST.MF 2>/dev/null | grep -c "Main-Class:" || true)
    if [ ! -f "$WRAPPER_JAR" ] || [ "$HAS_MAIN" -eq 0 ]; then
        print_status "Setting up Gradle wrapper..."
        mkdir -p "$PROJECT_DIR/gradle/wrapper"

        GRADLE_VERSION="9.0"
        WRAPPER_URL="https://raw.githubusercontent.com/gradle/gradle/v${GRADLE_VERSION}.0/gradle/wrapper/gradle-wrapper.jar"

        print_status "Downloading gradle-wrapper.jar..."
        if command -v curl &>/dev/null; then
            curl -sL "$WRAPPER_URL" -o "$WRAPPER_JAR"
        elif command -v wget &>/dev/null; then
            wget -q "$WRAPPER_URL" -O "$WRAPPER_JAR"
        else
            print_error "Need curl or wget"
            exit 1
        fi

        HAS_MAIN=$(unzip -p "$WRAPPER_JAR" META-INF/MANIFEST.MF 2>/dev/null | grep -c "Main-Class:" || true)
        if [ "$HAS_MAIN" -eq 0 ]; then
            print_warning "Direct download failed, using Gradle distribution..."

            GRADLE_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}.0-bin.zip"
            TEMP_ZIP=$(mktemp /tmp/gradle-XXXXXX.zip)
            GRADLE_EXTRACT=$(mktemp -d /tmp/gradle-XXXXXX)

            if command -v curl &>/dev/null; then
                curl -sL "$GRADLE_URL" -o "$TEMP_ZIP"
            else
                wget -q "$GRADLE_URL" -O "$TEMP_ZIP"
            fi

            unzip -q "$TEMP_ZIP" -d "$GRADLE_EXTRACT"
            rm -f "$TEMP_ZIP"

            mkdir -p /tmp/wrapper-gen
            touch /tmp/wrapper-gen/settings.gradle

            GRADLE_HOME="$GRADLE_EXTRACT/gradle-${GRADLE_VERSION}.0"
            (cd /tmp/wrapper-gen && "$GRADLE_HOME/bin/gradle" wrapper --gradle-version "$GRADLE_VERSION.0" --no-daemon 2>&1 | tail -5)
            cp /tmp/wrapper-gen/gradle/wrapper/gradle-wrapper.jar "$WRAPPER_JAR"
            cp /tmp/wrapper-gen/gradle/wrapper/gradle-wrapper.properties "$PROJECT_DIR/gradle/wrapper/"
            cp /tmp/wrapper-gen/gradlew "$PROJECT_DIR/gradlew"
            chmod +x "$PROJECT_DIR/gradlew"

            rm -rf "$GRADLE_EXTRACT" /tmp/wrapper-gen
        fi

        HAS_MAIN=$(unzip -p "$WRAPPER_JAR" META-INF/MANIFEST.MF 2>/dev/null | grep -c "Main-Class:" || true)
        if [ "$HAS_MAIN" -eq 0 ]; then
            print_error "Gradle wrapper JAR is invalid"
            exit 1
        fi

        print_success "Gradle wrapper ready (version $GRADLE_VERSION)"
    fi
}

build_app() {
    print_status "Building $APP_NAME..."
    if ! (cd "$PROJECT_DIR" && ANDROID_HOME="$ANDROID_HOME" ./gradlew assembleDebug --no-daemon 2>&1); then
        print_error "Build failed"
        exit 1
    fi
    APK_PATH="$PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk"
    if [ ! -f "$APK_PATH" ]; then
        print_error "Build failed: APK not found"
        exit 1
    fi
    print_success "Build complete: $APK_PATH"
}

install_app() {
    print_status "Installing on device..."
    adb install -r "$PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk" 2>&1 | tail -5
    print_success "Install complete"
}

launch_app() {
    print_status "Launching $APP_NAME..."
    adb shell am start -n "$PACKAGE/.MainActivity" 2>&1 | tail -3
    print_success "App launched on device"
}

watch_changes() {
    print_status "Starting file watcher..."
    WATCH_DIRS="$PROJECT_DIR/app/src"

    if ! command -v inotifywait &>/dev/null; then
        print_warning "inotifywait not found. Install: sudo apt install inotify-tools"
        print_warning "Falling back to polling every 2 seconds..."

        local last_build=$(date +%s)
        while true; do
            local changed=$(find "$WATCH_DIRS" -name "*.kt" -o -name "*.xml" -o -name "*.kts" | while read f; do
                local mtime=$(stat -c %Y "$f" 2>/dev/null)
                if [ -n "$mtime" ] && [ "$mtime" -gt "$last_build" ]; then
                    echo "$f"
                fi
            done)
            if [ -n "$changed" ]; then
                echo ""
                print_warning "Change detected: $(echo "$changed" | head -1 | xargs basename)"
                build_and_deploy
                last_build=$(date +%s)
            fi
            sleep 2
        done
    else
        print_success "Watching for changes (inotify)..."
        while true; do
            inotifywait -r -e modify,create,delete "$WATCH_DIRS" --include '.*\.(kt|xml|kts)$' 2>/dev/null
            print_warning "Change detected, rebuilding..."
            build_and_deploy
        done
    fi
}

build_and_deploy() {
    build_app
    install_app
    launch_app
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --watch, -w    Watch for file changes and auto-rebuild"
    echo "  --help, -h     Show this help"
    echo ""
    echo "Examples:"
    echo "  $0              Build and deploy once"
    echo "  $0 --watch      Deploy and continuously monitor changes"
}

main() {
    cd "$PROJECT_DIR"

    for arg in "$@"; do
        case "$arg" in
            --watch|-w) WATCH_MODE=true ;;
            --help|-h) show_help; exit 0 ;;
        esac
    done

    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ${GREEN}ScanAPK - Build & Deploy${BLUE}      ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
    echo ""

    check_prerequisites
    setup_gradle_wrapper

    if [ "$WATCH_MODE" = true ]; then
        print_status "Building initial version..."
        build_app
        install_app
        launch_app
        watch_changes
    else
        build_app
        install_app
        launch_app
        print_success "Done! App is running on your device."
    fi
}

main "$@"
