#!/usr/bin/env bash
set -euo pipefail

# Build and install Maprisma.app into /Applications (when writable or --system)
# or ~/Applications (default when /Applications requires root or with --user).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: install-mac.sh must be run on macOS (Darwin)." >&2
  exit 1
fi

MODE="auto"
SKIP_BUILD=0
BUILD_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      MODE="user"
      shift
      ;;
    --system)
      MODE="system"
      shift
      ;;
    --no-build)
      SKIP_BUILD=1
      shift
      ;;
    --addons)
      if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "error: --addons requires a directory." >&2
        exit 1
      fi
      BUILD_ARGS+=("--addons" "$2")
      shift 2
      ;;
    *)
      echo "usage: $0 [--user | --system] [--no-build] [--addons <maprisma-addons-dir>]" >&2
      exit 1
      ;;
  esac
done

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  "$ROOT/build-mac.sh" "${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}"
fi

SRC_APP="$ROOT/dist/Maprisma.app"
if [[ ! -d "$SRC_APP" ]]; then
  echo "error: $SRC_APP does not exist; run ./build-mac.sh first." >&2
  exit 1
fi

# Reject incomplete or modified packages before touching an existing install.
test -x "$SRC_APP/Contents/MacOS/Maprisma"
test -x "$SRC_APP/Contents/MacOS/maprisma-core"
codesign --verify --deep --strict "$SRC_APP"

if [[ "$MODE" == "system" ]]; then
  DEST_DIR="/Applications"
elif [[ "$MODE" == "user" ]]; then
  DEST_DIR="$HOME/Applications"
else
  if [[ -w "/Applications" ]]; then
    DEST_DIR="/Applications"
  else
    DEST_DIR="$HOME/Applications"
  fi
fi

DEST_APP="$DEST_DIR/Maprisma.app"
echo "==> Installing Maprisma.app to $DEST_APP..."

USE_SUDO=0
if [[ "$DEST_DIR" == "/Applications" ]] &&
   { [[ ! -w "$DEST_DIR" ]] || [[ -e "$DEST_APP" && ! -w "$DEST_APP" ]]; }; then
  USE_SUDO=1
fi

install_command() {
  if [[ "$USE_SUDO" -eq 1 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

install_command mkdir -p "$DEST_DIR"
STAGE_DIR="$(install_command mktemp -d "$DEST_DIR/.maprisma-install.XXXXXX")"
cleanup() {
  # Restore the old install if activating the verified replacement failed.
  if install_command test -d "$STAGE_DIR/previous.app" && [[ ! -e "$DEST_APP" ]]; then
    install_command mv "$STAGE_DIR/previous.app" "$DEST_APP"
  fi
  install_command rm -rf "$STAGE_DIR"
}
trap cleanup EXIT
install_command /usr/bin/ditto "$SRC_APP" "$STAGE_DIR/Maprisma.app"
# Remove only quarantine; preserve other metadata and framework symlinks.
install_command xattr -dr com.apple.quarantine "$STAGE_DIR/Maprisma.app" 2>/dev/null || true
if [[ "$USE_SUDO" -eq 1 ]]; then
  install_command chown -R root:wheel "$STAGE_DIR/Maprisma.app"
fi
install_command codesign --verify --deep --strict "$STAGE_DIR/Maprisma.app"
if [[ -e "$DEST_APP" ]]; then
  install_command mv "$DEST_APP" "$STAGE_DIR/previous.app"
fi
install_command mv "$STAGE_DIR/Maprisma.app" "$DEST_APP"

codesign --verify --deep --strict "$DEST_APP"
echo "==> Installed: $DEST_APP"
echo "Launch with: open \"$DEST_APP\""
