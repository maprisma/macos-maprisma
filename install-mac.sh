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

if [[ "$DEST_DIR" == "/Applications" && ! -w "/Applications" ]]; then
  sudo rm -rf "$DEST_APP"
  sudo /usr/bin/ditto "$SRC_APP" "$DEST_APP"
  sudo xattr -cr "$DEST_APP" 2>/dev/null || true
else
  mkdir -p "$DEST_DIR"
  rm -rf "$DEST_APP"
  /usr/bin/ditto "$SRC_APP" "$DEST_APP"
  xattr -cr "$DEST_APP" 2>/dev/null || true
fi

codesign --verify --deep --strict "$DEST_APP"
echo "==> Installed: $DEST_APP"
echo "Launch with: open \"$DEST_APP\""
