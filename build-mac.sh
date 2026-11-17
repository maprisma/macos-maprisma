#!/usr/bin/env bash
set -euo pipefail

# Build Maprisma.app for macOS (Apple Silicon arm64 / Ventura 13.0+).
# Produces dist/Maprisma.app with the pure-Dart maprisma-core worker binary,
# bundled manuals/helpers, optional signed add-ons, and an ad-hoc code signature.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: build-mac.sh must be run on macOS (Darwin)." >&2
  exit 1
fi

if ! command -v flutter >/dev/null 2>&1; then
  echo "error: 'flutter' not found in PATH." >&2
  exit 1
fi

DART_BIN="$(command -v dart || true)"
if [[ -z "$DART_BIN" ]]; then
  FLUTTER_BIN_DIR="$(cd "$(dirname "$(command -v flutter)")" && pwd)"
  if [[ -x "$FLUTTER_BIN_DIR/dart" ]]; then
    DART_BIN="$FLUTTER_BIN_DIR/dart"
  else
    echo "error: 'dart' not found in PATH." >&2
    exit 1
  fi
fi

ADDONS_REPO="${MAPRISMA_ADDONS_DIR:-$ROOT/../maprisma-addons}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --addons)
      ADDONS_REPO="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--addons <maprisma-addons-dir>]" >&2
      exit 1
      ;;
  esac
done

echo "==> Resolving packages in packages/maprisma_core..."
(
  cd "$ROOT/packages/maprisma_core"
  "$DART_BIN" pub get
)

echo "==> Building Release macOS app bundle..."
(
  cd "$ROOT/flutter_app"
  flutter pub get
  flutter build macos --release --no-codesign --dart-define=MAPRISMA_RELEASE=true
)

BUILT_APP="$ROOT/flutter_app/build/macos/Build/Products/Release/Maprisma.app"
if [[ ! -d "$BUILT_APP" ]]; then
  echo "error: expected app bundle not found at $BUILT_APP" >&2
  exit 1
fi

DIST_DIR="$ROOT/dist"
DIST_APP="$DIST_DIR/Maprisma.app"
rm -rf "$DIST_APP"
mkdir -p "$DIST_DIR"

# Use ditto so FlutterMacOS.framework internal symlinks stay intact.
/usr/bin/ditto "$BUILT_APP" "$DIST_APP"

echo "==> Compiling bundled maprisma-core worker executable..."
(
  cd "$ROOT/packages/maprisma_core"
  "$DART_BIN" compile exe bin/maprisma-core.dart -o "$DIST_APP/Contents/MacOS/maprisma-core"
)
chmod 755 "$DIST_APP/Contents/MacOS/maprisma-core"

echo "==> Bundling user manuals and helper metadata..."
RES_DATA="$DIST_APP/Contents/Resources/data"
mkdir -p "$RES_DATA"
for pdf in "$ROOT"/data/user-manual*.pdf; do
  [[ -f "$pdf" ]] && cp -p "$pdf" "$RES_DATA/"
done
if [[ -f "$ROOT/data/helpers.json" ]]; then
  cp -p "$ROOT/data/helpers.json" "$RES_DATA/helpers.json"
fi
: > "$RES_DATA/instance.lock"

if [[ -f "$ROOT/addons.py" && -d "$ADDONS_REPO/dist" ]]; then
  VER="$(sed -n 's/^MAPRISMA_VERSION = "\([0-9.]*\)"/\1/p' "$ROOT/addons.py" | head -n 1)"
  ADAPTERS_ZIP="$ADDONS_REPO/dist/adapters-${VER}.zip"
  if [[ -n "$VER" && -f "$ADAPTERS_ZIP" ]]; then
    echo "==> Unpacking signed add-ons from $ADAPTERS_ZIP..."
    python3 "$ROOT/packaging/unpack-adapters.py" "$ADAPTERS_ZIP" "$DIST_APP/Contents/Resources/addons"
  fi
fi

echo "==> Ad-hoc signing dist/Maprisma.app..."
codesign --force --deep -s - "$DIST_APP"
codesign --verify --deep --strict "$DIST_APP"

echo "==> Built: $DIST_APP"
