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

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "error: build-mac.sh requires a native Apple Silicon shell and Flutter SDK (arm64)." >&2
  exit 1
fi

# Xcode and CocoaPods are required by Flutter; Python only runs build-time gates.
for tool in xcodebuild pod codesign lipo python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' not found in PATH." >&2
    exit 1
  fi
done
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "error: Python 3.10+ is required for the build-time bundle check." >&2
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
      if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "error: --addons requires a directory." >&2
        exit 1
      fi
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
  flutter build macos --release --dart-define=MAPRISMA_RELEASE=true
)

BUILT_APP="$ROOT/flutter_app/build/macos/Build/Products/Release/Maprisma.app"
if [[ ! -d "$BUILT_APP" ]]; then
  echo "error: expected app bundle not found at $BUILT_APP" >&2
  exit 1
fi

DIST_DIR="$ROOT/dist"
DIST_APP="$DIST_DIR/Maprisma.app"
mkdir -p "$DIST_DIR"
STAGE_DIR="$(mktemp -d "$DIST_DIR/.maprisma-build.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT
STAGED_APP="$STAGE_DIR/Maprisma.app"

# Use ditto so FlutterMacOS.framework internal symlinks stay intact.
/usr/bin/ditto "$BUILT_APP" "$STAGED_APP"

echo "==> Compiling bundled maprisma-core worker executable..."
(
  cd "$ROOT/packages/maprisma_core"
  "$DART_BIN" compile exe bin/maprisma-core.dart -o "$STAGED_APP/Contents/MacOS/maprisma-core"
)
chmod 755 "$STAGED_APP/Contents/MacOS/maprisma-core"
# The Flutter release may be universal, but the standalone Dart worker is native.
# Both executables must support the architecture advertised by this package.
lipo "$STAGED_APP/Contents/MacOS/Maprisma" -verify_arch arm64
lipo "$STAGED_APP/Contents/MacOS/maprisma-core" -verify_arch arm64

echo "==> Bundling user manuals and helper metadata..."
RES_DATA="$STAGED_APP/Contents/Resources/data"
mkdir -p "$RES_DATA"
for pdf in "$ROOT"/data/user-manual*.pdf; do
  [[ -f "$pdf" ]] && cp -p "$pdf" "$RES_DATA/"
done
if [[ -f "$ROOT/data/helpers.json" ]]; then
  cp -p "$ROOT/data/helpers.json" "$RES_DATA/helpers.json"
fi
: > "$RES_DATA/instance.lock"

if [[ -d "$ADDONS_REPO/dist" ]]; then
  VER="$(sed -n 's/^version: \([0-9][0-9.]*\).*/\1/p' "$ROOT/flutter_app/pubspec.yaml")"
  ADAPTERS_ZIP="$ADDONS_REPO/dist/adapters-${VER}.zip"
  if [[ -n "$VER" && -f "$ADAPTERS_ZIP" ]]; then
    echo "==> Unpacking signed add-ons from $ADAPTERS_ZIP..."
    python3 "$ROOT/packaging/unpack-adapters.py" "$ADAPTERS_ZIP" "$STAGED_APP/Contents/Resources/addons"
  fi
fi

# The same no-Python release gate as Linux; Python is a build tool only.
python3 "$ROOT/tools/check-bundle.py" "$STAGED_APP"

echo "==> Ad-hoc signing dist/Maprisma.app..."
# Xcode already signed the embedded frameworks. Sign the added worker, then
# reseal the outer app with its Release entitlements. --deep during signing
# would overwrite the frameworks' signatures and apply app entitlements to them.
codesign --force -s - "$STAGED_APP/Contents/MacOS/maprisma-core"
codesign --force --entitlements "$ROOT/flutter_app/macos/Runner/Release.entitlements" -s - "$STAGED_APP"
codesign --verify --deep --strict "$STAGED_APP"

# Preserve the previous artifact until compilation, bundling and signing pass.
rm -rf "$DIST_APP"
mv "$STAGED_APP" "$DIST_APP"

echo "==> Built: $DIST_APP"
