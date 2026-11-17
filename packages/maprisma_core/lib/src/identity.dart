import 'dart:io';
import 'package:path/path.dart' as p;
import 'macos_platform.dart' show augmentMacosPath;

final class AppIdentity {
  AppIdentity({Map<String, String>? environment})
    : environment = Map.unmodifiable(_prepareEnvironment(environment));

  static Map<String, String> _prepareEnvironment(
    Map<String, String>? explicit,
  ) {
    final base = explicit ?? Platform.environment;
    // Augment PATH on macOS when inheriting the process environment (e.g. a
    // GUI Maprisma.app bundle launched from Finder/Spotlight/Dock) or when
    // explicitly requested via MAPRISMA_AUGMENT_PATH=1, while leaving isolated
    // unit-test environments untouched.
    if (Platform.isMacOS &&
        (explicit == null || explicit['MAPRISMA_AUGMENT_PATH'] == '1')) {
      final home = base['HOME'] ?? '/';
      return {...base, 'PATH': augmentMacosPath(base['PATH'], home)};
    }
    return base;
  }

  final Map<String, String> environment;
  String get home => environment['HOME'] ?? '/';

  /// Maprisma, called Asterism until 2026-10-30 (legacy_move.dart copies
  /// the old folders over once).
  String get name => 'Maprisma';
  String get appId => 'com.maprisma.Maprisma';
  String get shortName => 'maprisma';
  static const legacyShortName = 'asterism';
  String root(String key, String fallback) {
    final value = environment[key] ?? '';
    return value.isNotEmpty && p.isAbsolute(value)
        ? value
        : p.join(home, fallback);
  }

  String get configDir => p.join(root('XDG_CONFIG_HOME', '.config'), shortName);
  String get cacheDir => p.join(root('XDG_CACHE_HOME', '.cache'), shortName);
  String get settingsPath => p.join(configDir, 'settings.json');
  String get dataDir =>
      p.join(root('XDG_DATA_HOME', '.local/share'), shortName);
  String get stateDir =>
      p.join(root('XDG_STATE_HOME', '.local/state'), shortName);
}

/// The installed app's folder (its bundle): on Linux, the folder of the app's
/// program (or parent of `lib/maprisma-core`); on macOS `.app` bundles
/// (`Contents/MacOS/<exe>`), `Contents/Resources` when present so bundled
/// manuals (`data/`) and add-ons (`addons/`) live in standard macOS Resources.
String appFolder([String? executable]) {
  final exe = executable ?? Platform.resolvedExecutable;
  final dir = p.dirname(exe);
  if (p.basename(dir) == 'MacOS' && p.basename(p.dirname(dir)) == 'Contents') {
    final resources = p.join(p.dirname(dir), 'Resources');
    if (Directory(resources).existsSync()) return resources;
  }
  return p.basename(exe) == 'maprisma-core' && p.basename(dir) == 'lib'
      ? p.dirname(dir)
      : dir;
}
