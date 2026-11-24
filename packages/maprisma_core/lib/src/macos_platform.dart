import 'dart:convert';
import 'dart:ffi' show Abi;
import 'dart:io';

import 'package:path/path.dart' as p;

/// macOS (Darwin / Apple Silicon) platform parsers, path helpers, LaunchAgent
/// builders, and terminal command builders. Pure parsing/building functions are
/// exposed so unit tests run identically on Linux and macOS.

/// Standard CLI locations on macOS that GUI `.app` bundles launched from
/// Finder/Spotlight/Dock do not inherit in their default `/usr/bin:/bin:...`.
List<String> macosExtraPathDirs(String home) => [
  '/opt/homebrew/bin',
  '/opt/homebrew/sbin',
  '/usr/local/bin',
  if (home.isNotEmpty && home != '/') ...[
    p.join(home, '.local/bin'),
    p.join(home, '.cargo/bin'),
    p.join(home, '.local/share/mise/shims'),
    p.join(home, '.bun/bin'),
    p.join(home, '.npm-global/bin'),
  ],
];

/// Appends standard macOS Homebrew & user tool directories to [currentPath]
/// without duplicating entries already present.
String augmentMacosPath(String? currentPath, String home) {
  final parts = <String>[
    for (final s in (currentPath ?? '').split(':'))
      if (s.isNotEmpty) s,
  ];
  final seen = parts.toSet();
  for (final extra in macosExtraPathDirs(home)) {
    if (seen.add(extra)) parts.add(extra);
  }
  return parts.join(':');
}

/// Claude Desktop's MCP config file location (`~/Library/Application Support`
/// on macOS vs `~/.config` on Linux).
String claudeDesktopConfigPath(String home, {bool? isMacOS}) =>
    (isMacOS ?? Platform.isMacOS)
    ? p.join(
        home,
        'Library',
        'Application Support',
        'Claude',
        'claude_desktop_config.json',
      )
    : p.join(home, '.config', 'Claude', 'claude_desktop_config.json');

/// Jan Desktop's data root (`~/Library/Application Support/Jan` on macOS when
/// `~/.local/share/Jan` does not exist).
String janRootPath(String home, {bool? isMacOS}) {
  if (!(isMacOS ?? Platform.isMacOS)) return p.join(home, '.local/share/Jan');
  final macPath = p.join(home, 'Library', 'Application Support', 'Jan');
  final linuxPath = p.join(home, '.local/share/Jan');
  if (Directory(macPath).existsSync() || !Directory(linuxPath).existsSync()) {
    return macPath;
  }
  return linuxPath;
}

const _months = {
  'jan': 1,
  'feb': 2,
  'mar': 3,
  'apr': 4,
  'may': 5,
  'jun': 6,
  'jul': 7,
  'aug': 8,
  'sep': 9,
  'oct': 10,
  'nov': 11,
  'dec': 12,
};

/// Parses BSD/macOS `ps -o lstart=` 5-token timestamp
/// (e.g. `Tue Nov 17 16:55:03 2026`) into seconds since epoch (0.0 on error).
double parseMacosLstart(String text) {
  final parts = text
      .trim()
      .split(RegExp(r'\s+'))
      .where((s) => s.isNotEmpty)
      .toList();
  if (parts.length != 5) return 0.0;
  final month = _months[parts[1].toLowerCase()];
  final day = int.tryParse(parts[2]);
  final timeParts = parts[3].split(':');
  final year = int.tryParse(parts[4]);
  if (month == null || day == null || year == null || timeParts.length != 3) {
    return 0.0;
  }
  final hour = int.tryParse(timeParts[0]);
  final minute = int.tryParse(timeParts[1]);
  final second = int.tryParse(timeParts[2]);
  if (hour == null || minute == null || second == null) return 0.0;
  return DateTime(
        year,
        month,
        day,
        hour,
        minute,
        second,
      ).millisecondsSinceEpoch /
      1000.0;
}

final class MacosProcess {
  const MacosProcess({
    required this.pid,
    required this.ppid,
    required this.pgid,
    required this.sess,
    required this.uid,
    required this.lstart,
    required this.startedEpoch,
    required this.comm,
    required this.argv,
  });

  final int pid;
  final int ppid;
  final int pgid;
  final int sess;
  final int uid;
  final String lstart;
  final double startedEpoch;
  final String comm;
  final List<String> argv;
}

/// Splits a BSD `ps` `args=` command string into tokens, preserving `.app`
/// bundle executable paths that contain spaces (e.g.
/// `/Applications/LM Studio.app/Contents/MacOS/LM Studio --run-as-service`).
List<String> splitMacosCommandArgs(String argsText, {String? knownExe}) {
  final trimmed = argsText.trim();
  if (trimmed.isEmpty) return const [];
  if (knownExe != null &&
      knownExe.isNotEmpty &&
      (trimmed == knownExe || trimmed.startsWith('$knownExe '))) {
    final rest = trimmed.substring(knownExe.length).trim();
    return [knownExe, if (rest.isNotEmpty) ..._splitWords(rest)];
  }
  final appMatch = RegExp(
    r'^(/[^\n]*?\.app/Contents/MacOS/[^/\s]+(?:\s+[^-\s][^/\n]*?)?)(?=\s+-|\s*$)',
  ).firstMatch(trimmed);
  if (appMatch != null) {
    final exe = appMatch.group(1)!.trim();
    final rest = trimmed.substring(appMatch.end).trim();
    return [exe, if (rest.isNotEmpty) ..._splitWords(rest)];
  }
  return _splitWords(trimmed);
}

List<String> _splitWords(String text) =>
    text.split(RegExp(r'\s+')).where((s) => s.isNotEmpty).toList();

/// Extracts `(commBasename, argv)` from the `comm=,args=` tail of macOS `ps`.
/// On macOS `/bin/ps`, `comm=` prints the executable path (`argv[0]`), followed
/// by spaces and `args=` (`argv[0] argv[1] ...`).
(String, List<String>) _parseCommAndArgs(String tail) {
  final trimmed = tail.trim();
  if (trimmed.isEmpty) return ('', const []);

  // Check if tail begins with `<exe> <exe>` (including paths with spaces such
  // as `/Applications/LM Studio.app/Contents/MacOS/LM Studio`).
  for (var i = 1; i < trimmed.length; i++) {
    if (trimmed.codeUnitAt(i) != 0x20) continue;
    final candidate = trimmed.substring(0, i);
    var nextStart = i;
    while (nextStart < trimmed.length &&
        trimmed.codeUnitAt(nextStart) == 0x20) {
      nextStart++;
    }
    final rest = trimmed.substring(nextStart);
    if (rest == candidate || rest.startsWith('$candidate ')) {
      final comm = p.basename(candidate);
      return (comm, splitMacosCommandArgs(rest, knownExe: candidate));
    }
  }

  // Fallback when `comm` is kernel ucomm or differs from `argv[0]` (e.g. login
  // shell `-zsh` or custom process title).
  final space = trimmed.indexOf(' ');
  if (space < 0) {
    final base = p.basename(trimmed);
    return (base, [trimmed]);
  }
  final commToken = trimmed.substring(0, space);
  final argsPart = trimmed.substring(space + 1).trim();
  final argv = argsPart.isEmpty ? [commToken] : splitMacosCommandArgs(argsPart);
  return (p.basename(commToken), argv);
}

final _psShortLine = RegExp(
  r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*)$',
);
final _psFullLine = RegExp(
  r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-Fx]+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*)$',
);

/// Parses output from either:
/// - `ps -axo pid=,ppid=,uid=,lstart=,comm=,args=`
/// - `ps -axo pid=,ppid=,pgid=,sess=,uid=,lstart=,comm=,args=`
List<MacosProcess> parseMacosPs(String output, {int? onlyUid}) {
  final out = <MacosProcess>[];
  for (final line in const LineSplitter().convert(output)) {
    if (line.trim().isEmpty) continue;
    int pid, ppid, pgid, sess, uid;
    String lstart, tail;
    final full = _psFullLine.firstMatch(line);
    if (full != null) {
      pid = int.parse(full.group(1)!);
      ppid = int.parse(full.group(2)!);
      pgid = int.parse(full.group(3)!);
      final sessText = full.group(4)!;
      sess = sessText.startsWith('0x') || sessText.startsWith('0X')
          ? (int.tryParse(sessText.substring(2), radix: 16) ?? 0)
          : (int.tryParse(sessText) ?? 0);
      uid = int.parse(full.group(5)!);
      lstart = full.group(6)!.replaceAll(RegExp(r'\s+'), ' ').trim();
      tail = full.group(7)!;
    } else {
      final short = _psShortLine.firstMatch(line);
      if (short == null) continue;
      pid = int.parse(short.group(1)!);
      ppid = int.parse(short.group(2)!);
      pgid = 0;
      sess = 0;
      uid = int.parse(short.group(3)!);
      lstart = short.group(4)!.replaceAll(RegExp(r'\s+'), ' ').trim();
      tail = short.group(5)!;
    }
    if (onlyUid != null && uid != onlyUid) continue;
    final (comm, argv) = _parseCommAndArgs(tail);
    if (comm.isEmpty && argv.isEmpty) continue;
    out.add(
      MacosProcess(
        pid: pid,
        ppid: ppid,
        pgid: pgid,
        sess: sess,
        uid: uid,
        lstart: lstart,
        startedEpoch: parseMacosLstart(lstart),
        comm: comm,
        argv: argv,
      ),
    );
  }
  return out;
}

DateTime? _psCacheAt;
List<MacosProcess> _psCache = const [];

/// Forces C locale (`LC_ALL=C`, `LANG=C`) when running BSD/macOS inspection
/// tools (`ps`, `lsof`, `df`, `mount`, `sysctl`, `ioreg`) so weekday/month names
/// (e.g. `lstart=` on a German `de_DE.UTF-8` Mac) and numeric formatting never
/// change with the user's locale.
Map<String, String> macosCommandCEnv([Map<String, String>? base]) {
  final env = base ?? Platform.environment;
  return {...env, 'LC_ALL': 'C', 'LANG': 'C'};
}

/// Lists processes on macOS via `/bin/ps`, with a 200ms cache so callers that
/// inspect both process list and parent/group relationships do not spawn `ps`
/// repeatedly in a single scan.
List<MacosProcess> macosProcesses({bool fresh = false, int? onlyUid}) {
  final now = DateTime.now();
  if (fresh ||
      _psCacheAt == null ||
      now.difference(_psCacheAt!).inMilliseconds >= 200) {
    try {
      final res = Process.runSync(
        '/bin/ps',
        const ['-axo', 'pid=,ppid=,pgid=,sess=,uid=,lstart=,comm=,args='],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (res.exitCode == 0) {
        _psCache = parseMacosPs(res.stdout as String);
        _psCacheAt = now;
      }
    } on ProcessException {
      return const [];
    }
  }
  if (onlyUid == null) return _psCache;
  return [
    for (final proc in _psCache)
      if (proc.uid == onlyUid) proc,
  ];
}

final _psIdentityLine = RegExp(
  r'^\s*(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*$',
);

/// Parses lightweight macOS `ps -o pid=,pgid=,lstart=` lines into
/// `pid -> (pgid, roundedStartedEpoch)`. Omits `comm=,args=` so process-group
/// polling avoids per-process `KERN_PROCARGS2` lookups.
Map<int, (int, String)> parseMacosProcessIdentities(String output) {
  final out = <int, (int, String)>{};
  for (final line in const LineSplitter().convert(output)) {
    final m = _psIdentityLine.firstMatch(line);
    if (m == null) continue;
    final pid = int.parse(m.group(1)!);
    final pgid = int.parse(m.group(2)!);
    final lstart = m.group(3)!.replaceAll(RegExp(r'\s+'), ' ').trim();
    out[pid] = (pgid, '${parseMacosLstart(lstart).round()}');
  }
  return out;
}

/// Queries `(pgid, roundedStartedEpoch)` for a single [pid] on macOS using
/// `/bin/ps -p <pid> -o pid=,pgid=,lstart=`.
(int, String)? macosProcessIdentity(int pid) {
  if (pid <= 0) return null;
  try {
    final res = Process.runSync(
      '/bin/ps',
      ['-p', '$pid', '-o', 'pid=,pgid=,lstart='],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    if (res.exitCode != 0) return null;
    return parseMacosProcessIdentities(res.stdout as String)[pid];
  } on ProcessException {
    return null;
  }
}

/// Lists `pid -> roundedStartedEpoch` for all macOS processes in process group
/// [leader] (excluding [leader] itself), using `/bin/ps -axo pid=,pgid=,lstart=`.
Map<int, String> macosGroupMembers(int leader) {
  if (leader <= 0) return const {};
  try {
    final res = Process.runSync(
      '/bin/ps',
      const ['-axo', 'pid=,pgid=,lstart='],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    if (res.exitCode != 0) return const {};
    final all = parseMacosProcessIdentities(res.stdout as String);
    return {
      for (final e in all.entries)
        if (e.key != leader && e.value.$1 == leader) e.key: e.value.$2,
    };
  } on ProcessException {
    return const {};
  }
}

/// Parses BSD/macOS `/bin/ps -o time=` cumulative CPU time token
/// (`[dd-]hh:mm:ss[.ff]` or `mm:ss[.ff]`, e.g. `0:03.42`, `125:04.12`,
/// `1:02:03.45`, `2-03:04:05.67`) into seconds, or null if malformed.
double? parseMacosPsCpuSeconds(String timeText) {
  var s = timeText.trim();
  if (s.isEmpty) return null;
  var days = 0;
  final dash = s.indexOf('-');
  if (dash > 0) {
    final parsedDays = int.tryParse(s.substring(0, dash));
    if (parsedDays == null || parsedDays < 0) return null;
    days = parsedDays;
    s = s.substring(dash + 1);
  }
  final parts = s.split(':');
  if (parts.length != 2 && parts.length != 3) return null;
  int hours = 0;
  int minutes;
  double seconds;
  if (parts.length == 3) {
    final h = int.tryParse(parts[0]);
    final m = int.tryParse(parts[1]);
    final sec = double.tryParse(parts[2]);
    if (h == null || m == null || sec == null || h < 0 || m < 0 || sec < 0) {
      return null;
    }
    hours = h;
    minutes = m;
    seconds = sec;
  } else {
    if (days > 0) return null;
    final m = int.tryParse(parts[0]);
    final sec = double.tryParse(parts[1]);
    if (m == null || sec == null || m < 0 || sec < 0) return null;
    minutes = m;
    seconds = sec;
  }
  return ((days * 24 + hours) * 3600) + (minutes * 60) + seconds;
}

/// Parses `/bin/ps -o pid=,time= -p ...` output into `pid -> cumulative CPU seconds`.
Map<int, double> parseMacosPsCpuTimes(String output) {
  final out = <int, double>{};
  final lineRe = RegExp(r'^\s*(\d+)\s+(\S+)\s*$');
  for (final line in const LineSplitter().convert(output)) {
    final m = lineRe.firstMatch(line);
    if (m == null) continue;
    final pid = int.tryParse(m.group(1)!);
    final secs = parseMacosPsCpuSeconds(m.group(2)!);
    if (pid != null && secs != null) {
      out[pid] = secs;
    }
  }
  return out;
}

/// Reads cumulative CPU seconds for [pids] on macOS via `/bin/ps -o pid=,time=`.
Map<int, double> macosProcessCpuSeconds(Iterable<int> pids) {
  final valid = [
    for (final pid in pids)
      if (pid > 0) pid,
  ];
  if (valid.isEmpty) return const {};
  try {
    final res = Process.runSync(
      '/bin/ps',
      ['-o', 'pid=,time=', '-p', valid.join(',')],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    return parseMacosPsCpuTimes(res.stdout as String? ?? '');
  } on ProcessException {
    return const {};
  }
}

/// Reads environment keys in [allowed] for an own-UID process on macOS via
/// `/bin/ps eww -p <pid> -o command=`.
Map<String, String> macosProcessEnv(
  int pid,
  Set<String> allowed,
  int ownUid, {
  String? psOutput,
}) {
  if (allowed.isEmpty || pid <= 0) return const {};
  String text;
  if (psOutput != null) {
    text = psOutput;
  } else {
    final proc = macosProcesses().where((p) => p.pid == pid).firstOrNull;
    if (proc != null && proc.uid != ownUid) return const {};
    try {
      final res = Process.runSync(
        '/bin/ps',
        ['eww', '-p', '$pid', '-o', 'command='],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (res.exitCode != 0) return const {};
      text = res.stdout as String;
    } on ProcessException {
      return const {};
    }
  }
  final found = <String, String>{};
  for (final token in text.trim().split(RegExp(r'\s+'))) {
    final eq = token.indexOf('=');
    if (eq <= 0) continue;
    final key = token.substring(0, eq);
    if (allowed.contains(key)) {
      found[key] = token.substring(eq + 1);
    }
  }
  return found;
}

/// Working directory of an own-UID process on macOS via `/usr/sbin/lsof`.
String macosProcessCwd(int pid, int ownUid, {String? lsofOutput}) {
  if (pid <= 0) return '';
  String text;
  if (lsofOutput != null) {
    text = lsofOutput;
  } else {
    final proc = macosProcesses().where((p) => p.pid == pid).firstOrNull;
    if (proc == null || proc.uid != ownUid) return '';
    try {
      final res = Process.runSync(
        '/usr/sbin/lsof',
        ['-a', '-p', '$pid', '-d', 'cwd', '-Fn'],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (res.exitCode != 0) return '';
      text = res.stdout as String;
    } on ProcessException {
      return '';
    }
  }
  for (final line in const LineSplitter().convert(text)) {
    if (line.startsWith('n/')) return line.substring(1);
  }
  return '';
}

/// Regular file paths opened by [pid] on macOS via `/usr/sbin/lsof -Fn`.
List<String> macosProcessOpenFiles(int pid, int ownUid, {String? lsofOutput}) {
  if (pid <= 0) return const [];
  String text;
  if (lsofOutput != null) {
    text = lsofOutput;
  } else {
    final proc = macosProcesses().where((p) => p.pid == pid).firstOrNull;
    if (proc == null || proc.uid != ownUid) return const [];
    try {
      final res = Process.runSync(
        '/usr/sbin/lsof',
        ['-nP', '-p', '$pid', '-Fn'],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (res.exitCode != 0) return const [];
      text = res.stdout as String;
    } on ProcessException {
      return const [];
    }
  }
  return [
    for (final line in const LineSplitter().convert(text).take(1024))
      if (line.startsWith('n/')) line.substring(1),
  ];
}

enum _ListenKind { wildcard, ipv4Loopback, ipv6Loopback, other }

_ListenKind _classifyListenHost(String host) {
  final h = host.toLowerCase();
  if (h == '*' || h == '0.0.0.0' || h == '[::]' || h == '::') {
    return _ListenKind.wildcard;
  }
  if (h.startsWith('127.') ||
      h.startsWith('[::ffff:127.') ||
      h.startsWith('::ffff:127.')) {
    return _ListenKind.ipv4Loopback;
  }
  if (h == '[::1]' || h == '::1') {
    return _ListenKind.ipv6Loopback;
  }
  return _ListenKind.other;
}

List<({int uid, _ListenKind kind})> _parseLsofLoopbackEndpoints(
  String output,
  int port,
) {
  if (port <= 0 || port >= 65536) return const [];
  final endpoints = <({int uid, _ListenKind kind})>[];
  int? currentUid;
  for (final line in const LineSplitter().convert(output)) {
    if (line.isEmpty) continue;
    final tag = line[0];
    final value = line.substring(1);
    if (tag == 'p') {
      currentUid = null;
    } else if (tag == 'u') {
      currentUid = int.tryParse(value);
    } else if (tag == 'n' && currentUid != null) {
      // Listening endpoints have no `->`, e.g. `127.0.0.1:11434`, `*:8080`, `[::1]:8080`.
      if (value.contains('->')) continue;
      final colon = value.lastIndexOf(':');
      if (colon <= 0) continue;
      final parsedPort = int.tryParse(value.substring(colon + 1));
      if (parsedPort != port) continue;
      final kind = _classifyListenHost(value.substring(0, colon));
      if (kind != _ListenKind.other) {
        endpoints.add((uid: currentUid, kind: kind));
      }
    }
  }
  return endpoints;
}

/// Parses `/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -F pun` output and returns the
/// owner UIDs of all loopback-reachable TCP sockets listening on [port].
List<int> parseMacosLsofListeners(String output, int port) => [
  for (final ep in _parseLsofLoopbackEndpoints(output, port)) ep.uid,
];

String _runLsofListenersRaw() {
  try {
    final res = Process.runSync(
      '/usr/sbin/lsof',
      const ['-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'pun'],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    // Note: lsof exits with 1 when no files match, so parse stdout regardless.
    return res.stdout as String? ?? '';
  } on ProcessException {
    return '';
  }
}

/// Returns owner UIDs of loopback-reachable TCP listeners on [port] on macOS.
List<int> macosLoopbackListeners(int port) =>
    parseMacosLsofListeners(_runLsofListenersRaw(), port);

/// Security check: true iff:
/// 1. Every loopback-reachable or wildcard listener on [port] belongs to [uid]
///    (zero foreign UIDs on IPv4 or IPv6 loopback/wildcard), AND
/// 2. [uid]'s listeners actually cover the target loopback address family:
///    - default (`localhost: false`, connecting to `127.0.0.1`): [uid] owns a
///      wildcard (`*`/`0.0.0.0`/`::`) or IPv4 loopback (`127.*`) listener
///      (so an IPv6-only `[::1]` listener cannot leave `127.0.0.1` uncovered);
///    - `localhost: true` (connecting to `localhost`, which may resolve to
///      either `::1` or `127.0.0.1`): [uid] owns either wildcard (`*`) or BOTH
///      `127.*` and `[::1]`.
bool macosOwnPort(
  int port,
  int uid, {
  String? lsofOutput,
  bool localhost = false,
}) {
  if (port <= 0 || port >= 65536) return false;
  final raw = lsofOutput ?? _runLsofListenersRaw();
  final endpoints = _parseLsofLoopbackEndpoints(raw, port);
  if (endpoints.isEmpty || endpoints.any((ep) => ep.uid != uid)) {
    return false;
  }
  final hasWildcard = endpoints.any((ep) => ep.kind == _ListenKind.wildcard);
  final hasV4 = endpoints.any((ep) => ep.kind == _ListenKind.ipv4Loopback);
  final hasV6 = endpoints.any((ep) => ep.kind == _ListenKind.ipv6Loopback);
  if (localhost) {
    return hasWildcard || (hasV4 && hasV6);
  }
  return hasWildcard || hasV4;
}

/// Parses `lsof -nP -iTCP:<port> -sTCP:ESTABLISHED -F pn` to check if an
/// active connection to local [port] exists from a client PID not in [ignore].
bool parseMacosLsofEstablished(String output, int port, Set<int> ignorePids) {
  if (port <= 0 || port >= 65536) return false;
  int? currentPid;
  final pidEndpoints = <int, List<(String, String)>>{};
  for (final line in const LineSplitter().convert(output)) {
    if (line.isEmpty) continue;
    final tag = line[0];
    final value = line.substring(1);
    if (tag == 'p') {
      currentPid = int.tryParse(value);
    } else if (tag == 'n' && currentPid != null) {
      final arrow = value.indexOf('->');
      if (arrow <= 0) continue;
      final local = value.substring(0, arrow);
      final remote = value.substring(arrow + 2);
      pidEndpoints.putIfAbsent(currentPid, () => []).add((local, remote));
    }
  }
  bool hasPort(String ep) {
    final colon = ep.lastIndexOf(':');
    return colon > 0 && int.tryParse(ep.substring(colon + 1)) == port;
  }

  for (final entry in pidEndpoints.entries) {
    if (ignorePids.contains(entry.key)) continue;
    for (final (_, remote) in entry.value) {
      if (hasPort(remote)) return true;
    }
  }
  return false;
}

bool macosPortInUse(int port, Set<int> ignorePids) {
  if (port <= 0 || port >= 65536) return false;
  try {
    final res = Process.runSync(
      '/usr/sbin/lsof',
      ['-nP', '-iTCP:$port', '-sTCP:ESTABLISHED', '-F', 'pn'],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    return parseMacosLsofEstablished(
      res.stdout as String? ?? '',
      port,
      ignorePids,
    );
  } on ProcessException {
    return false;
  }
}

/// Parses Apple Silicon / macOS CPU, Unified Memory, and IOAccelerator Metal
/// statistics from `sysctl` and `ioreg -a -r -c IOAccelerator -d 1`.
({
  String vendor,
  String name,
  int ram,
  int vram,
  int? gpuCores,
  double? busyPercent,
  int vramUsed,
})
parseMacosHardware({
  required String cpuBrand,
  required String memsizeText,
  String ioregOutput = '',
  bool? isArm64,
}) {
  final brand = cpuBrand.trim();
  final ram = int.tryParse(memsizeText.trim()) ?? 0;

  int? intAfterKey(String xml, String key) {
    final m = RegExp(
      '<key>${RegExp.escape(key)}</key>\\s*<integer>(\\d+)</integer>',
    ).firstMatch(xml);
    return m == null ? null : int.tryParse(m.group(1)!);
  }

  String? stringAfterKey(String xml, String key) {
    final m = RegExp(
      '<key>${RegExp.escape(key)}</key>\\s*<string>([^<]+)</string>',
    ).firstMatch(xml);
    return m?.group(1)?.trim();
  }

  final cores = intAfterKey(ioregOutput, 'gpu-core-count');
  final util =
      intAfterKey(ioregOutput, 'Device Utilization %') ??
      intAfterKey(ioregOutput, 'Renderer Utilization %');
  final inUse =
      intAfterKey(ioregOutput, 'In use system memory') ??
      intAfterKey(ioregOutput, 'Alloc system memory') ??
      0;
  final ioModel = stringAfterKey(ioregOutput, 'model') ?? '';

  final appleSilicon =
      brand.toLowerCase().contains('apple') ||
      ioModel.toLowerCase().contains('apple') ||
      (isArm64 ?? (Abi.current() == Abi.macosArm64));

  if (appleSilicon) {
    final baseName = brand.isNotEmpty
        ? brand
        : (ioModel.isNotEmpty ? ioModel : 'Apple Silicon');
    return (
      vendor: 'apple',
      name: baseName,
      ram: ram,
      vram: ram,
      gpuCores: cores,
      busyPercent: util?.toDouble(),
      vramUsed: inUse,
    );
  }

  if (ioModel.isNotEmpty) {
    final lower = ioModel.toLowerCase();
    final vendor = lower.contains('amd') || lower.contains('radeon')
        ? 'amd'
        : lower.contains('nvidia')
        ? 'nvidia'
        : 'intel';
    return (
      vendor: vendor,
      name: ioModel,
      ram: ram,
      vram: 0,
      gpuCores: cores,
      busyPercent: util?.toDouble(),
      vramUsed: inUse,
    );
  }

  return (
    vendor: 'cpu',
    name: brand,
    ram: ram,
    vram: 0,
    gpuCores: null,
    busyPercent: null,
    vramUsed: 0,
  );
}

({
  String vendor,
  String name,
  int ram,
  int vram,
  int? gpuCores,
  double? busyPercent,
  int vramUsed,
})?
_hwCache;
DateTime? _hwCacheAt;

({
  String vendor,
  String name,
  int ram,
  int vram,
  int? gpuCores,
  double? busyPercent,
  int vramUsed,
})
macosHardwareInfo({bool includeIoreg = false}) {
  final now = DateTime.now();
  if (!includeIoreg &&
      _hwCache != null &&
      _hwCacheAt != null &&
      now.difference(_hwCacheAt!).inSeconds < 10) {
    return _hwCache!;
  }
  String runSysctl(String key) {
    try {
      final r = Process.runSync(
        '/usr/sbin/sysctl',
        ['-n', key],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      return r.exitCode == 0 ? (r.stdout as String).trim() : '';
    } on ProcessException {
      return '';
    }
  }

  var ioreg = '';
  if (includeIoreg) {
    try {
      final r = Process.runSync(
        '/usr/sbin/ioreg',
        const ['-a', '-r', '-c', 'IOAccelerator', '-d', '1'],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (r.exitCode == 0) ioreg = r.stdout as String;
    } on ProcessException {
      ioreg = '';
    }
  }
  final parsed = parseMacosHardware(
    cpuBrand: runSysctl('machdep.cpu.brand_string'),
    memsizeText: runSysctl('hw.memsize'),
    ioregOutput: ioreg,
  );
  if (!includeIoreg) {
    _hwCache = parsed;
    _hwCacheAt = now;
  }
  return parsed;
}

/// Parses `df -Pk` (and optional `/sbin/mount` output for filesystem types) on
/// macOS into Maprisma's local data mounts list (`path`, `filesystem`, `identity`).
List<Map<String, String>> parseMacosDfMounts(
  String dfOutput, {
  String mountOutput = '',
}) {
  final fsByPath = <String, String>{};
  // `/sbin/mount` lines look like: `/dev/disk4s1 on /Volumes/SSD (apfs, local, journaled)`
  final mountRe = RegExp(r'^(/dev/\S+)\s+on\s+(.+?)\s+\(([^,)\s]+)');
  for (final line in const LineSplitter().convert(mountOutput)) {
    final m = mountRe.firstMatch(line);
    if (m != null) {
      fsByPath[m.group(2)!.trim()] = m.group(3)!.trim();
    }
  }

  const excludedPrefixes = [
    '/System',
    '/private',
    '/dev',
    '/Library',
    '/Volumes/Recovery',
    '/Volumes/Preboot',
    '/Volumes/Update',
    '/Volumes/VM',
    '/Volumes/com.apple.TimeMachine',
  ];
  const allowedFs = {'apfs', 'hfs', 'exfat', 'msdos', 'ntfs', 'ufs', 'zfs'};

  final result = <String, Map<String, String>>{};
  final lineRe = RegExp(r'^(/dev/disk\S+)\s+\d+\s+\d+\s+\d+\s+\S+\s+(/.*)$');
  for (final line in const LineSplitter().convert(dfOutput).skip(1)) {
    final m = lineRe.firstMatch(line.trim());
    if (m == null) continue;
    final dev = m.group(1)!;
    final mountPath = m.group(2)!.trim();
    if (mountPath == '/' ||
        mountPath.startsWith('/Volumes/com.apple.') ||
        excludedPrefixes.any(
          (e) => mountPath == e || p.isWithin(e, mountPath),
        )) {
      continue;
    }
    final fs = (fsByPath[mountPath] ?? 'apfs').toLowerCase();
    if (!allowedFs.contains(fs)) continue;
    result[mountPath] = {'path': mountPath, 'filesystem': fs, 'identity': dev};
  }
  return result.values.toList();
}

List<Map<String, String>> macosLocalMounts() {
  try {
    final df = Process.runSync(
      '/bin/df',
      const ['-Pk'],
      environment: macosCommandCEnv(),
      stdoutEncoding: const Utf8Codec(allowMalformed: true),
    );
    if (df.exitCode != 0) return const [];
    var mountText = '';
    try {
      final m = Process.runSync(
        '/sbin/mount',
        const [],
        environment: macosCommandCEnv(),
        stdoutEncoding: const Utf8Codec(allowMalformed: true),
      );
      if (m.exitCode == 0) mountText = m.stdout as String;
    } on ProcessException {
      mountText = '';
    }
    return parseMacosDfMounts(df.stdout as String, mountOutput: mountText);
  } on ProcessException {
    return const [];
  }
}

String _xmlEscape(String text) => text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');

String _xmlUnescape(String text) => text
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');

/// Builds a `~/Library/LaunchAgents/<label>.plist` XML file for `launchd`.
String buildLaunchAgentPlist({
  required String label,
  required List<String> programArguments,
  Map<String, String> environment = const {},
  bool runAtLoad = true,
  bool keepAlive = true,
  String? workingDirectory,
  String? comment,
}) {
  final buf = StringBuffer()
    ..writeln('<?xml version="1.0" encoding="UTF-8"?>')
    ..writeln(
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    );
  if (comment != null && comment.isNotEmpty) {
    buf.writeln('<!-- ${comment.replaceAll('--', '-')} -->');
  }
  buf
    ..writeln('<plist version="1.0">')
    ..writeln('<dict>')
    ..writeln('  <key>Label</key>')
    ..writeln('  <string>${_xmlEscape(label)}</string>')
    ..writeln('  <key>ProgramArguments</key>')
    ..writeln('  <array>');
  for (final arg in programArguments) {
    buf.writeln('    <string>${_xmlEscape(arg)}</string>');
  }
  buf.writeln('  </array>');
  if (environment.isNotEmpty) {
    buf
      ..writeln('  <key>EnvironmentVariables</key>')
      ..writeln('  <dict>');
    for (final key in environment.keys.toList()..sort()) {
      buf
        ..writeln('    <key>${_xmlEscape(key)}</key>')
        ..writeln('    <string>${_xmlEscape(environment[key]!)}</string>');
    }
    buf.writeln('  </dict>');
  }
  if (workingDirectory != null && workingDirectory.isNotEmpty) {
    buf
      ..writeln('  <key>WorkingDirectory</key>')
      ..writeln('  <string>${_xmlEscape(workingDirectory)}</string>');
  }
  buf
    ..writeln('  <key>RunAtLoad</key>')
    ..writeln('  <${runAtLoad ? 'true' : 'false'}/>')
    ..writeln('  <key>KeepAlive</key>')
    ..writeln('  <${keepAlive ? 'true' : 'false'}/>')
    ..writeln('</dict>')
    ..writeln('</plist>');
  return buf.toString();
}

/// Parses `Label`, `ProgramArguments`, and `EnvironmentVariables` from a
/// macOS LaunchAgent XML plist.
({String label, List<String> programArguments, Map<String, String> environment})
parseLaunchAgentPlist(String xml) {
  final labelMatch = RegExp(
    r'<key>Label</key>\s*<string>([^<]*)</string>',
  ).firstMatch(xml);
  final label = labelMatch == null ? '' : _xmlUnescape(labelMatch.group(1)!);

  final args = <String>[];
  final argsBlock = RegExp(
    r'<key>ProgramArguments</key>\s*<array>([\s\S]*?)</array>',
  ).firstMatch(xml);
  if (argsBlock != null) {
    for (final m in RegExp(
      r'<string>([^<]*)</string>',
    ).allMatches(argsBlock.group(1)!)) {
      args.add(_xmlUnescape(m.group(1)!));
    }
  } else {
    final prog = RegExp(
      r'<key>Program</key>\s*<string>([^<]*)</string>',
    ).firstMatch(xml);
    if (prog != null) args.add(_xmlUnescape(prog.group(1)!));
  }

  final env = <String, String>{};
  final envBlock = RegExp(
    r'<key>EnvironmentVariables</key>\s*<dict>([\s\S]*?)</dict>',
  ).firstMatch(xml);
  if (envBlock != null) {
    for (final m in RegExp(
      r'<key>([^<]+)</key>\s*<string>([^<]*)</string>',
    ).allMatches(envBlock.group(1)!)) {
      env[_xmlUnescape(m.group(1)!)] = _xmlUnescape(m.group(2)!);
    }
  }
  return (label: label, programArguments: args, environment: env);
}

/// Parses `KEY=VALUE` lines from a systemd-style `.env` file text, stripping
/// optional `export ` prefixes and matching outer single/double quotes while
/// preserving spaces inside values (e.g. `/Volumes/External SSD/models`).
Map<String, String> parseEnvFileLines(String text) {
  final out = <String, String>{};
  for (final raw in const LineSplitter().convert(text)) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    final body = trimmed.startsWith('export ')
        ? trimmed.substring(7).trimLeft()
        : trimmed;
    final eq = body.indexOf('=');
    if (eq <= 0) continue;
    final key = body.substring(0, eq).trim();
    if (!RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(key)) continue;
    var val = body.substring(eq + 1).trim();
    if (val.length >= 2 &&
        ((val.startsWith('"') && val.endsWith('"')) ||
            (val.startsWith("'") && val.endsWith("'")))) {
      val = val.substring(1, val.length - 1);
    }
    out[key] = val;
  }
  return out;
}

/// POSIX `/bin/sh` wrapper script that reads `KEY=VALUE` lines from `"$1"`
/// (`server.env`) without `source` / `.` word-splitting or command evaluation,
/// so unquoted paths with spaces (e.g. `OLLAMA_MODELS=/Volumes/External SSD/models`)
/// are exported intact before `exec`ing `"$@"`.
const String macosEnvExecScript =
    'if [ -r "\$1" ]; then '
    'while IFS= read -r _line || [ -n "\$_line" ]; do '
    'case "\$_line" in ""|\\#*) continue ;; esac; '
    '_line="\${_line#export }"; '
    'case "\$_line" in [A-Za-z_]*=*) '
    '_k="\${_line%%=*}"; _v="\${_line#*=}"; '
    'case "\$_k" in *[!A-Za-z0-9_]*) continue ;; esac; '
    'case "\$_v" in \\"*\\") _v="\${_v#\\"}"; _v="\${_v%\\"}" ;; '
    "\\'*\\') _v=\"\${_v#\\'}\"; _v=\"\${_v%\\'}\" ;; esac; "
    'export "\$_k=\$_v" ;; esac; '
    'done < "\$1"; '
    'fi; shift; exec "\$@"';

/// Builds `ProgramArguments` that safely load [envFile] line-by-line and `exec`
/// [commandArgs] without a lingering shell process or word-splitting on spaces.
List<String> buildMacosEnvFileExecArgs(
  String envFile,
  List<String> commandArgs,
) => ['/bin/sh', '-c', macosEnvExecScript, 'sh', envFile, ...commandArgs];

/// Locates the LaunchAgent `.plist` file in `~/Library/LaunchAgents` for [label]
/// (checking `<label>.plist`, `com.maprisma.<label>.plist`, and scanning plist
/// `<key>Label</key>` values when filenames differ).
String? resolveLaunchAgentPlist(String home, String label) {
  if (home.isEmpty || label.isEmpty) return null;
  final dir = p.join(home, 'Library', 'LaunchAgents');
  for (final candidate in [
    p.join(dir, '$label.plist'),
    if (!label.startsWith('com.maprisma.'))
      p.join(dir, 'com.maprisma.$label.plist'),
  ]) {
    if (File(candidate).existsSync()) return candidate;
  }
  try {
    final entries =
        Directory(dir)
            .listSync(followLinks: false)
            .whereType<File>()
            .where((f) => f.path.endsWith('.plist'))
            .toList()
          ..sort((a, b) => a.path.compareTo(b.path));
    for (final file in entries.take(200)) {
      if (file.lengthSync() > 256 * 1024) continue;
      final parsed = parseLaunchAgentPlist(file.readAsStringSync());
      if (parsed.label == label) return file.path;
    }
  } on FileSystemException {
    // LaunchAgents directory may not exist yet.
  }
  return null;
}

/// Starts or stops a LaunchAgent [service] in `gui/<uid>` properly handling
/// `KeepAlive=true` jobs:
/// - `stop`: runs `launchctl bootout gui/<uid>/<service>` (falling back to
///   `launchctl bootout gui/<uid> <plistPath>`) so `launchd` unloads the job
///   instead of immediately respawning it as `launchctl stop` would;
/// - `start`: checks `launchctl print gui/<uid>/<service>` first, runs
///   `launchctl bootstrap gui/<uid> <plistPath>` when unloaded, then runs
///   `launchctl kickstart -k gui/<uid>/<service>`.
Future<(bool, String)> macosLaunchctlControl({
  required String service,
  required String action,
  required int uid,
  required String home,
  required Future<(bool, String)> Function(List<String> argv) run,
  String? plistOverride,
}) async {
  final domain = 'gui/$uid';
  final target = '$domain/$service';
  String? plistPath() =>
      plistOverride ?? resolveLaunchAgentPlist(home, service);

  if (action == 'stop') {
    final first = await run(['/bin/launchctl', 'bootout', target]);
    if (first.$1) return first;
    final plist = plistPath();
    if (plist != null && File(plist).existsSync()) {
      return run(['/bin/launchctl', 'bootout', domain, plist]);
    }
    return first;
  }

  if (action == 'start') {
    final (loaded, _) = await run(['/bin/launchctl', 'print', target]);
    if (!loaded) {
      final plist = plistPath();
      if (plist != null && File(plist).existsSync()) {
        await run(['/bin/launchctl', 'bootstrap', domain, plist]);
      }
    }
    return run(['/bin/launchctl', 'kickstart', '-k', target]);
  }

  return (false, 'unsupported launchctl action: $action');
}

/// Homebrew install commands for local runtimes and developer tools on macOS.
List<String>? macosBrewInstallCommand(String key) => switch (key) {
  'llamacpp' ||
  'llama.cpp' ||
  'llama-server' => const ['brew', 'install', 'llama.cpp'],
  'ollama' => const ['brew', 'install', '--cask', 'ollama'],
  'lmstudio' || 'lm-studio' => const ['brew', 'install', '--cask', 'lm-studio'],
  'jan' => const ['brew', 'install', '--cask', 'jan'],
  'node' || 'nodejs' || 'npx' => const ['brew', 'install', 'node'],
  'uv' || 'uvx' => const ['brew', 'install', 'uv'],
  'docker' => const ['brew', 'install', '--cask', 'docker'],
  'whisper' ||
  'whisper.cpp' ||
  'whisper-cpp' => const ['brew', 'install', 'whisper-cpp'],
  'mise' => const ['brew', 'install', 'mise'],
  _ => null,
};

/// Parses `defaults read -g AppleInterfaceStyle` exit code & stdout (`Dark` vs
/// light fallback when the key is absent).
String parseAppleInterfaceStyle(int exitCode, String stdout) =>
    exitCode == 0 && stdout.trim().toLowerCase() == 'dark' ? 'dark' : 'light';

/// POSIX shell quoting (matches `desktop.shellQuote`).
String _quote(String word) {
  if (word.isEmpty) return "''";
  if (RegExp(r'^[A-Za-z0-9_@%+=:,./-]+$').hasMatch(word)) return word;
  return "'${word.replaceAll("'", "'\"'\"'")}'";
}

/// Builds a safe `/usr/bin/osascript` argv for macOS `Terminal.app` (or
/// `iTerm.app`). The shell command is passed via `on run argv` (`item 1 of argv`)
/// rather than interpolated into AppleScript source code, preventing injection.
List<String> buildMacosOsascriptTerminalArgs(
  List<String> argv,
  String cwd, {
  String app = 'Terminal',
  String osascript = '/usr/bin/osascript',
}) {
  final cmd = 'cd -- ${_quote(cwd)} && ${argv.map(_quote).join(' ')}';
  if (app == 'iTerm') {
    return [
      osascript,
      '-e',
      'on run argv',
      '-e',
      'tell application "iTerm"',
      '-e',
      'activate',
      '-e',
      'create window with default profile',
      '-e',
      'tell current session of current window to write text (item 1 of argv)',
      '-e',
      'end tell',
      '-e',
      'end run',
      '--',
      cmd,
    ];
  }
  return [
    osascript,
    '-e',
    'on run argv',
    '-e',
    'tell application "Terminal"',
    '-e',
    'activate',
    '-e',
    'do script (item 1 of argv)',
    '-e',
    'end tell',
    '-e',
    'end run',
    '--',
    cmd,
  ];
}

/// Resolves the preferred macOS terminal launch command for [argv] in [cwd],
/// supporting Ghostty, iTerm, Kitty, WezTerm, Alacritty, and built-in
/// macOS `Terminal.app`.
List<String>? resolveMacosTerminalCommand(
  List<String> argv,
  String cwd, {
  required Map<String, String> environment,
  bool Function(String path)? dirExists,
  bool Function(String path)? fileExists,
  String? Function(String program)? which,
}) {
  if (argv.isEmpty) return null;
  final home = environment['HOME'] ?? '';
  final hasDir = dirExists ?? (String path) => Directory(path).existsSync();
  final hasFile = fileExists ?? (String path) => File(path).existsSync();
  final findBin =
      which ??
      (String prog) {
        for (final dir in (environment['PATH'] ?? '').split(':')) {
          if (dir.isEmpty) continue;
          final full = p.join(dir, prog);
          if (hasFile(full)) return full;
        }
        return null;
      };

  String? findApp(String bundleName) {
    for (final base in [
      '/Applications',
      if (home.isNotEmpty) p.join(home, 'Applications'),
    ]) {
      final candidate = p.join(base, bundleName);
      if (hasDir(candidate)) return candidate;
    }
    return null;
  }

  List<String>? tryTerminal(String kind) {
    switch (kind) {
      case 'ghostty':
        final app = findApp('Ghostty.app');
        if (app != null) {
          return [
            '/usr/bin/open',
            '-na',
            app,
            '--args',
            '--working-directory=$cwd',
            '-e',
            ...argv,
          ];
        }
        final bin = findBin('ghostty');
        if (bin != null) {
          return [bin, '--working-directory=$cwd', '-e', ...argv];
        }
      case 'iterm' || 'iterm2':
        if (findApp('iTerm.app') != null) {
          return buildMacosOsascriptTerminalArgs(argv, cwd, app: 'iTerm');
        }
      case 'kitty':
        final appBin = '/Applications/kitty.app/Contents/MacOS/kitty';
        final bin = hasFile(appBin) ? appBin : findBin('kitty');
        if (bin != null) return [bin, '--directory', cwd, ...argv];
      case 'wezterm':
        final appBin = '/Applications/WezTerm.app/Contents/MacOS/wezterm';
        final bin = hasFile(appBin) ? appBin : findBin('wezterm');
        if (bin != null) return [bin, 'start', '--cwd', cwd, '--', ...argv];
      case 'alacritty':
        final appBin = '/Applications/Alacritty.app/Contents/MacOS/alacritty';
        final bin = hasFile(appBin) ? appBin : findBin('alacritty');
        if (bin != null) {
          return [bin, '--working-directory', cwd, '-e', ...argv];
        }
      case 'terminal' || 'apple_terminal':
        if (hasFile('/usr/bin/osascript')) {
          return buildMacosOsascriptTerminalArgs(argv, cwd, app: 'Terminal');
        }
    }
    return null;
  }

  final preferred = (environment['TERMINAL'] ?? '').trim().toLowerCase();
  if (preferred.isNotEmpty) {
    final normalized = p.basename(preferred).replaceAll('.app', '');
    final chosen = tryTerminal(normalized);
    if (chosen != null) return chosen;
  }

  for (final candidate in const [
    'ghostty',
    'iterm',
    'kitty',
    'wezterm',
    'alacritty',
    'terminal',
  ]) {
    final found = tryTerminal(candidate);
    if (found != null) return found;
  }
  return null;
}
