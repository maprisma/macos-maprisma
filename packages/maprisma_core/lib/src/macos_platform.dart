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

/// Lists processes on macOS via `/bin/ps`, with a 200ms cache so callers that
/// inspect both process list and parent/group relationships do not spawn `ps`
/// repeatedly in a single scan.
List<MacosProcess> macosProcesses({bool fresh = false, int? onlyUid}) {
  final now = DateTime.now();
  if (fresh ||
      _psCacheAt == null ||
      now.difference(_psCacheAt!).inMilliseconds >= 200) {
    try {
      final res = Process.runSync('/bin/ps', const [
        '-axo',
        'pid=,ppid=,pgid=,sess=,uid=,lstart=,comm=,args=',
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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
      final res = Process.runSync('/bin/ps', [
        'eww',
        '-p',
        '$pid',
        '-o',
        'command=',
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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
      final res = Process.runSync('/usr/sbin/lsof', [
        '-a',
        '-p',
        '$pid',
        '-d',
        'cwd',
        '-Fn',
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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
      final res = Process.runSync('/usr/sbin/lsof', [
        '-nP',
        '-p',
        '$pid',
        '-Fn',
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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

bool _isLoopbackListenHost(String host) {
  final h = host.toLowerCase();
  return h == '*' ||
      h == '0.0.0.0' ||
      h.startsWith('127.') ||
      h == '[::]' ||
      h == '::' ||
      h == '[::1]' ||
      h == '::1' ||
      h.startsWith('[::ffff:127.') ||
      h.startsWith('::ffff:127.');
}

/// Parses `/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -F pun` output and returns the
/// owner UIDs of all loopback-reachable TCP sockets listening on [port].
List<int> parseMacosLsofListeners(String output, int port) {
  if (port <= 0 || port >= 65536) return const [];
  final owners = <int>[];
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
      final host = value.substring(0, colon);
      if (_isLoopbackListenHost(host)) {
        owners.add(currentUid);
      }
    }
  }
  return owners;
}

/// Returns owner UIDs of loopback-reachable TCP listeners on [port] on macOS.
List<int> macosLoopbackListeners(int port) {
  if (port <= 0 || port >= 65536) return const [];
  try {
    final res = Process.runSync('/usr/sbin/lsof', const [
      '-nP',
      '-iTCP',
      '-sTCP:LISTEN',
      '-F',
      'pun',
    ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
    // Note: lsof exits with 1 when no files match, so parse stdout regardless.
    return parseMacosLsofListeners(res.stdout as String? ?? '', port);
  } on ProcessException {
    return const [];
  }
}

/// Security check: true iff at least one socket listens on [port] and EVERY
/// loopback-reachable listener on [port] is owned by [uid].
bool macosOwnPort(int port, int uid, {String? lsofOutput}) {
  final owners = lsofOutput != null
      ? parseMacosLsofListeners(lsofOutput, port)
      : macosLoopbackListeners(port);
  return owners.isNotEmpty && owners.every((o) => o == uid);
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
    final res = Process.runSync('/usr/sbin/lsof', [
      '-nP',
      '-iTCP:$port',
      '-sTCP:ESTABLISHED',
      '-F',
      'pn',
    ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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
      final r = Process.runSync('/usr/sbin/sysctl', [
        '-n',
        key,
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
      return r.exitCode == 0 ? (r.stdout as String).trim() : '';
    } on ProcessException {
      return '';
    }
  }

  var ioreg = '';
  if (includeIoreg) {
    try {
      final r = Process.runSync('/usr/sbin/ioreg', const [
        '-a',
        '-r',
        '-c',
        'IOAccelerator',
        '-d',
        '1',
      ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
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
    final df = Process.runSync('/bin/df', const [
      '-Pk',
    ], stdoutEncoding: const Utf8Codec(allowMalformed: true));
    if (df.exitCode != 0) return const [];
    var mountText = '';
    try {
      final m = Process.runSync(
        '/sbin/mount',
        const [],
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
      'create window with default profile command (item 1 of argv)',
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
