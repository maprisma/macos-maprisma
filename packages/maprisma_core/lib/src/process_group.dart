import 'dart:async';
import 'dart:io';

import 'desktop.dart' show whichIn;
import 'posix_ffi.dart';
import 'pty_sessions.dart' show groupMembers, processIdentity;

/// process_group: ending a finite job's program together with everything it
/// started (its process group), also when the program itself ends first.
///
/// The program was started as a session of its own (`setsid -- …`), so its
/// pid is the group's and session's id. Dart's process manager reaps it as
/// soon as it exits, so the group is never signalled by number (killpg):
/// every member is held by a pidfd opened after its identity — group,
/// session and start time — was checked, before the first signal. A member
/// found later is only taken when its start time is not older than the
/// leader's, so a process that reused a number is never signalled.
/// Starts [argv] in a session of its own (`setsid -- ...` on Linux; `setsid()`
/// + `execv` without a shell on macOS) so `ProcessGroup(process.pid)` can
/// track and terminate the leader and every descendant in its process group.
Future<Process> startInNewSession(
  List<String> argv, {
  String? workingDirectory,
  Map<String, String>? environment,
  bool includeParentEnvironment = true,
}) {
  if (Platform.isMacOS) {
    final searchPath =
        environment?['PATH'] ??
        (includeParentEnvironment ? Platform.environment['PATH'] : null);
    final prog = argv.first.contains('/')
        ? argv.first
        : (whichIn(argv.first, searchPath) ?? argv.first);
    final resolved = [prog, ...argv.skip(1)];
    if (File('/usr/bin/perl').existsSync()) {
      return Process.start(
        '/usr/bin/perl',
        [
          '-MPOSIX=setsid',
          '-e',
          r'setsid(); exec {$ARGV[0]} @ARGV; exit 127',
          '--',
          ...resolved,
        ],
        workingDirectory: workingDirectory,
        environment: environment,
        includeParentEnvironment: includeParentEnvironment,
      );
    }
    return Process.start(
      resolved.first,
      resolved.skip(1).toList(),
      workingDirectory: workingDirectory,
      environment: environment,
      includeParentEnvironment: includeParentEnvironment,
    );
  }
  return Process.start(
    'setsid',
    ['--', ...argv],
    workingDirectory: workingDirectory,
    environment: environment,
    includeParentEnvironment: includeParentEnvironment,
  );
}

final class ProcessGroup {
  ProcessGroup(this.leader, [Posix? posix]) : posix = posix ?? Posix() {
    // Right after Process.start the child may not have run setsid() yet: a
    // moment for it to lead its group, so its start time is known.
    final pause = Platform.isMacOS
        ? const Duration(milliseconds: 10)
        : const Duration(milliseconds: 2);
    final tries = Platform.isMacOS ? 50 : 25;
    for (var i = 0; i < tries; i++) {
      final own = processIdentity(leader);
      if (own == null || (own.$1 == leader && own.$2 == leader)) break;
      sleep(pause);
    }
    _take();
  }

  final int leader;
  final Posix posix;
  final _fds = <int, int>{}; // pid -> pidfd
  String? _leaderStart;
  Timer? _watch;

  /// Held processes still alive and still in the group: only while one
  /// exists is the group's id taken, so every process found in the group
  /// then is one of ours.
  bool get _anchored => _fds.entries.any(
    (e) => !posix.pidfdExited(e.value) && processIdentity(e.key)?.$1 == leader,
  );

  /// Look through the group every [every] while the program runs, so what it
  /// starts is held before it may end (Dart reaps it at once).
  void watch([Duration? every]) {
    final interval =
        every ??
        (Platform.isMacOS
            ? const Duration(milliseconds: 50)
            : const Duration(milliseconds: 100));
    _watch ??= Timer.periodic(interval, (_) => _take());
  }

  void _take() {
    // The leader before anything is held (just started), else only while a
    // held member anchors the group; checked again after the look-up.
    if (_fds.isNotEmpty && !_anchored) return;
    if (!_fds.containsKey(leader)) {
      final own = processIdentity(leader);
      if (own != null && own.$1 == leader && own.$2 == leader) {
        _leaderStart ??= own.$3;
        _hold(leader, own.$3);
      }
    }
    if (_fds.isEmpty) return; // the leader is gone or not ours: nothing anchors
    final before = Map.of(_fds);
    var added = false;
    for (final e in groupMembers(leader).entries) {
      if (_fds.containsKey(e.key)) continue;
      final start = _leaderStart;
      // A member is never older than the leader of its group.
      if (start != null &&
          (int.tryParse(e.value) ?? 0) < (int.tryParse(start) ?? 0)) {
        continue;
      }
      if (_hold(e.key, e.value)) added = true;
    }
    if (!added) return;
    final anchor = before.entries.any(
      (e) =>
          !posix.pidfdExited(e.value) && processIdentity(e.key)?.$1 == leader,
    );
    if (!anchor) {
      // The group may have been empty during the look-up: what it found is
      // not known to be ours.
      for (final pid in _fds.keys.toList()) {
        if (!before.containsKey(pid)) posix.close(_fds.remove(pid)!);
      }
    }
  }

  bool _hold(int pid, String start) {
    if (_fds.containsKey(pid)) return false;
    final fd = posix.pidfdOpen(pid);
    if (fd < 0) return false;
    // Checked after opening: the pidfd pins the process whose identity is read.
    if (processIdentity(pid) == (leader, leader, start)) {
      _fds[pid] = fd;
      return true;
    } else {
      posix.close(fd);
      return false;
    }
  }

  void signal(int sig) {
    _take();
    for (final e in _fds.entries) {
      final identity = processIdentity(e.key);
      if (identity == null || identity.$1 != leader) continue; // left the group
      posix.pidfdSignal(e.value, sig);
    }
  }

  bool get alive => _fds.values.any((fd) => !posix.pidfdExited(fd));

  void close() {
    _watch?.cancel();
    _watch = null;
    for (final fd in _fds.values) {
      posix.close(fd);
    }
    _fds.clear();
  }
}

/// SIGTERM to the program's whole group, a grace for it to end, SIGKILL to
/// whatever is left — also when the program itself ended first — and the
/// program's exit code (null when it did not end).
Future<int?> endGroup(
  Process process, {
  Duration grace = const Duration(seconds: 2),
  ProcessGroup? taken,
}) async {
  final group = taken ?? ProcessGroup(process.pid);
  try {
    group.signal(15);
    final until = DateTime.now().add(grace);
    while (group.alive && DateTime.now().isBefore(until)) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    group.signal(9);
    return await process.exitCode
        .then<int?>((c) => c)
        .timeout(const Duration(seconds: 5), onTimeout: () => null);
  } finally {
    group.close();
  }
}
