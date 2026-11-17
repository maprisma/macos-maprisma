import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:maprisma_core/src/installers.dart';
import 'package:maprisma_core/src/model_downloads.dart' show ModelFiles;
import 'package:maprisma_core/src/posix_ffi.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;
  final posix = Posix();
  setUp(() => root = Directory.systemTemp.createTempSync('maprisma-trust-'));
  tearDown(() {
    Process.runSync('chmod', ['-R', 'u+rwx', root.path]);
    root.deleteSync(recursive: true);
  });

  void chmod(String path, String mode) =>
      Process.runSync('chmod', [mode, path]);

  test('private folders, missing parts: fine', () {
    checkTrusted(root.path);
    checkTrusted('${root.path}/new/deeper');
  });

  test('a program folder others can write is refused, sticky or not', () {
    final shared = Directory('${root.path}/shared')..createSync();
    for (final mode in ['775', '777', '1777']) {
      chmod(shared.path, mode);
      expect(() => checkTrusted(shared.path), throwsStateError);
    }
  });

  test('a writable folder above needs the sticky bit', () {
    final parent = '${root.path}/parent';
    Directory('$parent/prog').createSync(recursive: true);
    chmod(parent, '777');
    expect(() => checkTrusted('$parent/prog'), throwsStateError);
    expect(() => checkTrusted('$parent/other'), throwsStateError);
    chmod(parent, '1777');
    checkTrusted('$parent/prog');
  });

  test(
    'links on the way are followed and checked; the folder itself no link',
    () {
      Directory('${root.path}/real/prog').createSync(recursive: true);
      Link('${root.path}/theirs').createSync('${root.path}/real');
      Link('${root.path}/mine').createSync('${root.path}/theirs');
      checkTrusted('${root.path}/mine/prog');
      expect(() => checkTrusted('${root.path}/mine'), throwsStateError);
      Directory('${root.path}/b').createSync();
      Link('${root.path}/b/up').createSync('../real');
      checkTrusted('${root.path}/b/up/prog');
      chmod('${root.path}/real', '777');
      expect(() => checkTrusted('${root.path}/b/up/prog'), throwsStateError);
      expect(() => checkTrusted('${root.path}/a/../b'), throwsStateError);
    },
  );

  test('the verified file keeps its bytes when the name is swapped', () {
    final file = File('${root.path}/release.tar.zst')
      ..writeAsStringSync('verified bytes');
    final digest = sha256.convert(utf8.encode('verified bytes')).toString();
    final fd = openVerified(ModelFiles(posix), file.path, digest);
    try {
      File('${root.path}/evil').writeAsStringSync('other bytes');
      File('${root.path}/evil').renameSync(file.path);
      final fdPath = Platform.isMacOS ? '/dev/fd/$fd' : '/proc/$pid/fd/$fd';
      expect(File(fdPath).readAsStringSync(), 'verified bytes');
    } finally {
      posix.close(fd);
    }
  });

  test('wrong bytes, a link or a file others can write: refused', () {
    final file = File('${root.path}/a')..writeAsStringSync('x');
    final digest = sha256.convert(utf8.encode('x')).toString();
    expect(
      () => openVerified(
        ModelFiles(posix),
        file.path,
        sha256.convert([1]).toString(),
      ),
      throwsStateError,
    );
    Link('${root.path}/b').createSync(file.path);
    expect(
      () => openVerified(ModelFiles(posix), '${root.path}/b', digest),
      throwsStateError,
    );
    chmod(file.path, '666');
    expect(
      () => openVerified(ModelFiles(posix), file.path, digest),
      throwsStateError,
    );
  });

  test(
    'O_CLOEXEC verified descriptors unpack archives and run install.sh across exec via staged private copy',
    () async {
      // 1. Archive extraction across exec (`tar -x -f ...`) after name swap:
      final srcDir = Directory('${root.path}/src')..createSync();
      File('${srcDir.path}/ollama').writeAsStringSync('#!/bin/sh\necho ok\n');
      chmod('${srcDir.path}/ollama', '755');
      final archive = File('${root.path}/ollama-darwin.tgz');
      final tarRes = Process.runSync('tar', [
        '-czf',
        archive.path,
        '-C',
        srcDir.path,
        'ollama',
      ]);
      expect(tarRes.exitCode, 0);
      final tarDigest = sha256.convert(archive.readAsBytesSync()).toString();
      final tarFd = openVerified(ModelFiles(posix), archive.path, tarDigest);
      String? stagedSeen;
      try {
        // Swap the filename on disk before unpacking:
        File('${root.path}/tampered.tgz')
          ..writeAsStringSync('corrupted')
          ..renameSync(archive.path);
        final outDir = '${root.path}/unpacked';
        await withVerifiedFdPath(posix, tarFd, 'ollama-darwin.tgz', (
          verifiedPath,
        ) async {
          stagedSeen = verifiedPath;
          final st = posix.lstatOwn(verifiedPath)!;
          expect(st.mode & 0x1ff, 0x180); // 0600
          final dirSt = posix.lstatOwn(File(verifiedPath).parent.path)!;
          expect(dirSt.mode & 0x1ff, 0x1c0); // 0700
          await extract(verifiedPath, outDir, name: 'ollama-darwin.tgz');
        }, stageCopy: true);
        expect(
          File('$outDir/ollama').readAsStringSync(),
          '#!/bin/sh\necho ok\n',
        );
        expect(Directory(File(stagedSeen!).parent.path).existsSync(), isFalse);
      } finally {
        posix.close(tarFd);
      }

      // 2. Strata `sh <verifiedPath>` across exec after name swap:
      final script = File('${root.path}/install.sh')
        ..writeAsStringSync('#!/bin/sh\necho "verified-strata"\n');
      final shDigest = sha256.convert(script.readAsBytesSync()).toString();
      final shFd = openVerified(ModelFiles(posix), script.path, shDigest);
      try {
        File('${root.path}/evil.sh')
          ..writeAsStringSync('#!/bin/sh\necho "pwned"\n')
          ..renameSync(script.path);
        final output = await withVerifiedFdPath(posix, shFd, 'install.sh', (
          verifiedPath,
        ) async {
          final r = await Process.run('sh', [verifiedPath]);
          expect(r.exitCode, 0);
          return (r.stdout as String).trim();
        }, stageCopy: true);
        expect(output, 'verified-strata');
      } finally {
        posix.close(shFd);
      }
    },
  );
}
