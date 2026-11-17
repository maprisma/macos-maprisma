import 'dart:collection';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;
import 'macos_platform.dart' show macosProcesses;

typedef _RawStat = ({
  int major,
  int minor,
  int dev,
  int ino,
  int mode,
  int nlink,
  int uid,
  int size,
  int blocks,
  int atimeSec,
  int atimeNsec,
  int mtimeSec,
  int mtimeNsec,
  int ctimeSec,
  int ctimeNsec,
});

/// Descriptor operations for Linux and macOS (Darwin). No shell, credentials,
/// or UI-supplied argv.
class Posix {
  Posix() {
    if (!Platform.isLinux && !Platform.isMacOS) {
      throw UnsupportedError('Linux or macOS core required');
    }
  }

  static final _lib = Platform.isMacOS
      ? DynamicLibrary.process()
      : DynamicLibrary.open('libc.so.6');

  // openat(int fd, const char *path, int oflag, ...) is variadic in C; on
  // Darwin arm64 variadic arguments are passed on the stack, requiring VarArgs.
  static final _openat = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Int, VarArgs<(Uint32,)>),
        int Function(int, Pointer<Utf8>, int, int)
      >('openat');
  static final _close = _lib
      .lookupFunction<Int Function(Int), int Function(int)>('close');
  static final _read = _lib
      .lookupFunction<
        IntPtr Function(Int, Pointer<Uint8>, IntPtr),
        int Function(int, Pointer<Uint8>, int)
      >('read');
  static final _write = _lib
      .lookupFunction<
        IntPtr Function(Int, Pointer<Uint8>, IntPtr),
        int Function(int, Pointer<Uint8>, int)
      >('write');
  static final _sync = _lib
      .lookupFunction<Int Function(Int), int Function(int)>('fsync');
  static final _chmod = _lib
      .lookupFunction<Int Function(Int, Uint32), int Function(int, int)>(
        'fchmod',
      );
  static final _statx = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Int, Uint32, Pointer<Uint8>),
        int Function(int, Pointer<Utf8>, int, int, Pointer<Uint8>)
      >('statx');
  static final _darwinFstat = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Uint8>),
        int Function(int, Pointer<Uint8>)
      >(Abi.current() == Abi.macosX64 ? 'fstat\$INODE64' : 'fstat');
  static final _darwinFstatat = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Pointer<Uint8>, Int),
        int Function(int, Pointer<Utf8>, Pointer<Uint8>, int)
      >(Abi.current() == Abi.macosX64 ? 'fstatat\$INODE64' : 'fstatat');
  static final _statvfs = _lib
      .lookupFunction<
        Int Function(Pointer<Utf8>, Pointer<Uint8>),
        int Function(Pointer<Utf8>, Pointer<Uint8>)
      >('statvfs');
  static final _rename = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Int, Pointer<Utf8>),
        int Function(int, Pointer<Utf8>, int, Pointer<Utf8>)
      >('renameat');
  static final _unlink = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Int),
        int Function(int, Pointer<Utf8>, int)
      >('unlinkat');
  static final _mkdir = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Uint32),
        int Function(int, Pointer<Utf8>, int)
      >('mkdirat');
  static final _futimens = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Int64>),
        int Function(int, Pointer<Int64>)
      >('futimens');
  static final _errno = _lib
      .lookupFunction<Pointer<Int> Function(), Pointer<Int> Function()>(
        Platform.isMacOS ? '__error' : '__errno_location',
      );
  static final _uid = _lib.lookupFunction<Uint32 Function(), int Function()>(
    'getuid',
  );

  // Exact POSIX / XNU <sys/fcntl.h> vs Linux <bits/fcntl-linux.h> constants:
  static const rdonly = 0x0000, wronly = 0x0001, rdwr = 0x0002;
  static final int creat = Platform.isMacOS ? 0x0200 : 0x40;
  static final int trunc = Platform.isMacOS ? 0x0400 : 0x200;
  static final int excl = Platform.isMacOS ? 0x0800 : 0x80;
  static final int append = Platform.isMacOS ? 0x0008 : 0x400;
  static final int noFollow = Platform.isMacOS ? 0x0100 : 0x20000;
  static final int nonBlock = Platform.isMacOS ? 0x0004 : 0x800;
  static final int cloexec = Platform.isMacOS ? 0x1000000 : 0x80000;
  static final int directory = Platform.isMacOS ? 0x100000 : 0x10000;
  static final int atFdCwd = Platform.isMacOS ? -2 : -100;
  static final int _atSymlinkNofollow = Platform.isMacOS ? 0x0020 : 0x100;
  static final int _atSymlinkFollow = Platform.isMacOS ? 0x0040 : 0x400;
  static final int _eloop = Platform.isMacOS ? 62 : 40;

  static int makeDev(int major, int minor) => Platform.isMacOS
      ? (((major & 0xff) << 24) | (minor & 0xffffff)).toSigned(32)
      : ((major & 0xfffff000) << 32) |
            ((major & 0xfff) << 8) |
            ((minor & 0xffffff00) << 12) |
            (minor & 0xff);

  static int _dir(int dir) => dir == -100 ? atFdCwd : dir;

  int get uid => _uid();
  Never _fail() => throw FileSystemException(
    'POSIX operation failed',
    '',
    OSError('', _errno().value),
  );
  T _path<T>(String path, T Function(Pointer<Utf8>) action) {
    if (path.contains('\x00')) throw ArgumentError('NUL in path');
    final native = path.toNativeUtf8();
    try {
      return action(native);
    } finally {
      calloc.free(native);
    }
  }

  int openAt(int dir, String path, int flags, [int mode = 0]) =>
      _path(path, (name) {
        final fd = _openat(_dir(dir), name, flags | cloexec, mode);
        if (fd < 0) _fail();
        return fd;
      });

  void close(int fd) {
    _kqueuePids.remove(fd);
    if (_close(fd) != 0) _fail();
  }

  void sync(int fd) {
    if (_sync(fd) != 0) _fail();
  }

  void chmod(int fd, int mode) {
    if (_chmod(fd, mode) != 0) _fail();
  }

  static final _ftruncate = _lib
      .lookupFunction<Int Function(Int, Int64), int Function(int, int)>(
        'ftruncate',
      );

  static final _linkat = _lib
      .lookupFunction<
        Int Function(Int, Pointer<Utf8>, Int, Pointer<Utf8>, Int),
        int Function(int, Pointer<Utf8>, int, Pointer<Utf8>, int)
      >('linkat');

  /// os.link: a hard link (a link given as the existing name is followed,
  /// AT_SYMLINK_FOLLOW, as os.link does); false on failure.
  bool hardLink(String existing, String link) {
    final from = existing.toNativeUtf8(), to = link.toNativeUtf8();
    try {
      return _linkat(atFdCwd, from, atFdCwd, to, _atSymlinkFollow) == 0;
    } finally {
      calloc.free(from);
      calloc.free(to);
    }
  }

  /// flock(2) without waiting: false when another holds a conflicting lock.
  /// [shared]: LOCK_SH, else LOCK_EX (task 073: the install's instance lock).
  bool tryFlock(int fd, {required bool shared}) =>
      _flock(fd, (shared ? 1 : 2) | 4) == 0;

  void truncate(int fd, int length) {
    if (_ftruncate(fd, length) != 0) _fail();
  }

  static _RawStat _decodeDarwinStat(ByteData b) {
    final dev = b.getInt32(0, Endian.host);
    return (
      major: (dev >> 24) & 0xff,
      minor: dev & 0xffffff,
      dev: dev,
      mode: b.getUint16(4, Endian.host),
      nlink: b.getUint16(6, Endian.host),
      ino: b.getUint64(8, Endian.host),
      uid: b.getUint32(16, Endian.host),
      atimeSec: b.getInt64(32, Endian.host),
      atimeNsec: b.getInt64(40, Endian.host),
      mtimeSec: b.getInt64(48, Endian.host),
      mtimeNsec: b.getInt64(56, Endian.host),
      ctimeSec: b.getInt64(64, Endian.host),
      ctimeNsec: b.getInt64(72, Endian.host),
      size: b.getInt64(96, Endian.host),
      blocks: b.getInt64(104, Endian.host),
    );
  }

  static _RawStat _decodeLinuxStatx(ByteData b) {
    final major = b.getUint32(136, Endian.host);
    final minor = b.getUint32(140, Endian.host);
    return (
      major: major,
      minor: minor,
      dev: makeDev(major, minor),
      mode: b.getUint16(28, Endian.host),
      nlink: b.getUint32(16, Endian.host),
      ino: b.getUint64(32, Endian.host),
      uid: b.getUint32(20, Endian.host),
      atimeSec: b.getInt64(64, Endian.host),
      atimeNsec: b.getUint32(72, Endian.host),
      mtimeSec: b.getInt64(112, Endian.host),
      mtimeNsec: b.getUint32(120, Endian.host),
      ctimeSec: b.getInt64(96, Endian.host),
      ctimeNsec: b.getUint32(104, Endian.host),
      size: b.getUint64(40, Endian.host),
      blocks: b.getUint64(48, Endian.host),
    );
  }

  _RawStat _readFdStat(int fd) {
    final buffer = calloc<Uint8>(256);
    try {
      if (Platform.isMacOS) {
        if (_darwinFstat(fd, buffer) != 0) _fail();
        return _decodeDarwinStat(ByteData.sublistView(buffer.asTypedList(144)));
      }
      _path('', (name) {
        if (_statx(fd, name, 0x1000, 0x7ff, buffer) != 0) _fail();
      });
      return _decodeLinuxStatx(ByteData.sublistView(buffer.asTypedList(256)));
    } finally {
      calloc.free(buffer);
    }
  }

  _RawStat? _tryPathStat(int dir, String path, {required bool follow}) {
    final d = _dir(dir);
    final buffer = calloc<Uint8>(256);
    try {
      if (Platform.isMacOS) {
        if (path.isEmpty) {
          if (_darwinFstat(d, buffer) != 0) return null;
        } else {
          var ok = false;
          _path(
            path,
            (name) => ok =
                _darwinFstatat(
                  d,
                  name,
                  buffer,
                  follow ? 0 : _atSymlinkNofollow,
                ) ==
                0,
          );
          if (!ok) return null;
        }
        return _decodeDarwinStat(ByteData.sublistView(buffer.asTypedList(144)));
      }
      var ok = false;
      final flags = path.isEmpty
          ? (follow ? 0x1000 : 0x1100)
          : (follow ? 0 : 0x100);
      _path(path, (name) => ok = _statx(d, name, flags, 0x7ff, buffer) == 0);
      if (!ok) return null;
      return _decodeLinuxStatx(ByteData.sublistView(buffer.asTypedList(256)));
    } finally {
      calloc.free(buffer);
    }
  }

  /// fstat's type, owner, size, link count and identity (device, inode).
  ({int mode, int uid, int size, int nlink, List<int> identity}) statFull(
    int fd,
  ) {
    final s = _readFdStat(fd);
    return (
      mode: s.mode,
      uid: s.uid,
      size: s.size,
      nlink: s.nlink,
      identity: [s.major, s.minor, s.ino],
    );
  }

  ({int mode, int uid, int size}) stat(int fd) {
    final s = _readFdStat(fd);
    return (mode: s.mode, uid: s.uid, size: s.size);
  }

  /// lstat's modification time and type bits, without following a final link;
  /// null when the path cannot be examined.
  ({int sec, int nsec, int mode})? lstatTime(String path) {
    final s = _tryPathStat(atFdCwd, path, follow: false);
    if (s == null) return null;
    return (sec: s.mtimeSec, nsec: s.mtimeNsec, mode: s.mode);
  }

  static final _lseek = _lib
      .lookupFunction<
        Int64 Function(Int, Int64, Int),
        int Function(int, int, int)
      >('lseek');

  void rewind(int fd) {
    if (_lseek(fd, 0, 0) < 0) _fail();
  }

  /// lstat (or stat with [follow]): times, type, owner and the identity Python
  /// compares as (st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns).
  ({int sec, int nsec, int mode, int uid, List<int> signature})? lstatFull(
    String path, {
    bool follow = false,
  }) {
    final s = _tryPathStat(atFdCwd, path, follow: follow);
    if (s == null) return null;
    return (
      sec: s.mtimeSec,
      nsec: s.mtimeNsec,
      mode: s.mode,
      uid: s.uid,
      signature: [
        s.major,
        s.minor,
        s.ino,
        s.size,
        s.mtimeSec,
        s.mtimeNsec,
        s.ctimeSec,
        s.ctimeNsec,
      ],
    );
  }

  /// lstat's type, owner, size, link count and identity; null when the path
  /// cannot be examined.
  ({int mode, int uid, int size, int nlink, List<int> identity})? lstatOwn(
    String path,
  ) {
    final s = _tryPathStat(atFdCwd, path, follow: false);
    if (s == null) return null;
    return (
      mode: s.mode,
      uid: s.uid,
      size: s.size,
      nlink: s.nlink,
      identity: [s.major, s.minor, s.ino],
    );
  }

  List<int>? signature(String path) => lstatFull(path)?.signature;

  /// os.stat / os.lstat as Python's DirEntry.stat gives them: st_dev, st_ino,
  /// st_mode, st_uid, st_size, st_blocks; null when the path cannot be looked at.
  ({int dev, int ino, int mode, int uid, int size, int blocks})? statBlocks(
    String path, {
    bool follow = false,
  }) {
    final s = _tryPathStat(atFdCwd, path, follow: follow);
    if (s == null) return null;
    return (
      dev: s.dev,
      ino: s.ino,
      mode: s.mode,
      uid: s.uid,
      size: s.size,
      blocks: s.blocks,
    );
  }

  /// mkdirat; false when the name exists already (EEXIST), else it throws.
  bool mkdirAt(int dir, String name, int mode) => _path(name, (native) {
    if (_mkdir(_dir(dir), native, mode) == 0) return true;
    if (_errno().value == 17) return false;
    _fail();
  });

  /// os.stat(name, dir_fd=dir, follow_symlinks=False) as Python gives it;
  /// null when it cannot be looked at. An empty name: dir itself.
  ({
    int dev,
    int ino,
    int mode,
    int uid,
    int size,
    int nlink,
    int atimeNs,
    int mtimeNs,
  })?
  statAt(int dir, String name) {
    final s = _tryPathStat(dir, name, follow: false);
    if (s == null) return null;
    return (
      dev: s.dev,
      ino: s.ino,
      mode: s.mode,
      uid: s.uid,
      size: s.size,
      nlink: s.nlink,
      atimeNs: s.atimeSec * 1000000000 + s.atimeNsec,
      mtimeNs: s.mtimeSec * 1000000000 + s.mtimeNsec,
    );
  }

  /// linkat(fromDir, from, toDir, to, flags); throws on failure.
  void linkAt(
    int fromDir,
    String from,
    int toDir,
    String to, {
    bool follow = false,
  }) => _path(
    from,
    (a) => _path(to, (b) {
      if (_linkat(
            _dir(fromDir),
            a,
            _dir(toDir),
            b,
            follow ? _atSymlinkFollow : 0,
          ) !=
          0) {
        _fail();
      }
    }),
  );

  /// unlinkat(dir, name, 0); throws on failure.
  void unlinkAt(int dir, String name) => _path(name, (native) {
    if (_unlink(_dir(dir), native, 0) != 0) _fail();
  });

  /// futimens: the file's access and modification times, in nanoseconds.
  void setTimes(int fd, int atimeNs, int mtimeNs) {
    final times = calloc<Int64>(4);
    try {
      times[0] = atimeNs ~/ 1000000000;
      times[1] = atimeNs % 1000000000;
      times[2] = mtimeNs ~/ 1000000000;
      times[3] = mtimeNs % 1000000000;
      if (_futimens(fd, times) != 0) _fail();
    } finally {
      calloc.free(times);
    }
  }

  /// os.statvfs: (f_blocks, f_frsize, f_bavail); null when it fails.
  ({int blocks, int frsize, int bavail})? statvfs(String path) {
    final buffer = calloc<Uint8>(128);
    try {
      var ok = false;
      _path(path, (name) => ok = _statvfs(name, buffer) == 0);
      if (!ok) return null;
      final b = ByteData.sublistView(buffer.asTypedList(128));
      if (Platform.isMacOS) {
        // Darwin <sys/statvfs.h>: f_bsize (u64@0), f_frsize (u64@8),
        // f_blocks (fsblkcnt_t=u32@16), f_bfree (u32@20), f_bavail (u32@24).
        return (
          blocks: b.getUint32(16, Endian.host),
          frsize: b.getUint64(8, Endian.host),
          bavail: b.getUint32(24, Endian.host),
        );
      }
      return (
        blocks: b.getUint64(16, Endian.host),
        frsize: b.getUint64(8, Endian.host),
        bavail: b.getUint64(32, Endian.host),
      );
    } finally {
      calloc.free(buffer);
    }
  }

  /// Open [path] without following it, check it is this account's own regular
  /// file with the same device and inode as [expected] (when given), then read.
  T? readChecked<T>(
    String path,
    T Function(int fd, int size) read, {
    List<int>? expected,
  }) {
    int? fd;
    try {
      fd = openAt(atFdCwd, path, noFollow | nonBlock);
      final _RawStat opened = _readFdStat(fd);
      if (opened.mode & 0xf000 != 0x8000 ||
          opened.uid != uid ||
          expected != null &&
              (expected.length < 3 ||
                  opened.major != expected[0] ||
                  opened.minor != expected[1] ||
                  opened.ino != expected[2])) {
        return null;
      }
      return read(fd, opened.size);
    } on FileSystemException {
      return null;
    } finally {
      if (fd != null) close(fd);
    }
  }

  /// Up to [length] bytes from [offset] (pread-like, short reads continued).
  Uint8List readAt(int fd, int offset, int length) {
    if (_lseek(fd, offset, 0) < 0) _fail();
    final buffer = calloc<Uint8>(max(1, min(length, 1 << 20)));
    final out = BytesBuilder(copy: false);
    try {
      while (out.length < length) {
        final count = _read(fd, buffer, min(length - out.length, 1 << 20));
        if (count < 0) _fail();
        if (count == 0) break;
        out.add(Uint8List.fromList(buffer.asTypedList(count)));
      }
      return out.takeBytes();
    } finally {
      calloc.free(buffer);
    }
  }

  String stamp(int fd) {
    final s = _readFdStat(fd);
    return '${s.ino}:${s.size}:${s.ctimeSec}:${s.ctimeNsec}:${s.mtimeSec}:${s.mtimeNsec}';
  }

  Uint8List readRegular(String path, int limit, {bool follow = false}) {
    final fd = openAt(atFdCwd, path, nonBlock | (follow ? 0 : noFollow));
    try {
      return readDescriptor(fd, limit);
    } finally {
      close(fd);
    }
  }

  Uint8List readSuffix(int fd, int limit) {
    final info = stat(fd);
    if ((info.mode & 0xf000) != 0x8000 ||
        limit < 0 ||
        limit > 8 * 1024 * 1024) {
      throw const FileSystemException('Invalid suffix read');
    }
    if (_lseek(fd, max(0, info.size - limit), 0) < 0) _fail();
    return readPrefix(fd, limit);
  }

  Uint8List readPrefix(int fd, int limit) {
    if ((stat(fd).mode & 0xf000) != 0x8000 ||
        limit < 0 ||
        limit > 8 * 1024 * 1024) {
      throw const FileSystemException('Invalid prefix read');
    }
    final buffer = calloc<Uint8>(max(1, limit));
    try {
      final size = _read(fd, buffer, limit);
      if (size < 0) _fail();
      return Uint8List.fromList(buffer.asTypedList(size));
    } finally {
      calloc.free(buffer);
    }
  }

  Uint8List readDescriptor(int fd, int limit) {
    final info = stat(fd);
    if ((info.mode & 0xf000) != 0x8000) {
      throw const FileSystemException('Not a regular file');
    }
    if (info.size > limit) {
      throw const FileSystemException('File exceeds bound');
    }
    final buffer = calloc<Uint8>(min(limit + 1, 65536));
    final bytes = BytesBuilder(copy: false);
    try {
      while (bytes.length <= limit) {
        final count = _read(fd, buffer, min(limit + 1 - bytes.length, 65536));
        if (count < 0) _fail();
        if (count == 0) break;
        bytes.add(Uint8List.fromList(buffer.asTypedList(count)));
      }
      if (bytes.length > limit) {
        throw const FileSystemException('File exceeds bound');
      }
      return bytes.takeBytes();
    } finally {
      calloc.free(buffer);
    }
  }

  void write(int fd, List<int> bytes) {
    final buffer = calloc<Uint8>(max(1, bytes.length));
    try {
      buffer.asTypedList(bytes.length).setAll(0, bytes);
      var offset = 0;
      while (offset < bytes.length) {
        final count = _write(fd, buffer + offset, bytes.length - offset);
        if (count <= 0) _fail();
        offset += count;
      }
    } finally {
      calloc.free(buffer);
    }
  }

  void _trustedDirectory(int fd) {
    final info = stat(fd);
    if (![0, uid].contains(info.uid) ||
        (info.mode & 0x12 != 0 && info.mode & 0x200 == 0)) {
      throw const FileSystemException('Unsafe private-write ancestor');
    }
  }

  String _readLink(int fd, String part) {
    final readlink = _lib
        .lookupFunction<
          IntPtr Function(Int, Pointer<Utf8>, Pointer<Uint8>, IntPtr),
          int Function(int, Pointer<Utf8>, Pointer<Uint8>, int)
        >('readlinkat');
    final buffer = calloc<Uint8>(4096);
    try {
      final length = _path(part, (name) => readlink(fd, name, buffer, 4096));
      if (length < 0) _fail();
      if (length == 4096) {
        throw const FileSystemException('Parent symlink too long');
      }
      return utf8.decode(buffer.asTypedList(length));
    } finally {
      calloc.free(buffer);
    }
  }

  /// Descriptor-based realpath: validate every traversed directory, including
  /// directories hidden by intermediate symlinks, and allow a missing suffix.
  /// The returned path is subsequently walked again without following links.
  String resolveParent(String absolute) {
    if (!p.isAbsolute(absolute)) throw ArgumentError('Absolute path required');
    final pending = ListQueue<String>.from(p.split(absolute).skip(1));
    final resolved = <String>[];
    var fd = openAt(atFdCwd, '/', directory | noFollow);
    var links = 0;
    try {
      _trustedDirectory(fd);
      while (pending.isNotEmpty) {
        final part = pending.removeFirst();
        if (part.isEmpty || part == '.') continue;
        if (part == '..') {
          final child = openAt(fd, '..', directory | noFollow);
          close(fd);
          fd = child;
          if (resolved.isNotEmpty) resolved.removeLast();
          _trustedDirectory(fd);
          continue;
        }
        int child;
        try {
          child = openAt(fd, part, directory | noFollow);
        } on FileSystemException catch (e) {
          if (e.osError?.errorCode == 2) {
            return p.normalize(p.joinAll(['/', ...resolved, part, ...pending]));
          }
          if (![20, _eloop].contains(e.osError?.errorCode)) rethrow;
          final target = _readLink(fd, part);
          if (++links > 40) {
            throw const FileSystemException('Too many parent symlinks');
          }
          final absoluteTarget = p.isAbsolute(target);
          if (absoluteTarget) {
            close(fd);
            fd = openAt(atFdCwd, '/', directory | noFollow);
            resolved.clear();
            _trustedDirectory(fd);
          }
          final parts = p.split(target);
          for (final component
              in (absoluteTarget ? parts.skip(1) : parts).toList().reversed) {
            pending.addFirst(component);
          }
          continue;
        }
        close(fd);
        fd = child;
        resolved.add(part);
        _trustedDirectory(fd);
      }
      return p.joinAll(['/', ...resolved]);
    } finally {
      close(fd);
    }
  }

  /// Resolve the existing layout once, then pin the trusted, resolved chain.
  /// A symlink inserted into that chain after resolution fails closed.
  int privateDirectory(String absolute) {
    if (!p.isAbsolute(absolute)) throw ArgumentError('Absolute path required');
    final resolved = resolveParent(p.normalize(absolute));
    var fd = openAt(atFdCwd, '/', directory | noFollow);
    try {
      _trustedDirectory(fd);
      for (final part in p.split(resolved).skip(1)) {
        try {
          final child = openAt(fd, part, directory | noFollow);
          close(fd);
          fd = child;
        } on FileSystemException catch (e) {
          if (e.osError?.errorCode != 2) rethrow;
          _path(part, (name) {
            if (_mkdir(fd, name, 0x1c0) != 0 && _errno().value != 17) _fail();
          });
          final child = openAt(fd, part, directory | noFollow);
          close(fd);
          fd = child;
        }
        _trustedDirectory(fd);
      }
      return fd;
    } catch (_) {
      close(fd);
      rethrow;
    }
  }

  /// Resolve trusted aliases and pin an existing directory without creating it.
  int existingDirectory(String absolute) {
    final resolved = resolveParent(p.normalize(absolute));
    var fd = openAt(atFdCwd, '/', directory | noFollow);
    try {
      _trustedDirectory(fd);
      for (final part in p.split(resolved).skip(1)) {
        final child = openAt(fd, part, directory | noFollow);
        close(fd);
        fd = child;
        _trustedDirectory(fd);
      }
      return fd;
    } catch (_) {
      close(fd);
      rethrow;
    }
  }

  static final _chmodPath = _lib
      .lookupFunction<
        Int Function(Pointer<Utf8>, Uint32),
        int Function(Pointer<Utf8>, int)
      >('chmod');

  /// chmod for a path this process just created (folders and copies in its
  /// own backup folder).
  void chmodPath(String path, int mode) => _path(path, (name) {
    if (_chmodPath(name, mode) != 0) _fail();
  });

  /// Python connect._write for an agent's settings: a fresh exclusive
  /// temporary file in the same folder, its mode set before writing, fsync,
  /// then renamed over.
  void replaceFile(String path, List<int> bytes, int mode) {
    final dir = openAt(atFdCwd, p.dirname(path), directory);
    final temporary =
        '.${p.basename(path)}-${Random.secure().nextInt(1 << 32)}-${Random.secure().nextInt(1 << 32)}';
    int? fd;
    var created = false, renamed = false;
    try {
      fd = openAt(dir, temporary, wronly | creat | excl | noFollow, mode);
      created = true;
      chmod(fd, mode);
      write(fd, bytes);
      sync(fd);
      close(fd);
      fd = null;
      _path(
        temporary,
        (from) => _path(p.basename(path), (to) {
          if (_rename(dir, from, dir, to) != 0) _fail();
        }),
      );
      renamed = true;
    } finally {
      if (fd != null) close(fd);
      if (created && !renamed) {
        _path(temporary, (name) => _unlink(dir, name, 0));
      }
      close(dir);
    }
  }

  void atomicWrite(String path, List<int> bytes) {
    final dir = privateDirectory(p.dirname(path));
    final temporary =
        '.${p.basename(path)}-${Random.secure().nextInt(1 << 32)}-${Random.secure().nextInt(1 << 32)}';
    int? fd;
    var created = false;
    try {
      fd = openAt(dir, temporary, wronly | creat | excl | noFollow, 0x180);
      created = true;
      chmod(fd, 0x180);
      write(fd, bytes);
      sync(fd);
      close(fd);
      fd = null;
      _path(
        temporary,
        (from) => _path(p.basename(path), (to) {
          if (_rename(dir, from, dir, to) != 0) _fail();
        }),
      );
      sync(dir);
    } finally {
      if (fd != null) close(fd);
      if (created) _path(temporary, (name) => _unlink(dir, name, 0));
      close(dir);
    }
  }

  // --- Process pinning: pidfd on Linux, kqueue EVFILT_PROC on macOS ----------

  static final _linuxPidfdOpen = _lib
      .lookupFunction<Int Function(Int, Uint32), int Function(int, int)>(
        'pidfd_open',
      );
  static final _linuxPidfdSend = _lib
      .lookupFunction<
        Int Function(Int, Int, Pointer<Void>, Uint32),
        int Function(int, int, Pointer<Void>, int)
      >('pidfd_send_signal');

  static final _kqueue = _lib.lookupFunction<Int Function(), int Function()>(
    'kqueue',
  );
  static final _kevent = _lib
      .lookupFunction<
        Int Function(
          Int,
          Pointer<Uint8>,
          Int,
          Pointer<Uint8>,
          Int,
          Pointer<Int64>,
        ),
        int Function(
          int,
          Pointer<Uint8>,
          int,
          Pointer<Uint8>,
          int,
          Pointer<Int64>,
        )
      >('kevent');
  static final _fcntlSet = _lib
      .lookupFunction<
        Int Function(Int, Int, VarArgs<(Int,)>),
        int Function(int, int, int)
      >('fcntl');
  static final _kill = _lib
      .lookupFunction<Int Function(Int, Int), int Function(int, int)>('kill');

  static final _poll = _lib
      .lookupFunction<
        Int Function(Pointer<Int32>, Uint64, Int),
        int Function(Pointer<Int32>, int, int)
      >('poll');

  // Maps active macOS kqueue process descriptors back to their monitored PID.
  static final _kqueuePids = <int, int>{};

  static int _darwinProcOpen(int pid) {
    if (pid <= 0) return -1;
    final kq = _kqueue();
    if (kq < 0) return -1;
    // F_SETFD = 2, FD_CLOEXEC = 1 on Darwin.
    _fcntlSet(kq, 2, 1);
    final change = calloc<Uint8>(32);
    final event = calloc<Uint8>(32);
    try {
      final cb = ByteData.sublistView(change.asTypedList(32));
      cb.setUint64(0, pid, Endian.host); // ident = pid
      cb.setInt16(8, -5, Endian.host); // filter = EVFILT_PROC (-5)
      // EV_ADD (0x1) | EV_ENABLE (0x4) | EV_RECEIPT (0x40): returns a receipt
      // without dequeuing NOTE_EXIT if the process already exited.
      cb.setUint16(10, 0x0001 | 0x0004 | 0x0040, Endian.host);
      cb.setUint32(12, 0x80000000, Endian.host); // NOTE_EXIT
      final n = _kevent(kq, change, 1, event, 1, nullptr);
      if (n < 0) {
        _close(kq);
        return -1;
      }
      if (n > 0) {
        final eb = ByteData.sublistView(event.asTypedList(32));
        final flags = eb.getUint16(10, Endian.host);
        final data = eb.getInt64(16, Endian.host);
        if ((flags & 0x4000) != 0 && data != 0) {
          _close(kq);
          return -1;
        }
      }
      _kqueuePids[kq] = pid;
      return kq;
    } finally {
      calloc.free(change);
      calloc.free(event);
    }
  }

  /// pidfd (Linux) or kqueue EVFILT_PROC (macOS) pins the process identity.
  /// Start time and UID are checked after open; an exited/reused PID cannot
  /// make this descriptor target its replacement.
  bool signalOwned(int pid, String expectedStart, int signal) {
    if (pid <= 0 || ![0, 15].contains(signal)) return false;
    if (Platform.isMacOS) {
      final fd = _darwinProcOpen(pid);
      if (fd < 0) return false;
      try {
        final proc = macosProcesses(
          fresh: true,
        ).where((p) => p.pid == pid).firstOrNull;
        if (proc == null || proc.uid != uid) return false;
        final expectedEpoch = double.tryParse(expectedStart);
        final matchesStart =
            proc.lstart == expectedStart ||
            (expectedEpoch != null &&
                (proc.startedEpoch - expectedEpoch).abs() < 0.5);
        if (!matchesStart || pidfdExited(fd)) return false;
        return _kill(pid, signal) == 0;
      } finally {
        close(fd);
      }
    }
    late final int Function(int, int) open;
    late final int Function(int, int, Pointer<Void>, int) send;
    try {
      open = _linuxPidfdOpen;
      send = _linuxPidfdSend;
    } on ArgumentError {
      throw UnsupportedError(
        'Linux pidfd libc symbols are unavailable; no signal was sent',
      );
    }
    final fd = open(pid, 0);
    if (fd < 0) return false;
    try {
      final proc = openAt(atFdCwd, '/proc/$pid', directory | noFollow);
      try {
        if (stat(proc).uid != uid) return false;
      } finally {
        close(proc);
      }
      final status = utf8.decode(readRegular('/proc/$pid/stat', 65536));
      final tail = status.substring(status.lastIndexOf(')') + 2).split(' ');
      if (tail.length < 20 || tail[19] != expectedStart) return false;
      return send(fd, signal, nullptr, 0) == 0;
    } on FileSystemException {
      return false;
    } finally {
      close(fd);
    }
  }

  /// Pins [pid] via pidfd (Linux) or kqueue EVFILT_PROC (macOS); -1 if gone.
  int pidfdOpen(int pid) => pid <= 0
      ? -1
      : (Platform.isMacOS ? _darwinProcOpen(pid) : _linuxPidfdOpen(pid, 0));

  /// Sends [signal] to the pinned process if it has not yet exited.
  void pidfdSignal(int fd, int signal) {
    if (Platform.isMacOS) {
      final targetPid = _kqueuePids[fd];
      if (targetPid == null || pidfdExited(fd)) return;
      _kill(targetPid, signal);
      return;
    }
    _linuxPidfdSend(fd, signal, nullptr, 0);
  }

  /// Both Linux pidfds and macOS EVFILT_PROC kqueues become POLLIN-readable as
  /// soon as the pinned process exits.
  bool pidfdExited(int fd) {
    final entry = calloc<Int32>(2);
    try {
      entry[0] = fd;
      entry[1] = 1; // POLLIN in events (low 16 bits); revents in high 16 bits
      final ready = _poll(entry, 1, 0);
      return ready > 0 && (entry[1] >> 16) & 0x39 != 0;
    } finally {
      calloc.free(entry);
    }
  }

  static final _flock = _lib
      .lookupFunction<Int Function(Int, Int), int Function(int, int)>('flock');

  /// fcntl.flock(fd, LOCK_EX): the same lock the reference takes.
  void lockExclusive(int fd) {
    if (_flock(fd, 2) != 0) _fail();
  }

  /// flock(fd, LOCK_EX | LOCK_NB): false when another holds it.
  bool tryLockExclusive(int fd) => _flock(fd, 6) == 0;
}
