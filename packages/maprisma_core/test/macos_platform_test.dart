import 'dart:convert';
import 'dart:io';

import 'package:maprisma_core/maprisma_core.dart';
import 'package:maprisma_core/src/desktop_palette.dart' show macosFonts;
import 'package:maprisma_core/src/installers.dart'
    show Gpu, InstallHost, LlamaCppInstaller, OllamaInstaller;
import 'package:maprisma_core/src/skill_plans.dart' show AgentProfiles;
import 'package:test/test.dart';

void main() {
  group('macOS PATH augmentation', () {
    test('appends Homebrew and user CLI directories without duplicates', () {
      const home = '/Users/uwe';
      final augmented = augmentMacosPath(
        '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin',
        home,
      );
      final parts = augmented.split(':');
      expect(
        parts,
        equals([
          '/usr/bin',
          '/bin',
          '/usr/sbin',
          '/sbin',
          '/opt/homebrew/bin',
          '/opt/homebrew/sbin',
          '/usr/local/bin',
          '/Users/uwe/.local/bin',
          '/Users/uwe/.cargo/bin',
          '/Users/uwe/.local/share/mise/shims',
          '/Users/uwe/.bun/bin',
          '/Users/uwe/.npm-global/bin',
        ]),
      );
    });

    test('AppIdentity augments PATH when MAPRISMA_AUGMENT_PATH=1', () {
      final id = AppIdentity(
        environment: {
          'HOME': '/Users/uwe',
          'PATH': '/usr/bin:/bin',
          'MAPRISMA_AUGMENT_PATH': '1',
        },
      );
      if (Platform.isMacOS) {
        expect(
          id.environment['PATH']!.split(':'),
          containsAll(['/opt/homebrew/bin', '/Users/uwe/.local/bin']),
        );
      } else {
        // Explicit Linux hermetic environment remains untouched.
        expect(id.environment['PATH'], '/usr/bin:/bin');
      }
    });
  });

  group('macOS ps output parser', () {
    test(
      'parses CLI agents, node shims, .app bundles with spaces, UID filter, and lstart',
      () {
        const psOutput = '''
  101     1     0 Tue Nov 17 09:00:00 2026 /sbin/launchd /sbin/launchd
 4201   812   501 Tue Nov 17 16:55:03 2026 /opt/homebrew/bin/claude /opt/homebrew/bin/claude --dangerously-skip-permissions
 4202   812   501 Tue Nov 17 16:55:10 2026 /opt/homebrew/bin/node /opt/homebrew/bin/node /Users/uwe/.npm-global/bin/codex --model o3
 4203     1   501 Tue Nov 17 16:56:00 2026 /Applications/LM Studio.app/Contents/MacOS/LM Studio /Applications/LM Studio.app/Contents/MacOS/LM Studio --run-as-service
 4204   812   502 Tue Nov 17 16:56:12 2026 /opt/homebrew/bin/gemini /opt/homebrew/bin/gemini
''';

        final own = parseMacosPs(psOutput, onlyUid: 501);
        expect(own.map((p) => p.pid), equals([4201, 4202, 4203]));

        final claude = own[0];
        expect(claude.ppid, 812);
        expect(claude.uid, 501);
        expect(claude.comm, 'claude');
        expect(
          claude.argv,
          equals([
            '/opt/homebrew/bin/claude',
            '--dangerously-skip-permissions',
          ]),
        );
        expect(
          claude.startedEpoch,
          equals(
            DateTime(2026, 11, 17, 16, 55, 3).millisecondsSinceEpoch / 1000.0,
          ),
        );

        final codex = own[1];
        expect(codex.comm, 'node');
        expect(
          codex.argv,
          equals([
            '/opt/homebrew/bin/node',
            '/Users/uwe/.npm-global/bin/codex',
            '--model',
            'o3',
          ]),
        );

        final lmStudio = own[2];
        expect(lmStudio.comm, 'LM Studio');
        expect(
          lmStudio.argv,
          equals([
            '/Applications/LM Studio.app/Contents/MacOS/LM Studio',
            '--run-as-service',
          ]),
        );
      },
    );

    test('parses full ps output with pgid and hex session pointer', () {
      const psFull =
          ' 5120  5100  5120 0x7f9a12340  501 Tue Nov 17 17:00:05 2026 /opt/homebrew/bin/llama-server /opt/homebrew/bin/llama-server --port 8080\n';
      final parsed = parseMacosPs(psFull);
      expect(parsed, hasLength(1));
      expect(parsed.single.pid, 5120);
      expect(parsed.single.pgid, 5120);
      expect(parsed.single.sess, 0x7f9a12340);
      expect(parsed.single.comm, 'llama-server');
      expect(
        parsed.single.argv,
        equals(['/opt/homebrew/bin/llama-server', '--port', '8080']),
      );
    });
  });

  group('macOS lsof port security check', () {
    test(
      'accepts own-UID loopback listeners and rejects foreign-UID or missing listeners',
      () {
        const lsofListen = '''
p1200
u501
f4
n127.0.0.1:11434
n[::1]:11434
p1300
u501
f6
n*:8080
p1400
u502
f8
n127.0.0.1:8080
p1500
u501
f9
n192.168.1.42:9090
''';

        // Port 11434: owned solely by UID 501 on IPv4 & IPv6 loopback.
        expect(parseMacosLsofListeners(lsofListen, 11434), equals([501, 501]));
        expect(macosOwnPort(11434, 501, lsofOutput: lsofListen), isTrue);
        expect(macosOwnPort(11434, 502, lsofOutput: lsofListen), isFalse);

        // Port 8080: wildcard by 501 + loopback hijack by 502 -> MUST be rejected!
        expect(parseMacosLsofListeners(lsofListen, 8080), equals([501, 502]));
        expect(macosOwnPort(8080, 501, lsofOutput: lsofListen), isFalse);

        // Port 9090: LAN interface only, not loopback -> ignored.
        expect(parseMacosLsofListeners(lsofListen, 9090), isEmpty);
        expect(macosOwnPort(9090, 501, lsofOutput: lsofListen), isFalse);
      },
    );

    test('detects established client connections excluding ignored PIDs', () {
      const lsofEst = '''
p5000
n127.0.0.1:8080->127.0.0.1:54321
p6001
n127.0.0.1:54321->127.0.0.1:8080
''';
      expect(parseMacosLsofEstablished(lsofEst, 8080, {5000}), isTrue);
      expect(parseMacosLsofEstablished(lsofEst, 8080, {5000, 6001}), isFalse);
    });
  });

  group('macOS Apple Silicon Metal & Unified Memory detection', () {
    test(
      'detects Apple M4 Max unified memory and IOAccelerator Metal utilization',
      () {
        const ioregSample = '''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array>
  <dict>
    <key>model</key>
    <string>Apple M4 Max</string>
    <key>gpu-core-count</key>
    <integer>40</integer>
    <key>PerformanceStatistics</key>
    <dict>
      <key>Device Utilization %</key>
      <integer>37</integer>
      <key>In use system memory</key>
      <integer>17179869184</integer>
    </dict>
  </dict>
</array>
</plist>
''';
        final hw = parseMacosHardware(
          cpuBrand: 'Apple M4 Max',
          memsizeText: '68719476736', // 64 GiB unified memory
          ioregOutput: ioregSample,
          isArm64: true,
        );
        expect(hw.vendor, 'apple');
        expect(hw.name, 'Apple M4 Max');
        expect(hw.ram, 68719476736);
        expect(hw.vram, 68719476736);
        expect(hw.gpuCores, 40);
        expect(hw.busyPercent, 37.0);
        expect(hw.vramUsed, 17179869184);
      },
    );
  });

  group('macOS df / mount local disks parser', () {
    test('keeps external /Volumes disks and excludes macOS system volumes', () {
      const dfOut = '''
Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/disk3s1s1   971350180  15234120 712345600     3%   /
/dev/disk3s6     971350180   2097152 712345600     1%   /System/Volumes/VM
/dev/disk3s5     971350180 241684300 712345600    26%   /System/Volumes/Data
/dev/disk4s2    1953514584 412000000 1541514584   22%   /Volumes/ModelsSSD
/dev/disk5s1     500000000  10000000 490000000     2%   /Volumes/com.apple.TimeMachine.localsnapshots
''';
      const mountOut = '''
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
/dev/disk4s2 on /Volumes/ModelsSSD (apfs, local, nodev, nosuid, journaled, noowners)
''';
      final mounts = parseMacosDfMounts(dfOut, mountOutput: mountOut);
      expect(
        mounts,
        equals([
          {
            'path': '/Volumes/ModelsSSD',
            'filesystem': 'apfs',
            'identity': '/dev/disk4s2',
          },
        ]),
      );
    });
  });

  group('macOS config paths, LaunchAgents, Homebrew & Terminal commands', () {
    test('resolves Claude Desktop and Jan paths on macOS vs Linux', () {
      const home = '/Users/uwe';
      expect(
        claudeDesktopConfigPath(home, isMacOS: true),
        '/Users/uwe/Library/Application Support/Claude/claude_desktop_config.json',
      );
      expect(
        claudeDesktopConfigPath(home, isMacOS: false),
        '/Users/uwe/.config/Claude/claude_desktop_config.json',
      );
      expect(
        janRootPath(home, isMacOS: true),
        '/Users/uwe/Library/Application Support/Jan',
      );
      expect(
        AgentProfiles.pathOk(
          '~/Library/Application Support/Claude/claude_desktop_config.json',
        ),
        isTrue,
      );
      expect(
        AgentProfiles.pathOk(
          '~/Library/Application Support/Claude/credentials.json',
        ),
        isFalse,
      );
    });

    test(
      'McpPlans reads Claude Desktop MCP servers from its platform path',
      () {
        final tmp = Directory.systemTemp.createTempSync(
          'maprisma-claude-desk-',
        );
        addTearDown(() => tmp.deleteSync(recursive: true));
        final cfgPath = claudeDesktopConfigPath(tmp.path);
        File(cfgPath)
          ..parent.createSync(recursive: true)
          ..writeAsStringSync(
            jsonEncode({
              'mcpServers': {
                'memory': {
                  'command': 'npx',
                  'args': ['-y', '@modelcontextprotocol/server-memory'],
                },
              },
            }),
          );
        final service = CoreService(environment: {'HOME': tmp.path});
        final entries = service.mcp.rawEntries('claude-desktop');
        expect(entries.keys, contains('memory'));
        expect((entries['memory'] as Map)['command'], 'npx');
      },
    );

    test(
      'LaunchAgent plist round-trips Label, ProgramArguments, and EnvironmentVariables',
      () {
        final xml = buildLaunchAgentPlist(
          label: 'com.maprisma.llama-server',
          programArguments: [
            '/Users/uwe/.local/bin/llama-server',
            '--models-preset',
            '/Users/uwe/.config/llama.cpp/models.ini',
          ],
          environment: {
            'MAPRISMA_ENV_FILE': '/Users/uwe/.config/llama.cpp/server.env',
            'LLAMA_ARG_PORT': '8080',
          },
          runAtLoad: true,
          keepAlive: true,
          comment: 'installed by Maprisma',
        );
        expect(xml, contains('<!-- installed by Maprisma -->'));
        final parsed = parseLaunchAgentPlist(xml);
        expect(parsed.label, 'com.maprisma.llama-server');
        expect(
          parsed.programArguments,
          equals([
            '/Users/uwe/.local/bin/llama-server',
            '--models-preset',
            '/Users/uwe/.config/llama.cpp/models.ini',
          ]),
        );
        expect(parsed.environment['LLAMA_ARG_PORT'], '8080');
        expect(
          parsed.environment['MAPRISMA_ENV_FILE'],
          '/Users/uwe/.config/llama.cpp/server.env',
        );
      },
    );

    test('Homebrew commands & AppleInterfaceStyle dark/light parser', () {
      expect(
        macosBrewInstallCommand('llamacpp'),
        equals(['brew', 'install', 'llama.cpp']),
      );
      expect(
        macosBrewInstallCommand('ollama'),
        equals(['brew', 'install', '--cask', 'ollama']),
      );
      expect(
        macosBrewInstallCommand('lmstudio'),
        equals(['brew', 'install', '--cask', 'lm-studio']),
      );
      expect(
        macosBrewInstallCommand('node'),
        equals(['brew', 'install', 'node']),
      );
      expect(macosBrewInstallCommand('uv'), equals(['brew', 'install', 'uv']));

      expect(parseAppleInterfaceStyle(0, 'Dark\n'), 'dark');
      expect(parseAppleInterfaceStyle(1, ''), 'light');
      expect(macosFonts(hasSfMono: true), {
        'ui': '.AppleSystemUIFont',
        'mono': 'SF Mono',
      });
      expect(macosFonts(hasSfMono: false), {
        'ui': '.AppleSystemUIFont',
        'mono': 'Menlo',
      });
    });

    test(
      'Darwin shellQuote & Terminal/Ghostty/iTerm command builders safely quote special characters',
      () {
        const trickyDir = "/Users/uwe/My Project's \"Dir\" \$(whoami)";
        expect(
          shellQuote(trickyDir),
          equals("'${trickyDir.replaceAll("'", "'\"'\"'")}'"),
        );

        final osa = buildMacosOsascriptTerminalArgs([
          'claude',
          '--append-system-prompt',
          "Don't run \$(rm -rf /)",
        ], trickyDir);
        expect(osa.first, '/usr/bin/osascript');
        expect(osa, contains('tell application "Terminal"'));
        expect(osa, contains('do script (item 1 of argv)'));
        // Verify command is passed out-of-band after `--`, never interpolated in AppleScript!
        final dashDash = osa.indexOf('--');
        expect(dashDash, greaterThan(0));
        final scriptCmd = osa[dashDash + 1];
        expect(
          scriptCmd,
          "cd -- ${shellQuote(trickyDir)} && claude --append-system-prompt ${shellQuote("Don't run \$(rm -rf /)")}",
        );

        // Ghostty preferred when installed in /Applications/Ghostty.app:
        final ghosttyCmd = resolveMacosTerminalCommand(
          ['codex'],
          '/Users/uwe/work',
          environment: {'HOME': '/Users/uwe', 'PATH': '/usr/bin:/bin'},
          dirExists: (path) => path == '/Applications/Ghostty.app',
          fileExists: (_) => false,
        );
        expect(
          ghosttyCmd,
          equals([
            '/usr/bin/open',
            '-na',
            '/Applications/Ghostty.app',
            '--args',
            '--working-directory=/Users/uwe/work',
            '-e',
            'codex',
          ]),
        );

        // Falls back to Terminal.app via osascript when no third-party terminal is installed:
        final termFallback = resolveMacosTerminalCommand(
          ['gemini'],
          '/Users/uwe/work',
          environment: {'HOME': '/Users/uwe', 'PATH': '/usr/bin:/bin'},
          dirExists: (_) => false,
          fileExists: (path) => path == '/usr/bin/osascript',
        );
        expect(termFallback, isNotNull);
        expect(termFallback!.first, '/usr/bin/osascript');
        expect(termFallback.last, 'cd -- /Users/uwe/work && gemini');

        // iTerm2 AppleScript uses `create window with default profile` +
        // `write text (item 1 of argv)` so `cd ... && ...` runs in a shell:
        final itermArgs = buildMacosOsascriptTerminalArgs(
          ['claude'],
          '/Users/uwe/My Repo',
          app: 'iTerm',
        );
        expect(itermArgs, contains('create window with default profile'));
        expect(
          itermArgs,
          contains(
            'tell current session of current window to write text (item 1 of argv)',
          ),
        );
        expect(
          itermArgs.any((s) => s.contains('default profile command')),
          isFalse,
        );
      },
    );

    test(
      'C-locale environment override prevents German/non-English ps lstart failures',
      () {
        final env = macosCommandCEnv({
          'HOME': '/Users/uwe',
          'PATH': '/usr/bin:/bin',
          'LANG': 'de_DE.UTF-8',
          'LC_ALL': 'de_DE.UTF-8',
          'LC_TIME': 'de_DE.UTF-8',
        });
        expect(env['LC_ALL'], 'C');
        expect(env['LANG'], 'C');
        expect(env['PATH'], '/usr/bin:/bin');

        final dateRes = Process.runSync('/bin/sh', const [
          '-c',
          'date "+%a %b"',
        ], environment: env);
        expect(dateRes.exitCode, 0);
        expect(
          (dateRes.stdout as String).trim(),
          matches(
            RegExp(
              r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$',
            ),
          ),
        );
      },
    );

    test(
      'LaunchAgent server.env loader preserves spaces in model paths without shell word-splitting',
      () async {
        final tmp = Directory.systemTemp.createTempSync('maprisma-env-space-');
        addTearDown(() => tmp.deleteSync(recursive: true));

        const spacedModels = '/Volumes/External SSD/AI Models/Ollama Store';
        final host = InstallHost(tmp.path, Posix());
        final ollama = OllamaInstaller(host);
        final llama = LlamaCppInstaller(host);
        final envContent = ollama.envText(spacedModels, Gpu());
        final envFile = File('${tmp.path}/server.env')
          ..writeAsStringSync(envContent);

        // Plist EnvironmentVariables dictionary holds the unsplit path:
        final plistXml = ollama.plistText(spacedModels, Gpu());
        final parsedPlist = parseLaunchAgentPlist(plistXml);
        expect(parsedPlist.environment['OLLAMA_MODELS'], spacedModels);

        final llamaPlist = parseLaunchAgentPlist(
          llama.plistText('/Volumes/External SSD/GGUF Models', Gpu()),
        );
        expect(
          llamaPlist.environment['LLAMA_ARG_MODELS_DIR'],
          '/Volumes/External SSD/GGUF Models',
        );

        // Executing the LaunchAgent ProgramArguments with a later-edited
        // server.env containing spaces exports the exact path without splitting:
        envFile.writeAsStringSync(
          '# edited later\n'
          'OLLAMA_MODELS=/Volumes/Second Drive/With Spaces/models\n'
          'OLLAMA_HOST=127.0.0.1:11434\n',
        );
        final execArgs = buildMacosEnvFileExecArgs(envFile.path, [
          '/bin/sh',
          '-c',
          'printf "%s" "\$OLLAMA_MODELS"',
        ]);
        final runRes = await Process.run(execArgs.first, execArgs.sublist(1));
        expect(runRes.exitCode, 0, reason: '${runRes.stderr}');
        expect(runRes.stdout, '/Volumes/Second Drive/With Spaces/models');
      },
    );

    test(
      'macosLaunchctlControl uses bootout for KeepAlive stop and print+bootstrap before kickstart',
      () async {
        final tmp = Directory.systemTemp.createTempSync('maprisma-launchctl-');
        addTearDown(() => tmp.deleteSync(recursive: true));
        final plist =
            File('${tmp.path}/Library/LaunchAgents/com.maprisma.ollama.plist')
              ..parent.createSync(recursive: true)
              ..writeAsStringSync(
                buildLaunchAgentPlist(
                  label: 'com.maprisma.ollama',
                  programArguments: ['/Users/uwe/.local/bin/ollama', 'serve'],
                ),
              );

        // 1. Stop: bootout service target fails -> falls back to bootout plist path (never `launchctl stop`).
        final calls = <List<String>>[];
        final stopRes = await macosLaunchctlControl(
          service: 'com.maprisma.ollama',
          action: 'stop',
          uid: 501,
          home: tmp.path,
          run: (argv) async {
            calls.add(argv);
            if (argv.length == 3 && argv[1] == 'bootout') {
              return (false, 'Could not find specified service');
            }
            return (true, '');
          },
        );
        expect(stopRes.$1, isTrue);
        expect(
          calls,
          equals([
            ['/bin/launchctl', 'bootout', 'gui/501/com.maprisma.ollama'],
            ['/bin/launchctl', 'bootout', 'gui/501', plist.path],
          ]),
        );

        // 2. Start when unloaded: print fails -> bootstrap plist -> kickstart -k.
        calls.clear();
        final startUnloaded = await macosLaunchctlControl(
          service: 'com.maprisma.ollama',
          action: 'start',
          uid: 501,
          home: tmp.path,
          run: (argv) async {
            calls.add(argv);
            if (argv[1] == 'print') return (false, 'not loaded');
            return (true, '');
          },
        );
        expect(startUnloaded.$1, isTrue);
        expect(
          calls,
          equals([
            ['/bin/launchctl', 'print', 'gui/501/com.maprisma.ollama'],
            ['/bin/launchctl', 'bootstrap', 'gui/501', plist.path],
            [
              '/bin/launchctl',
              'kickstart',
              '-k',
              'gui/501/com.maprisma.ollama',
            ],
          ]),
        );

        // 3. Start when already loaded: print succeeds -> kickstart -k directly.
        calls.clear();
        final startLoaded = await macosLaunchctlControl(
          service: 'com.maprisma.ollama',
          action: 'start',
          uid: 501,
          home: tmp.path,
          run: (argv) async {
            calls.add(argv);
            return (true, '');
          },
        );
        expect(startLoaded.$1, isTrue);
        expect(
          calls,
          equals([
            ['/bin/launchctl', 'print', 'gui/501/com.maprisma.ollama'],
            [
              '/bin/launchctl',
              'kickstart',
              '-k',
              'gui/501/com.maprisma.ollama',
            ],
          ]),
        );
      },
    );

    test('parses macOS ps -o time= cumulative CPU durations into seconds', () {
      expect(parseMacosPsCpuSeconds('0:03.42'), closeTo(3.42, 1e-6));
      expect(parseMacosPsCpuSeconds('125:04.12'), closeTo(7504.12, 1e-6));
      expect(parseMacosPsCpuSeconds('1:02:03.45'), closeTo(3723.45, 1e-6));
      expect(parseMacosPsCpuSeconds('2-03:04:05.50'), closeTo(183845.50, 1e-6));
      expect(parseMacosPsCpuSeconds('bad'), isNull);

      final table = parseMacosPsCpuTimes(
        '  4201   0:12.50\n  4202 1:00:00.00\n',
      );
      expect(table[4201], closeTo(12.5, 1e-6));
      expect(table[4202], closeTo(3600.0, 1e-6));
    });

    test('macosOwnPort enforces IPv4 and localhost loopback family coverage', () {
      // IPv6-only `[::1]` listener leaves 127.0.0.1 uncovered -> must be rejected!
      const v6Only = 'p100\nu501\nn[::1]:8080\n';
      expect(macosOwnPort(8080, 501, lsofOutput: v6Only), isFalse);
      expect(
        macosOwnPort(8080, 501, lsofOutput: v6Only, localhost: true),
        isFalse,
      );

      // IPv4-only `127.0.0.1` listener covers 127.0.0.1, but not `localhost` dual-family:
      const v4Only = 'p100\nu501\nn127.0.0.1:8080\n';
      expect(macosOwnPort(8080, 501, lsofOutput: v4Only), isTrue);
      expect(
        macosOwnPort(8080, 501, lsofOutput: v4Only, localhost: true),
        isFalse,
      );

      // Wildcard `*` owned solely by 501 covers both:
      const wildcardOwn = 'p100\nu501\nn*:8080\n';
      expect(macosOwnPort(8080, 501, lsofOutput: wildcardOwn), isTrue);
      expect(
        macosOwnPort(8080, 501, lsofOutput: wildcardOwn, localhost: true),
        isTrue,
      );

      // Both 127.0.0.1 and [::1] owned by 501 covers both:
      const bothOwn = 'p100\nu501\nn127.0.0.1:8080\nn[::1]:8080\n';
      expect(macosOwnPort(8080, 501, lsofOutput: bothOwn), isTrue);
      expect(
        macosOwnPort(8080, 501, lsofOutput: bothOwn, localhost: true),
        isTrue,
      );
    });
  });
}
