import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';

const _keystoreChannel = MethodChannel('com.thclab.keri_android/keystore');

const _defaultWitnessUrls = <String>[
  'https://witness1.dkms.colossi.network',
  'https://witness2.dkms.colossi.network',
  'https://witness3.dkms.colossi.network',
];

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(const SmokeTestApp());
}

class SmokeTestApp extends StatelessWidget {
  const SmokeTestApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'KERI smoke test',
        theme: ThemeData(useMaterial3: true),
        home: const AlgorithmPickerPage(),
      );
}

class AlgorithmPickerPage extends StatelessWidget {
  const AlgorithmPickerPage({super.key});

  void _choose(BuildContext context, String algorithm, String label) {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (_) =>
            SmokeTestPage(algorithm: algorithm, algorithmLabel: label),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Pick signing algorithm')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              'Choose how KERI keys are stored and signed on this device. '
              'You can wipe and switch any time.',
              style: TextStyle(fontSize: 16),
            ),
            const SizedBox(height: 32),
            _AlgoCard(
              title: 'Software — BouncyCastle Ed25519',
              subtitle:
                  'Seed encrypted under an AndroidKeyStore AES-GCM master '
                  'key, biometric-gated. Seed lives in process memory briefly '
                  'during sign() and is cached for 10s to coalesce bursts.',
              chip: 'fallback',
              chipColor: Colors.orange,
              onTap: () => _choose(context, 'Ed25519', 'Ed25519 (software)'),
            ),
            const SizedBox(height: 16),
            _AlgoCard(
              title: 'Hardware — AndroidKeyStore P-256',
              subtitle:
                  'NIST secp256r1, private key generated and held inside the '
                  'TEE/StrongBox. Time-bound biometric auth (10s) enforced by '
                  'KeyMint — no seed exists in app memory.',
              chip: 'native',
              chipColor: Colors.green,
              onTap: () =>
                  _choose(context, 'EcdsaSecp256r1', 'P-256 (hardware)'),
            ),
          ],
        ),
      ),
    );
  }
}

class _AlgoCard extends StatelessWidget {
  const _AlgoCard({
    required this.title,
    required this.subtitle,
    required this.chip,
    required this.chipColor,
    required this.onTap,
  });

  final String title;
  final String subtitle;
  final String chip;
  final Color chipColor;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(title,
                        style:
                            Theme.of(context).textTheme.titleMedium),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: chipColor,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(chip,
                        style: const TextStyle(
                            color: Colors.white, fontSize: 12)),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(subtitle),
            ],
          ),
        ),
      ),
    );
  }
}

class SmokeTestPage extends StatefulWidget {
  const SmokeTestPage({
    super.key,
    required this.algorithm,
    required this.algorithmLabel,
  });
  final String algorithm;
  final String algorithmLabel;
  @override
  State<SmokeTestPage> createState() => _SmokeTestPageState();
}

class _SmokeTestPageState extends State<SmokeTestPage> {
  static const _testKeyLabel = 'demo';
  static const _identAlias = 'alice';

  KeriMobileSdk? _sdk;
  String _bootStatus = 'not initialised';
  String _rustStatus = 'idle';
  String _keystoreStatus = 'idle';
  String _identStatus = 'idle';
  String _rotateStatus = 'idle';
  String _wipeStatus = 'idle';
  String _kelStatus = 'idle';
  String? _kelDump;
  List<String> _rustAliases = const [];
  List<String> _keystoreLabels = const [];
  Uint8List? _lastPublicKey;
  Uint8List? _lastSignature;
  String? _lastAid;

  late final List<TextEditingController> _witnessControllers = [
    for (final url in _defaultWitnessUrls) TextEditingController(text: url),
  ];
  final TextEditingController _witnessThresholdCtrl =
      TextEditingController(text: '1');

  @override
  void dispose() {
    for (final c in _witnessControllers) {
      c.dispose();
    }
    _witnessThresholdCtrl.dispose();
    super.dispose();
  }

  // ------- bootstrap -------

  Future<KeriMobileSdk> _ensureSdk() async {
    final existing = _sdk;
    if (existing != null) return existing;

    setState(() => _bootStatus = 'creating SDK + registering key provider...');
    final docs = await getApplicationDocumentsDirectory();
    final dbDir = Directory('${docs.path}/keri_smoke');
    if (!await dbDir.exists()) await dbDir.create(recursive: true);

    final sdk = await KeriMobileSdk.newInstance(dbPath: dbDir.path);
    await sdk.registerKeyProvider(
      createKey: (label, algo) async {
        final pub = await _keystoreChannel.invokeMethod<Uint8List>(
          'createKey',
          {'label': label, 'algo': algo},
        );
        return pub ?? Uint8List(0);
      },
      openKey: (label) async {
        final pub = await _keystoreChannel.invokeMethod<Uint8List>(
          'getPublicKey',
          {'label': label},
        );
        return pub ?? Uint8List(0);
      },
      sign: (label, msg) async {
        final sig = await _keystoreChannel.invokeMethod<Uint8List>(
          'sign',
          {'label': label, 'message': msg},
        );
        return sig ?? Uint8List(0);
      },
      deleteKey: (label) async {
        await _keystoreChannel.invokeMethod('deleteKey', {'label': label});
      },
      listKeys: () async {
        final keys =
            await _keystoreChannel.invokeMethod<List<dynamic>>('listKeys');
        return (keys ?? const []).cast<String>();
      },
    );

    _sdk = sdk;
    setState(() => _bootStatus = 'SDK ready');
    return sdk;
  }

  List<String> _activeWitnessUrls() => [
        for (final c in _witnessControllers)
          if (c.text.trim().isNotEmpty) c.text.trim(),
      ];

  BigInt _witnessThreshold() {
    final n = int.tryParse(_witnessThresholdCtrl.text.trim()) ?? 0;
    return BigInt.from(n);
  }

  // ------- handlers -------

  Future<void> _refreshRustAliases() async {
    setState(() {
      _rustStatus = 'running...';
      _rustAliases = const [];
    });
    try {
      final sdk = await _ensureSdk();
      final aliases = await sdk.listAliases();
      setState(() {
        _rustAliases = aliases;
        _rustStatus = 'ok — ${aliases.length} aliases';
      });
    } catch (e) {
      setState(() => _rustStatus = 'error: $e');
    }
  }

  Future<void> _listKeystore() async {
    setState(() => _keystoreStatus = 'listing...');
    try {
      final keys =
          await _keystoreChannel.invokeMethod<List<dynamic>>('listKeys');
      setState(() {
        _keystoreLabels = (keys ?? []).cast<String>();
        _keystoreStatus = 'ok — ${_keystoreLabels.length} keys';
      });
    } catch (e) {
      setState(() => _keystoreStatus = 'error: $e');
    }
  }

  Future<void> _createTestKey() async {
    setState(() => _keystoreStatus = 'creating (biometric)...');
    try {
      final pubAtCreate =
          await _keystoreChannel.invokeMethod<Uint8List>('createKey', {
        'label': _testKeyLabel,
        'algo': widget.algorithm,
      });
      final pubAtRead =
          await _keystoreChannel.invokeMethod<Uint8List>('getPublicKey', {
        'label': _testKeyLabel,
      });
      final match = pubAtCreate != null &&
          pubAtRead != null &&
          pubAtCreate.length == pubAtRead.length &&
          List.generate(pubAtCreate.length, (i) => pubAtCreate[i] == pubAtRead[i])
              .every((b) => b);
      setState(() {
        _lastPublicKey = pubAtCreate;
        _keystoreStatus = 'create vs read match=$match\n'
            'create=${_hex(pubAtCreate)}\n'
            'read  =${_hex(pubAtRead)}';
      });
    } catch (e) {
      setState(() => _keystoreStatus = 'error: $e');
    }
  }

  Future<void> _signTest() async {
    setState(() => _keystoreStatus = 'signing (biometric)...');
    try {
      final msg = Uint8List.fromList(utf8.encode('hello keri'));
      final sig = await _keystoreChannel.invokeMethod<Uint8List>('sign', {
        'label': _testKeyLabel,
        'message': msg,
      });
      setState(() {
        _lastSignature = sig;
        _keystoreStatus =
            'signed (${sig?.length ?? 0} bytes). sig=${_hex(sig)}';
      });
    } catch (e) {
      setState(() => _keystoreStatus = 'error: $e');
    }
  }

  Future<void> _deleteTestKey() async {
    setState(() => _keystoreStatus = 'deleting...');
    try {
      await _keystoreChannel
          .invokeMethod('deleteKey', {'label': _testKeyLabel});
      setState(() {
        _lastPublicKey = null;
        _lastSignature = null;
        _keystoreStatus = 'deleted';
      });
      await _listKeystore();
    } catch (e) {
      setState(() => _keystoreStatus = 'error: $e');
    }
  }

  /// Rust mints both current + next via the registered callbacks — expect
  /// two biometric prompts back-to-back, one per key.
  Future<void> _createIdentifier() async {
    setState(() => _identStatus = 'creating identifier (biometric x2)...');
    try {
      final sdk = await _ensureSdk();

      final aid = await sdk.createIdentifier(
        alias: _identAlias,
        config: FfiIdentifierConfig(
          witnessUrls: _activeWitnessUrls(),
          witnessThreshold: _witnessThreshold(),
          watcherUrls: const [],
          algorithm: widget.algorithm,
        ),
      );

      setState(() {
        _lastAid = aid;
        _identStatus = 'AID: $aid';
      });
      await _refreshRustAliases();
      await _listKeystore();
    } catch (e) {
      setState(() => _identStatus = 'error: $e');
    }
  }

  /// Rotation: Rust opens alice_vN as the new current (was the committed
  /// next), mints alice_v(N+1) as the new next, signs, then deletes the
  /// previous alice_v(N-1) from the keystore. Expect two biometric prompts:
  /// one to unlock the old-next-now-current for signing, one to wrap the new
  /// next-key seed.
  Future<void> _rotateIdentifier() async {
    setState(() => _rotateStatus = 'rotating (biometric x2)...');
    try {
      final sdk = await _ensureSdk();
      await sdk.rotateKeys(
        alias: _identAlias,
        config: FfiRotationConfig(
          witnessToAdd: const [],
          witnessToRemove: const [],
          witnessThreshold: _witnessThreshold(),
        ),
      );
      setState(() => _rotateStatus = 'rotated');
      await _listKeystore();
    } catch (e) {
      setState(() => _rotateStatus = 'error: $e');
    }
  }

  /// Clears all on-device state so the create/rotate flow can be re-run:
  ///   1. Rust drops the cached KeriStore (releasing redb's flock) and
  ///      deletes the db directory.
  ///   2. Every label in the AndroidKeystore-backed vault is removed.
  ///   3. UI status fields reset to idle.
  ///
  /// The Rust opaque handle survives; the next "Init SDK" recreates state
  /// against an empty filesystem.
  Future<void> _wipeAll() async {
    setState(() => _wipeStatus = 'wiping...');
    try {
      final sdk = _sdk;
      if (sdk != null) {
        await sdk.wipe();
      }
      final labels =
          (await _keystoreChannel.invokeMethod<List<dynamic>>('listKeys'))
                  ?.cast<String>() ??
              const [];
      for (final l in labels) {
        await _keystoreChannel.invokeMethod('deleteKey', {'label': l});
      }
      setState(() {
        _rustStatus = 'idle';
        _keystoreStatus = 'idle';
        _identStatus = 'idle';
        _rotateStatus = 'idle';
        _rustAliases = const [];
        _keystoreLabels = const [];
        _lastPublicKey = null;
        _lastSignature = null;
        _lastAid = null;
        _wipeStatus =
            'wiped — Rust db deleted, ${labels.length} keystore labels removed';
      });
    } catch (e) {
      setState(() => _wipeStatus = 'error: $e');
    }
  }

  Future<void> _showKel() async {
    setState(() => _kelStatus = 'loading...');
    try {
      final sdk = await _ensureSdk();
      final dump = await sdk.showKel(alias: _identAlias);
      setState(() {
        _kelDump = dump;
        _kelStatus = 'ok';
      });
      if (!mounted) return;
      await showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('KEL for alice'),
          content: SizedBox(
            width: double.maxFinite,
            child: SingleChildScrollView(
              child: SelectableText(
                dump,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } catch (e) {
      setState(() => _kelStatus = 'error: $e');
    }
  }

  void _addWitnessField() {
    setState(() => _witnessControllers.add(TextEditingController()));
  }

  void _removeWitnessField(int index) {
    setState(() => _witnessControllers.removeAt(index).dispose());
  }

  String _hex(Uint8List? data) {
    if (data == null) return '∅';
    final preview = data.length > 16 ? data.sublist(0, 16) : data;
    final hex =
        preview.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return data.length > 16 ? '$hex…(${data.length} bytes)' : hex;
  }

  // ------- UI -------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('KERI smoke test — ${widget.algorithmLabel}'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          tooltip: 'Back to algorithm picker',
          onPressed: () {
            Navigator.of(context).pushReplacement(
              MaterialPageRoute(
                builder: (_) => const AlgorithmPickerPage(),
              ),
            );
          },
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _SectionTitle('Bootstrap'),
            Text('SDK:  $_bootStatus'),
            Text('Wipe: $_wipeStatus'),
            const SizedBox(height: 8),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: Colors.red.shade700,
                foregroundColor: Colors.white,
              ),
              icon: const Icon(Icons.delete_forever),
              label: const Text('Wipe all app data'),
              onPressed: () async {
                final confirmed = await showDialog<bool>(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    title: const Text('Wipe app data?'),
                    content: const Text(
                        'Deletes the Rust KERI database and removes every '
                        'key from the AndroidKeyStore vault. Cannot be undone.'),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: const Text('Cancel'),
                      ),
                      FilledButton.tonal(
                        onPressed: () => Navigator.pop(ctx, true),
                        child: const Text('Wipe'),
                      ),
                    ],
                  ),
                );
                if (confirmed == true) await _wipeAll();
              },
            ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: _ensureSdk,
              child: const Text('Init SDK + register key provider'),
            ),

            const Divider(height: 32),
            const _SectionTitle('Witnesses'),
            for (var i = 0; i < _witnessControllers.length; i++)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _witnessControllers[i],
                        decoration: InputDecoration(
                          labelText: 'witness ${i + 1} URL',
                          isDense: true,
                          border: const OutlineInputBorder(),
                        ),
                      ),
                    ),
                    IconButton(
                      tooltip: 'remove',
                      icon: const Icon(Icons.remove_circle_outline),
                      onPressed: () => _removeWitnessField(i),
                    ),
                  ],
                ),
              ),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                icon: const Icon(Icons.add),
                label: const Text('Add witness'),
                onPressed: _addWitnessField,
              ),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: 160,
              child: TextField(
                controller: _witnessThresholdCtrl,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'witness threshold',
                  isDense: true,
                  border: OutlineInputBorder(),
                ),
              ),
            ),

            const Divider(height: 32),
            const _SectionTitle('End-to-end: createIdentifier / rotateKeys'),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(
                  onPressed: _createIdentifier,
                  child: const Text('Create identifier (alice)'),
                ),
                FilledButton.tonal(
                  onPressed: _rotateIdentifier,
                  child: const Text('Rotate keys (alice)'),
                ),
                OutlinedButton(
                  onPressed: _showKel,
                  child: const Text('Show KEL'),
                ),
                OutlinedButton(
                  onPressed: () async {
                    setState(() => _kelStatus = 'verifying...');
                    try {
                      final sdk = await _ensureSdk();
                      final result =
                          await sdk.verifyNextBinding(alias: _identAlias);
                      setState(() => _kelStatus = 'verify ok');
                      if (!mounted) return;
                      await showDialog(
                        context: context,
                        builder: (ctx) => AlertDialog(
                          title: const Text('Next-key binding check'),
                          content: SingleChildScrollView(
                            child: SelectableText(
                              result,
                              style: const TextStyle(
                                  fontFamily: 'monospace', fontSize: 11),
                            ),
                          ),
                          actions: [
                            TextButton(
                                onPressed: () => Navigator.pop(ctx),
                                child: const Text('Close')),
                          ],
                        ),
                      );
                    } catch (e) {
                      setState(() => _kelStatus = 'verify error: $e');
                    }
                  },
                  child: const Text('Verify next-binding'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text('Create status: $_identStatus'),
            Text('Rotate status: $_rotateStatus'),
            Text('Show KEL:      $_kelStatus'),
            if (_lastAid != null) Text('AID: $_lastAid'),

            const Divider(height: 32),
            const _SectionTitle('Rust FFI inspection'),
            FilledButton(
              onPressed: _refreshRustAliases,
              child: const Text('listAliases() via Rust'),
            ),
            const SizedBox(height: 8),
            Text('Status: $_rustStatus'),
            for (final a in _rustAliases) Text('• $a'),

            const Divider(height: 32),
            const _SectionTitle('Android Keystore (label=demo)'),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: _createTestKey,
                  child: const Text('Create key'),
                ),
                OutlinedButton(
                  onPressed: _signTest,
                  child: const Text('Sign "hello keri"'),
                ),
                OutlinedButton(
                  onPressed: _listKeystore,
                  child: const Text('List keys'),
                ),
                OutlinedButton(
                  onPressed: _deleteTestKey,
                  child: const Text('Delete key'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text('Status: $_keystoreStatus'),
            Text('Last public key: ${_hex(_lastPublicKey)}'),
            Text('Last signature:  ${_hex(_lastSignature)}'),
            const SizedBox(height: 8),
            const Text('Stored labels:'),
            for (final l in _keystoreLabels) Text('• $l'),
          ],
        ),
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(text, style: Theme.of(context).textTheme.titleMedium),
      );
}
