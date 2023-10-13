import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keri/keri.dart';
import 'package:keri_windows/exceptions.dart';
import 'dart:convert';
import 'package:convert/convert.dart';

import 'package:path/path.dart';
//import 'package:test/expect.dart' as ex;

import 'package:cryptography/cryptography.dart';

Future<void> main() async {
// void main() {

  final api =
      KeriDartImpl(loadLibForDart("../../target/release/libdartkeriox.so"));
  final algorithm = Ed25519();
  final keyPair0 = await algorithm.newKeyPair();
  final keyPair1 = await algorithm.newKeyPair();
  final b64_current_key =
      base64Url.encode((await keyPair0.extractPublicKey()).bytes);
  final b64_next_key =
      base64Url.encode((await keyPair1.extractPublicKey()).bytes);

  final verifierKeyPair0 = await algorithm.newKeyPair();
  final verifierKeyPair1 = await algorithm.newKeyPair();
  final verifier_b64_current_key =
      base64Url.encode((await verifierKeyPair0.extractPublicKey()).bytes);
  final verifier_b64_next_key =
      base64Url.encode((await verifierKeyPair1.extractPublicKey()).bytes);

  // Generate a key pair

  // Sign a message
  final message = <int>[1, 2, 3];
  final signature = await algorithm.sign(
    message,
    keyPair: keyPair0,
  );
  print('Signature bytes: ${signature.bytes}');
  print('Public key: ${signature}');
  print('keypair: ${keyPair0}');

  // Anyone can verify the signature
  final isSignatureCorrect = await algorithm.verify(
    message,
    signature: signature,
  );

  Future<void> collect_receipts(identifier, witnesses, keypair) async {
    api.notifyWitnesses(identifier: identifier);

    var query = await api.queryMailbox(
        whoAsk: identifier, aboutWho: identifier, witness: witnesses);

    for (final qry in query) {
      var raw_signature = await algorithm.sign(
        utf8.encode(qry),
        keyPair: keypair,
      );
      var hex_signature = await api.signatureFromHex(
          st: SignatureType.Ed25519Sha512,
          signature: hex.encode(raw_signature.bytes));
      await api.finalizeQuery(
          identifier: identifier, queryEvent: qry, signature: hex_signature);
    }
  }

  test('Test verification', () async {
    final current = await api
        .newPublicKey(kt: KeyType.Ed25519, keyB64UrlSafe: b64_current_key)
        .catchError((onError) {
      expect(onError.toString(), 'error');
    });

    final testDirectory = join(
      Directory.current.path,
      Directory.current.path.endsWith('test') ? '' : 'test/db1',
    );
    print(testDirectory);

    var current_keys = [current];
    print("${current.publicKey}");
    var next = await api
        .newPublicKey(kt: KeyType.Ed25519, keyB64UrlSafe: b64_next_key)
        .catchError((onError) {
      expect(onError.toString(), 'error');
    });
    var next_keys = [next];
    print("${next.publicKey}");
    // var witness_oobi = ['{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}'];
    var witness_oobi = [
      '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}'
    ];
    var witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC";
    print("${witness_oobi[0]}");
    await api.initKel(inputAppDir: testDirectory);

    // Setup signing identifier
    var icp_event = await api.incept(
        publicKeys: current_keys,
        nextPubKeys: next_keys,
        witnesses: witness_oobi,
        witnessThreshold: 1);

    var raw_signature = await algorithm.sign(
      utf8.encode(icp_event),
      keyPair: keyPair0,
    );
    var hex_signature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(raw_signature.bytes));

    var signing_identifier =
        await api.finalizeInception(event: icp_event, signature: hex_signature);

    await collect_receipts(signing_identifier, [witness_id], keyPair0);

    // Setup TEL
    var ixn = await api.inceptRegistry(identifier: signing_identifier);

    raw_signature = await algorithm.sign(
      utf8.encode(ixn.ixn),
      keyPair: keyPair0,
    );
    hex_signature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(raw_signature.bytes));

    await api.finalizeEvent(
        identifier: signing_identifier,
        event: ixn.ixn,
        signature: hex_signature);
    await collect_receipts(signing_identifier, [witness_id], keyPair0);

    var kel = await api.getKel(identifier: signing_identifier);
    print("kel: ${kel}");

    // Sign message
    var message = '{"m":"hello there"}';

    raw_signature = await algorithm.sign(
      utf8.encode(message),
      keyPair: keyPair0,
    );
    hex_signature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(raw_signature.bytes));

    var signed = await api.signToCesr(
        identifier: signing_identifier,
        data: message,
        signature: hex_signature);
    print("Signed: ${signed}");

    // var credential = await api.issueCredential(identifier: signing_identifier, credential: message);

    // await api.finalizeEvent(identifier: signing_identifier, event: ixn.ixn, signature: hex_signature);
    // await collect_receipts(signing_identifier, [witness_id], keyPair0);

    // await api.notifyBackers(identifier: signing_identifier);

    // Setup verifying identifier
    var verifierDbPath = join(
      Directory.current.path,
      Directory.current.path.endsWith('test') ? '' : 'test/db2',
    );

    await api.changeController(dbPath: verifierDbPath);

    current_keys = [
      await api
          .newPublicKey(
              kt: KeyType.Ed25519, keyB64UrlSafe: verifier_b64_current_key)
          .catchError((onError) {
        expect(onError.toString(), 'error');
      })
    ];
    next_keys = [
      await api
          .newPublicKey(
              kt: KeyType.Ed25519, keyB64UrlSafe: verifier_b64_next_key)
          .catchError((onError) {
        expect(onError.toString(), 'error');
      })
    ];

    icp_event = await api.incept(
        publicKeys: current_keys,
        nextPubKeys: next_keys,
        witnesses: witness_oobi,
        witnessThreshold: 1);

    raw_signature = await algorithm.sign(
      utf8.encode(icp_event),
      keyPair: verifierKeyPair0,
    );
    hex_signature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(raw_signature.bytes));

    var verifyingIdentifier =
        await api.finalizeInception(event: icp_event, signature: hex_signature);

    await collect_receipts(verifyingIdentifier, [witness_id], verifierKeyPair0);

    // Setup watcher
    // var watcherOobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    var watcherOobi =
        '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}';
    var add_watcher = await api.addWatcher(
        identifier: verifyingIdentifier, watcherOobi: watcherOobi);
    print("\n add watcher: ${add_watcher}");

    raw_signature = await algorithm.sign(
      utf8.encode(add_watcher),
      keyPair: verifierKeyPair0,
    );
    hex_signature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(raw_signature.bytes));

    await api.finalizeEvent(
        identifier: verifyingIdentifier,
        event: add_watcher,
        signature: hex_signature);

    var issuer_oobi =
        '{"cid":"${signing_identifier.id}","role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}';
    print(issuer_oobi);

    var issuer_oobis = "${witness_oobi[0]}$issuer_oobi";
    print("rrr: ${issuer_oobis}");

    try {
      await api.verifyFromCesr(stream: signed);
    } catch (e) {
      expect(e.toString().contains("Verification failed"), true);
    }
    ;

    // var result = ;
    // print(result);

    await api.sendOobiToWatcher(
        identifier: verifyingIdentifier, oobisJson: issuer_oobi);
    var query = await api.queryWatchers(
        whoAsk: verifyingIdentifier, aboutWho: signing_identifier);

    for (final qry in query) {
      var raw_signature = await algorithm.sign(
        utf8.encode(qry),
        keyPair: verifierKeyPair0,
      );
      var hex_signature = await api.signatureFromHex(
          st: SignatureType.Ed25519Sha512,
          signature: hex.encode(raw_signature.bytes));
      await api.finalizeQuery(
          identifier: verifyingIdentifier,
          queryEvent: qry,
          signature: hex_signature);
    }

    var result = await api.verifyFromCesr(stream: signed);
    print(result);
  });
}
