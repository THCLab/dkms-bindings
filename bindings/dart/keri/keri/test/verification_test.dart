import 'dart:convert';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keri/keri.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  final api =
      KeriDartImpl(loadLibForDart("../../target/release/libdartkeriox.so"));
  final algorithm = Ed25519();
  final signerKeyPair0 = await algorithm.newKeyPair();
  final signerKeyPair1 = await algorithm.newKeyPair();
  final b64CurrentKey =
      base64Url.encode((await signerKeyPair0.extractPublicKey()).bytes);
  final b64NextKey =
      base64Url.encode((await signerKeyPair1.extractPublicKey()).bytes);

  final verifierKeyPair0 = await algorithm.newKeyPair();
  final verifierKeyPair1 = await algorithm.newKeyPair();
  final verifierB64CurrentKey =
      base64Url.encode((await verifierKeyPair0.extractPublicKey()).bytes);
  final verifierB64NextKey =
      base64Url.encode((await verifierKeyPair1.extractPublicKey()).bytes);

  // Helper function for publishing KEL events to Witnesses.
  Future<void> collectReceipts(identifier, witnesses, keyPair) async {
    await api.notifyWitnesses(identifier: identifier);

    var query = await api.queryMailbox(
        whoAsk: identifier, aboutWho: identifier, witness: witnesses);

    for (final qry in query) {
      var rawSignature = await algorithm.sign(
        utf8.encode(qry),
        keyPair: keyPair,
      );
      var hexSignature = await api.signatureFromHex(
          st: SignatureType.Ed25519Sha512,
          signature: hex.encode(rawSignature.bytes));
      await api.finalizeQuery(
          identifier: identifier, queryEvent: qry, signature: hexSignature);
    }
  }

  test('Test verification', () async {
    final current = await api
        .newPublicKey(kt: KeyType.Ed25519, keyB64UrlSafe: b64CurrentKey)
        .catchError((onError) {
      expect(onError.toString(), 'error');
    });

    final testDirectory = await Directory.systemTemp.createTemp("sig_test");

    var currentKeys = [current];
    var next = await api
        .newPublicKey(kt: KeyType.Ed25519, keyB64UrlSafe: b64NextKey)
        .catchError((onError) {
      expect(onError.toString(), 'error');
    });
    var nextKeys = [next];
    var witnessOobi = [
      '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}'
    ];
    // var witnessOobi = [
    //   '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}'
    // ];
    var witnessId = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC";
    await api.initKel(inputAppDir: testDirectory.path);

    // Setup signing identifier
    var icpEvent = await api.incept(
        publicKeys: currentKeys,
        nextPubKeys: nextKeys,
        witnesses: witnessOobi,
        witnessThreshold: 1);

    var rawSignature = await algorithm.sign(
      utf8.encode(icpEvent),
      keyPair: signerKeyPair0,
    );
    var hexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(rawSignature.bytes));

    var signingIdentifier =
        await api.finalizeInception(event: icpEvent, signature: hexSignature);

    await collectReceipts(signingIdentifier, [witnessId], signerKeyPair0);

    // Setup TEL
    var ixn = await api.inceptRegistry(identifier: signingIdentifier);

    rawSignature = await algorithm.sign(
      utf8.encode(ixn.ixn),
      keyPair: signerKeyPair0,
    );
    hexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(rawSignature.bytes));

    await api.finalizeEvent(
        identifier: signingIdentifier, event: ixn.ixn, signature: hexSignature);
    await collectReceipts(signingIdentifier, [witnessId], signerKeyPair0);

    // Sign message
    var message = '{"i":"${signingIdentifier.id}","m":"hello there"}';
    print("\n\nmessage: ${message}");

    var credential = await api.issueCredential(
        identifier: signingIdentifier, credential: message);

    rawSignature = await algorithm.sign(
      utf8.encode(credential.ixn),
      keyPair: signerKeyPair0,
    );
    hexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(rawSignature.bytes));

    await api.finalizeEvent(
        identifier: signingIdentifier,
        event: credential.ixn,
        signature: hexSignature);
    await collectReceipts(signingIdentifier, [witnessId], signerKeyPair0);

    await api.notifyBackers(identifier: signingIdentifier);

    // Setup verifying identifier
    final verTestDirectory = await Directory.systemTemp.createTemp("ver_test");

    await api.changeController(dbPath: verTestDirectory.path);

    currentKeys = [
      await api
          .newPublicKey(
              kt: KeyType.Ed25519, keyB64UrlSafe: verifierB64CurrentKey)
          .catchError((onError) {
        expect(onError.toString(), 'error');
      })
    ];
    nextKeys = [
      await api
          .newPublicKey(kt: KeyType.Ed25519, keyB64UrlSafe: verifierB64NextKey)
          .catchError((onError) {
        expect(onError.toString(), 'error');
      })
    ];

    icpEvent = await api.incept(
        publicKeys: currentKeys,
        nextPubKeys: nextKeys,
        witnesses: witnessOobi,
        witnessThreshold: 1);

    rawSignature = await algorithm.sign(
      utf8.encode(icpEvent),
      keyPair: verifierKeyPair0,
    );

    hexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(rawSignature.bytes));

    var verifyingIdentifier =
        await api.finalizeInception(event: icpEvent, signature: hexSignature);

    await collectReceipts(verifyingIdentifier, [witnessId], verifierKeyPair0);

    // Setup watcher
    var watcherOobi =
        '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    // var watcherOobi =
    //     '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}';
    var add_watcher = await api.addWatcher(
        identifier: verifyingIdentifier, watcherOobi: watcherOobi);

    rawSignature = await algorithm.sign(
      utf8.encode(add_watcher),
      keyPair: verifierKeyPair0,
    );
    hexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(rawSignature.bytes));

    await api.finalizeEvent(
        identifier: verifyingIdentifier,
        event: add_watcher,
        signature: hexSignature);

    var issuer_oobi =
        '{"cid":"${signingIdentifier.id}","role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}';
    print(issuer_oobi);

    var st = await api.getCredentialState(
        identifier: verifyingIdentifier, credentialSaid: credential.vcId);
    expect(st, null);

    await api.sendOobiToWatcher(
        identifier: verifyingIdentifier, oobisJson: witnessOobi[0]);
    await api.sendOobiToWatcher(
        identifier: verifyingIdentifier, oobisJson: issuer_oobi);
    var query = await api.queryWatchers(
        whoAsk: verifyingIdentifier, aboutWho: signingIdentifier);

    for (final qry in query) {
      var rawSignature = await algorithm.sign(
        utf8.encode(qry),
        keyPair: verifierKeyPair0,
      );
      var hexSignature = await api.signatureFromHex(
          st: SignatureType.Ed25519Sha512,
          signature: hex.encode(rawSignature.bytes));
      await api.finalizeQuery(
          identifier: verifyingIdentifier,
          queryEvent: qry,
          signature: hexSignature);
    }

    var telQry = await api.queryTel(
        identifier: verifyingIdentifier,
        registryId: ixn.registryId,
        credentialSaid: credential.vcId);

    var telRawSignature = await algorithm.sign(
      utf8.encode(telQry),
      keyPair: verifierKeyPair0,
    );
    var telHexSignature = await api.signatureFromHex(
        st: SignatureType.Ed25519Sha512,
        signature: hex.encode(telRawSignature.bytes));
    await api.finalizeTelQuery(
        identifier: verifyingIdentifier,
        queryEvent: telQry,
        signature: telHexSignature);

    st = await api.getCredentialState(
        identifier: verifyingIdentifier, credentialSaid: credential.vcId);
    expect(st?.contains("Issued"), true);
  });
}
