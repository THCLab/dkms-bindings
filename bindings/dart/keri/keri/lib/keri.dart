import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri_platform_interface/keri_platform_interface.dart';
import 'package:keri_platform_interface/bridge_generated.dart';
export 'package:keri_platform_interface/bridge_generated.dart';

///Initializes database for storing events.
Future<bool> initKel(
    {required String inputAppDir,
    Config? optionalConfigs,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance.initKel(inputAppDir: inputAppDir);
}

///Creates inception event that needs to be signed externally.
Future<String> incept(
    {required List<PublicKey> publicKeys,
    required List<PublicKey> nextPubKeys,
    required List<String> witnesses,
    required int witnessThreshold,
    dynamic hint}) async {

    return await KeriPlatformInterface.instance.incept(
        publicKeys: publicKeys,
        nextPubKeys: nextPubKeys,
        witnesses: witnesses,
        witnessThreshold: witnessThreshold);
}

///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
Future<Identifier> finalizeInception(
    {required String event, required Signature signature, dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .finalizeInception(event: event, signature: signature);
}

///Creates rotation event that needs to be signed externally.
Future<String> rotate(
    {required Identifier controller,
    required List<PublicKey> currentKeys,
    required List<PublicKey> newNextKeys,
    required List<String> witnessToAdd,
    required List<String> witnessToRemove,
    required int witnessThreshold,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance.rotate(
        controller: controller,
        currentKeys: currentKeys,
        newNextKeys: newNextKeys,
        witnessToAdd: witnessToAdd,
        witnessToRemove: witnessToRemove,
        witnessThreshold: witnessThreshold);
}

///Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
Future<String> addWatcher(
    {required Identifier controller,
    required String watcherOobi,
    dynamic hint}) async {

    return await KeriPlatformInterface.instance
        .addWatcher(controller: controller, watcherOobi: watcherOobi);
}

///Verifies provided signatures against event and saves it.
Future<bool> finalizeEvent(
    {required Identifier identifier,
    required String event,
    required Signature signature,
    dynamic hint}) async {

    return await KeriPlatformInterface.instance.finalizeEvent(
        identifier: identifier, event: event, signature: signature);
}

///Checks and saves provided identifier's endpoint information.
Future<bool> resolveOobi({required String oobiJson, dynamic hint}) async {

    return await KeriPlatformInterface.instance.resolveOobi(oobiJson: oobiJson);
}

///Query designated watcher about other identifier's public keys data.
// static Future<bool> query(
//     {required Identifier controller,
//     required String oobisJson,
//     dynamic hint}) async {
//   try {
//     return await api.query(identifier: controller, oobisJson: oobisJson);
//   } on FfiException catch (e) {
//     if (e.message.contains('Deserialize error')) {
//       throw IdentifierException(
//           'The identifier provided to the controller is incorrect. Check the identifier once again.');
//     }
//     if (e.message.contains('Unknown id')) {
//       throw IdentifierException(
//           'Unknown controller identifier. Check the confroller for identifier once again.');
//     }
//     if (e.message.contains('Can\'t parse controller')) {
//       throw IdentifierException(
//           'Can\'t parse controller prefix. Check the confroller for identifier once again.');
//     }
//     if (e.message.contains('error sending request for url')) {
//       throw OobiResolvingErrorException(
//           "No service is listening under the provided port number. Consider changing it.");
//     }
//     if (e.message.contains('Controller wasn\'t initialized')) {
//       throw ControllerNotInitializedException(
//           "Controller has not been initialized. Execute initKel() before incepting.");
//     }
//     if (e.message.contains('Signature verification failed')) {
//       throw SignatureVerificationException(
//           'Signature verification failed - event signature does not match event keys.');
//     }
//     if (e.message.contains('Can\'t parse oobi json')) {
//       throw IncorrectOobiException(
//           'Provided oobi is incorrect. Please check the JSON once again');
//     }
//     rethrow;
//   }
// }

//CZY JEST POTRZEBNA?
Future<void> processStream({required String stream, dynamic hint}) async {
  await KeriPlatformInterface.instance.processStream(stream: stream);
}

///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
Future<String> getKel({required Identifier cont, dynamic hint}) async {
    return await KeriPlatformInterface.instance.getKel(cont: cont);
}

/// Returns pairs: public key encoded in base64 and signature encoded in hex.
Future<List<PublicKeySignaturePair>> getCurrentPublicKey(
    {required String attachment, dynamic hint}) async {

    return await KeriPlatformInterface.instance
        .getCurrentPublicKey(attachment: attachment);
}

///Creates new Interaction Event along with provided Self Addressing Identifiers.
Future<String> anchorDigest(
    {required Identifier controller,
    required List<String> sais,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .anchorDigest(controller: controller, sais: sais);
}

///Creates new Interaction Event along with arbitrary data.
Future<String> anchor(
    {required Identifier controller,
    required String data,
    required DigestType algo,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .anchor(controller: controller, data: data, algo: algo);
}

Future<Identifier> newIdentifier({required String idStr, dynamic hint}) async {
    return await KeriPlatformInterface.instance.newIdentifier(idStr: idStr);
}

//ToDo
Future<List<String>> queryMailbox(
    {required Identifier whoAsk,
    required Identifier aboutWho,
    required List<String> witness,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .queryMailbox(whoAsk: whoAsk, aboutWho: aboutWho, witness: witness);
}

//ToDo
Future<List<ActionRequired>> finalizeMailboxQuery(
    {required Identifier identifier,
    required String queryEvent,
    required Signature signature,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance.finalizeMailboxQuery(
        identifier: identifier, queryEvent: queryEvent, signature: signature);
}

Future<Signature> signatureFromHex(
    {required SignatureType st,
    required String signature,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .signatureFromHex(st: st, signature: signature);
}

Future<GroupInception> inceptGroup(
    {required Identifier identifier,
    required List<Identifier> participants,
    required int signatureThreshold,
    required List<String> initialWitnesses,
    required int witnessThreshold,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance.inceptGroup(
        identifier: identifier,
        participants: participants,
        signatureThreshold: signatureThreshold,
        initialWitnesses: initialWitnesses,
        witnessThreshold: witnessThreshold);
}

Future<Identifier> finalizeGroupIncept(
    {required Identifier identifier,
    required String groupEvent,
    required Signature signature,
    required List<DataAndSignature> toForward,
    dynamic hint}) async {
    return await KeriPlatformInterface.instance.finalizeGroupIncept(
        identifier: identifier,
        groupEvent: groupEvent,
        signature: signature,
        toForward: toForward);
}

Future<PublicKey> newPublicKey(
    {required KeyType kt, required String keyB64, dynamic hint}) async {
    return await KeriPlatformInterface.instance
        .newPublicKey(kt: kt, keyB64: keyB64);
}

Future<DataAndSignature> newDataAndSignature(
    {required String data, required Signature signature, dynamic hint}) async {
  return await KeriPlatformInterface.instance
      .newDataAndSignature(data: data, signature: signature);
}

Future<bool> changeController({required String dbPath, dynamic hint}) async {
  return await KeriPlatformInterface.instance.changeController(dbPath: dbPath);
}
