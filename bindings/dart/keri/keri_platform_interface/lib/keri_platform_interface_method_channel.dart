import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'bridge_generated.dart';
import 'keri_platform_interface.dart';

/// An implementation of [KeriPlatformInterfacePlatform] that uses method channels.
class MethodChannelKeriPlatformInterface extends KeriPlatformInterface {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('keri_platform_interface');

  ///Initializes database for storing events.
  Future<bool> initKel(
      {required String inputAppDir,
      Config? optionalConfigs,
      dynamic hint}) async {
    return false;
  }

  ///Creates inception event that needs to be signed externally.
  Future<String> incept(
      {required List<PublicKey> publicKeys,
      required List<PublicKey> nextPubKeys,
      required List<String> witnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    return 'default string - incept';
  }

  ///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
  Future<Identifier> finalizeInception(
      {required String event,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError('finalizeInception() has not been implemented.');
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
    return 'default string - rotate';
  }

  ///Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
  Future<String> addWatcher(
      {required Identifier controller,
      required String watcherOobi,
      dynamic hint}) async {
    return 'default string - addWatcher';
  }

  ///Verifies provided signatures against event and saves it.
  Future<bool> finalizeEvent(
      {required Identifier identifier,
      required String event,
      required Signature signature,
      dynamic hint}) async {
    return false;
  }

  ///Checks and saves provided identifier's endpoint information.
  Future<bool> resolveOobi({required String oobiJson, dynamic hint}) async {
    return false;
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  Future<String> getKel({required Identifier cont, dynamic hint}) async {
    return 'default string - getKel';
  }

  /// Returns pairs: public key encoded in base64 and signature encoded in hex.
  Future<List<PublicKeySignaturePair>> getCurrentPublicKey(
      {required String attachment, dynamic hint}) async {
    throw UnimplementedError('getCurrentPublicKey() has not been implemented.');
  }

  ///Creates new Interaction Event along with provided Self Addressing Identifiers.
  Future<String> anchorDigest(
      {required Identifier controller,
      required List<String> sais,
      dynamic hint}) async {
    return 'default string - anchorDigest';
  }

  ///Creates new Interaction Event along with arbitrary data.
  Future<String> anchor(
      {required Identifier controller,
      required String data,
      required DigestType algo,
      dynamic hint}) async {
    return 'default string - anchor';
  }

  ///Creates new Identifier from string
  Future<Identifier> newIdentifier(
      {required String idStr, dynamic hint}) async {
    throw UnimplementedError('newIdentifier() has not been implemented.');
  }

  Future<List<String>> queryMailbox(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      required List<String> witness,
      dynamic hint}) async {
    return [];
  }

  Future<Signature> signatureFromHex(
      {required SignatureType st,
      required String signature,
      dynamic hint}) async {
    throw UnimplementedError('signatureFromHex() has not been implemented.');
  }

  Future<GroupInception> inceptGroup(
      {required Identifier identifier,
      required List<Identifier> participants,
      required int signatureThreshold,
      required List<String> initialWitnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    throw UnimplementedError('inceptGroup() has not been implemented.');
  }

  Future<Identifier> finalizeGroupIncept(
      {required Identifier identifier,
      required String groupEvent,
      required Signature signature,
      required List<DataAndSignature> toForward,
      dynamic hint}) async {
    throw UnimplementedError('finalizeGroupIncept() has not been implemented.');
  }

  Future<PublicKey> newPublicKey(
      {required KeyType kt, required String keyB64, dynamic hint}) async {
    throw UnimplementedError('newPublicKey() has not been implemented.');
  }

  Future<DataAndSignature> newDataAndSignature(
      {required String data,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError('newDataAndSignature() has not been implemented.');
  }

  Future<bool> changeController({required String dbPath, dynamic hint}) async {
    throw UnimplementedError('changeController() has not been implemented.');
  }

  Future<void> processStream({required String stream, dynamic hint}) async {
    throw UnimplementedError('processStream() has not been implemented.');
  }

  Future<bool> sendOobiToWatcher(
      {required Identifier identifier,
      required String oobisJson,
      dynamic hint}) {
    throw UnimplementedError('sendOobiToWatcher() has not been implemented.');
  }

  Future<List<String>> queryWatchers(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      dynamic hint}) {
    throw UnimplementedError('queryWatchers() has not been implemented.');
  }

  Future<List<ActionRequired>> finalizeQuery(
      {required Identifier identifier,
      required String queryEvent,
      required Signature signature,
      dynamic hint}) {
    throw UnimplementedError('finalizeQuery() has not been implemented.');
  }
}
