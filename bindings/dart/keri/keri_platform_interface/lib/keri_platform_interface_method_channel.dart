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
  @override
  Future<bool> initKel(
      {required String inputAppDir,
      Config? optionalConfigs,
      dynamic hint}) async {
    return false;
  }

  ///Creates inception event that needs to be signed externally.
  @override
  Future<String> incept(
      {required List<PublicKey> publicKeys,
      required List<PublicKey> nextPubKeys,
      required List<String> witnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    return 'default string - incept';
  }

  ///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
  @override
  Future<Identifier> finalizeInception(
      {required String event,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError('finalizeInception() has not been implemented.');
  }

  ///Creates rotation event that needs to be signed externally.
  @override
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
  @override
  Future<String> addWatcher(
      {required Identifier controller,
      required String watcherOobi,
      dynamic hint}) async {
    return 'default string - addWatcher';
  }

  ///Verifies provided signatures against event and saves it.
  @override
  Future<bool> finalizeEvent(
      {required Identifier identifier,
      required String event,
      required Signature signature,
      dynamic hint}) async {
    return false;
  }

  ///Checks and saves provided identifier's endpoint information.
  @override
  Future<bool> resolveOobi({required String oobiJson, dynamic hint}) async {
    return false;
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  @override
  Future<String> getKel({required Identifier cont, dynamic hint}) async {
    return 'default string - getKel';
  }

  ///Creates new Interaction Event along with provided Self Addressing Identifiers.
  @override
  Future<String> anchorDigest(
      {required Identifier controller,
      required List<String> sais,
      dynamic hint}) async {
    return 'default string - anchorDigest';
  }

  ///Creates new Interaction Event along with arbitrary data.
  @override
  Future<String> anchor(
      {required Identifier controller,
      required String data,
      required DigestType algo,
      dynamic hint}) async {
    return 'default string - anchor';
  }

  ///Creates new Identifier from string
  @override
  Future<Identifier> newIdentifier(
      {required String idStr, dynamic hint}) async {
    throw UnimplementedError('newIdentifier() has not been implemented.');
  }

  @override
  Future<List<String>> queryMailbox(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      required List<String> witness,
      dynamic hint}) async {
    return [];
  }

  @override
  Future<Signature> signatureFromHex(
      {required SignatureType st,
      required String signature,
      dynamic hint}) async {
    throw UnimplementedError('signatureFromHex() has not been implemented.');
  }

  @override
  Future<GroupInception> inceptGroup(
      {required Identifier identifier,
      required List<Identifier> participants,
      required int signatureThreshold,
      required List<String> initialWitnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    throw UnimplementedError('inceptGroup() has not been implemented.');
  }

  @override
  Future<Identifier> finalizeGroupIncept(
      {required Identifier identifier,
      required String groupEvent,
      required Signature signature,
      required List<DataAndSignature> toForward,
      dynamic hint}) async {
    throw UnimplementedError('finalizeGroupIncept() has not been implemented.');
  }

  @override
  Future<PublicKey> newPublicKey(
      {required KeyType kt, required String keyB64, dynamic hint}) async {
    throw UnimplementedError('newPublicKey() has not been implemented.');
  }

  @override
  Future<DataAndSignature> newDataAndSignature(
      {required String data,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError('newDataAndSignature() has not been implemented.');
  }

  @override
  Future<bool> changeController({required String dbPath, dynamic hint}) async {
    throw UnimplementedError('changeController() has not been implemented.');
  }

  @override
  Future<void> processStream({required String stream, dynamic hint}) async {
    throw UnimplementedError('processStream() has not been implemented.');
  }

  @override
  Future<bool> sendOobiToWatcher(
      {required Identifier identifier,
      required String oobisJson,
      dynamic hint}) {
    throw UnimplementedError('sendOobiToWatcher() has not been implemented.');
  }

  @override
  Future<List<String>> queryWatchers(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      dynamic hint}) {
    throw UnimplementedError('queryWatchers() has not been implemented.');
  }

  @override
  Future<List<ActionRequired>> finalizeQuery(
      {required Identifier identifier,
      required String queryEvent,
      required Signature signature,
      dynamic hint}) {
    throw UnimplementedError('finalizeQuery() has not been implemented.');
  }

  @override
  Future<String> signToCesr(
      {required Identifier identifier,
      required String data,
      required Signature signature,
      dynamic hint}) {
    throw UnimplementedError('signToCesr() has not been implemented');
  }

  @override
  Future<bool> verifyFromCesr({required String stream, dynamic hint}) {
    throw UnimplementedError('verifyFromCesr() has not been implemented');
  }

  @override

  /// Splits parsed elements from stream into oobis to resolve and other signed
  /// data.
  Future<SplittingResult> splitOobisAndData(
      {required String stream, dynamic hint}) {
    throw UnimplementedError('splitOobisAndData() has not been implemented');
  }

  Future<RegistryData> inceptRegistry(
      {required Identifier identifier, dynamic hint}) {
    throw UnimplementedError('inceptRegistry() has not been implemented');
  }

  @override
  Future<IssuanceData> issueCredential(
      {required Identifier identifier,
      required String credential,
      dynamic hint}) {
    throw UnimplementedError('issueCredential() has not been implemented');
  }

  @override
  Future<String> revokeCredential(
      {required Identifier identifier,
      required String credentialSaid,
      dynamic hint}) {
    throw UnimplementedError('revokeCredential() has not been implemented');
  }

  @override
  Future<String> queryTel(
      {required Identifier identifier,
      required String registryId,
      required String credentialSaid,
      dynamic hint}) {
    throw UnimplementedError('queryTel() has not been implemented');
  }

  @override
  Future<bool> finalizeTelQuery(
      {required Identifier identifier,
      required String queryEvent,
      required Signature signature,
      dynamic hint}) {
    throw UnimplementedError('finalizeTelQuery() has not been implemented');
  }

  @override
  Future<String?> getCredentialState(
      {required Identifier identifier,
      required String credentialSaid,
      dynamic hint}) {
    throw UnimplementedError('getCredentialState() has not been implemented');
  }

  @override
  Future<bool> notifyBackers({required Identifier identifier, dynamic hint}) {
    throw UnimplementedError('notifyBackers() has not been implemented');
  }

  @override
  Future<String> addMessagebox(
      {required Identifier identifier,
      required String messageboxOobi,
      dynamic hint}) {
    throw UnimplementedError('addMessagebox() has not been implemented');
  }

  @override
  Future<List<String>> getMessagebox({required String whose, dynamic hint}) {
    throw UnimplementedError('getMessagebox() has not been implemented');
  }
}
