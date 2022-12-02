import 'package:keri_platform_interface/keri_platform_interface_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'bridge_generated.dart';

abstract class KeriPlatformInterface extends PlatformInterface {
  KeriPlatformInterface() : super(token: _token);

  static final Object _token = Object();

  static KeriPlatformInterface _instance = MethodChannelKeriPlatformInterface();

  /// The default instance of [KeriPlatformInterface] to use.
  ///
  /// Defaults to [MethodChannelKeriPlatformInterface].
  static KeriPlatformInterface get instance => _instance;

  static set instance(KeriPlatformInterface instance) {
    PlatformInterface.verify(instance, _token);
    _instance = instance;
  }

  ///Initializes database for storing events.
  Future<bool> initKel(
      {required String inputAppDir,
      Config? optionalConfigs,
      dynamic hint}) async {
    throw UnimplementedError('initKel() has not been implemented.');
  }

  ///Creates inception event that needs to be signed externally.
  Future<String> incept(
      {required List<PublicKey> publicKeys,
      required List<PublicKey> nextPubKeys,
      required List<String> witnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    throw UnimplementedError('incept() has not been implemented.');
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
    throw UnimplementedError('rotate() has not been implemented.');
  }

  ///Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
  Future<String> addWatcher(
      {required Identifier controller,
      required String watcherOobi,
      dynamic hint}) async {
    throw UnimplementedError('addWatcher() has not been implemented.');
  }

  ///Verifies provided signatures against event and saves it.
  Future<bool> finalizeEvent(
      {required Identifier identifier,
      required String event,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError('finalizeEvent() has not been implemented.');
  }

  ///Checks and saves provided identifier's endpoint information.
  Future<bool> resolveOobi({required String oobiJson, dynamic hint}) async {
    throw UnimplementedError('resolveOobi() has not been implemented.');
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  Future<String> getKel({required Identifier cont, dynamic hint}) async {
    throw UnimplementedError('getKel() has not been implemented.');
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
    throw UnimplementedError('anchorDigest() has not been implemented.');
  }

  ///Creates new Interaction Event along with arbitrary data.
  Future<String> anchor(
      {required Identifier controller,
      required String data,
      required DigestType algo,
      dynamic hint}) async {
    throw UnimplementedError('anchor() has not been implemented.');
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
    throw UnimplementedError('queryMailbox() has not been implemented.');
  }

  Future<List<ActionRequired>> finalizeMailboxQuery(
      {required Identifier identifier,
      required String queryEvent,
      required Signature signature,
      dynamic hint}) async {
    throw UnimplementedError(
        'finalizeMailboxQuery() has not been implemented.');
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
}
