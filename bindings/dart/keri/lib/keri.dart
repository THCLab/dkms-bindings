
import 'dart:ffi';
import 'dart:io';

import 'bridge_generated.dart';

class Keri {
  static const base = 'dartkeriox';
  final path = Platform.isWindows ? '$base.dll' : 'lib$base.so';
  late final dylib = Platform.isIOS
      ? DynamicLibrary.process()
      : Platform.isMacOS
      ? DynamicLibrary.executable()
      : DynamicLibrary.open(path);
  late final api = KeriDartImpl(dylib);


  Future<void> initKel({required String inputAppDir, Config? optionalConfigs, dynamic hint}) async{
    await api.initKel(inputAppDir: inputAppDir);
  }

  Future<String> incept(
      {required List<PublicKey> publicKeys,
        required List<PublicKey> nextPubKeys,
        required List<String> witnesses,
        required int witnessThreshold,
        dynamic hint}) async{
    return await api.incept(publicKeys: publicKeys, nextPubKeys: nextPubKeys, witnesses: witnesses, witnessThreshold: witnessThreshold);
  }

  Future<Controller> finalizeInception(
      {required String event, required Signature signature, dynamic hint}) async{
    return await api.finalizeInception(event: event, signature: signature);
  }

  Future<String> rotate(
      {required Controller controller,
        required List<PublicKey> currentKeys,
        required List<PublicKey> newNextKeys,
        required List<String> witnessToAdd,
        required List<String> witnessToRemove,
        required int witnessThreshold,
        dynamic hint}) async{
    return await api.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: witnessToAdd, witnessToRemove: witnessToRemove, witnessThreshold: witnessThreshold);
  }

  Future<String> addWatcher(
      {required Controller controller,
        required String watcherOobi,
        dynamic hint}) async{
    return await api.addWatcher(controller: controller, watcherOobi: watcherOobi);
  }

  Future<void> finalizeEvent(
      {required Controller identifier,
        required String event,
        required Signature signature,
        dynamic hint}) async{
    await api.finalizeEvent(identifier: identifier, event: event, signature: signature);
  }

  Future<void> resolveOobi({required String oobiJson, dynamic hint}) async{
    await api.resolveOobi(oobiJson: oobiJson);
  }

  Future<void> query(
      {required Controller controller,
        required String oobisJson,
        dynamic hint}) async{
    await api.query(controller: controller, oobisJson: oobisJson);
  }

  Future<void> processStream({required String stream, dynamic hint}) async{
    await api.processStream(stream: stream);
  }

  Future<String> getKel({required Controller cont, dynamic hint}) async{
    return await api.getKel(cont: cont);
  }

  Future<String> getKelByStr({required String contId, dynamic hint}) async{
    return await api.getKelByStr(contId: contId);
  }

  /// Returns pairs: public key encoded in base64 and signature encoded in hex
  Future<List<PublicKeySignaturePair>> getCurrentPublicKey(
      {required String attachment, dynamic hint}) async{
    return await api.getCurrentPublicKey(attachment: attachment);
  }

}
