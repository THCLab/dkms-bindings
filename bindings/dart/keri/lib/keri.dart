
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri/exceptions.dart';

import 'bridge_generated.dart';

class Keri {
  static const base = 'dartkeriox';
  static const path = 'lib$base.so';
  static late final dylib = Platform.isIOS
      ? DynamicLibrary.process()
      : Platform.isMacOS
      ? DynamicLibrary.executable()
      : DynamicLibrary.open(path);
  static late final api = KeriDartImpl(dylib);


  static Future<void> initKel({required String inputAppDir, Config? optionalConfigs, dynamic hint}) async{
    if(optionalConfigs != null){
      try{
        await api.initKel(inputAppDir: inputAppDir, optionalConfigs: optionalConfigs);
      }on FfiException catch(e){
        print(e.message);
        if(e.message.contains('Improper location scheme structure')){
          throw IncorrectOptionalConfigsException("The provided argument optionalConfigs contains incorrect data.");
        }
        if(e.message.contains('os error 30')){
          throw UnavailableDirectoryException("The provided directory isn't available for writing. Consider changing the path.");
        }
        if(e.message.contains('error sending request for url')){
          throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
        }
      }
    }else{
      await api.initKel(inputAppDir: inputAppDir);
      try{
        await api.initKel(inputAppDir: inputAppDir);
      }on FfiException catch(e){
        throw UnavailableDirectoryException("The provided directory isn't available for writing. Consider changing the path.");
      }
    }
  }

  static Future<String> incept(
      {required List<PublicKey> publicKeys,
        required List<PublicKey> nextPubKeys,
        required List<String> witnesses,
        required int witnessThreshold,
        dynamic hint}) async{
    try{
      return await api.incept(publicKeys: publicKeys, nextPubKeys: nextPubKeys, witnesses: witnesses, witnessThreshold: witnessThreshold);
    }on FfiException catch(e){
      if(e.message.contains('Controller wasn\'t initiated')){
        throw ControllerNotInitializedException("Controller has not been initialized. Execute initKel() before incepting.");
      }
      if(e.message.contains('Base64Error')){
        throw IncorrectKeyFormatException("The provided key is not a Base64 string. Check the string once again.");
      }
      if(e.message.contains('Can\'t parse witnesses oobis')){
        throw IncorrectWitnessOobiException("The provided witness oobi is incorrect. Check the string once again.");
      }
      print(e);
      throw Exception(e.message);
    }
  }

  static Future<Controller> finalizeInception(
      {required String event, required Signature signature, dynamic hint}) async{
    try{
      return await api.finalizeInception(event: event, signature: signature);
    }on FfiException catch (e){
      if(e.message.contains('hex decode error')){
        throw IncorrectSignatureException('The signature provided is not a correct HEX string. Check the signature once again');
      }
      if(e.message.contains('can\'t parse event')){
        throw WrongEventException('Provided string is not a correct icp event. Check the string once again.');
      }
      rethrow;
    }

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
