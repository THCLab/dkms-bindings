
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri/exceptions.dart';
import 'package:path/path.dart' as p;

import 'bridge_generated.dart';

class Keri {
  static final examplePath = Directory.current.absolute.path;
  //print(examplePath);
  static const base = 'dartkeriox';
  static const path = 'lib$base.so';
  static const path2 = 'C:/Users/66jus/Documents/GitHub/keri-bindings/bindings/dart/keri/android/src/main/jniLibs/x86_64/lib$base.so';
  static const path3 = 'C:/Users/66jus/Documents/GitHub/keri-bindings/bindings/dart/keri/build/test/libdartkeriox.dylib';
  static const path4 = 'C:/Users/66jus/Documents/GitHub/keri-bindings/bindings/dart/keri/android/src/main/jniLibs/arm64-v8a/lib$base.so';

  //static final path = p.join(examplePath, 'android/src/main/jniLibs/arm64-v8a/lib$base.so');
  //path = p.join(examplePath, 'lib$base.so');

  static late final dylib = Platform.environment.containsKey('FLUTTER_TEST') ? DynamicLibrary.open(Platform.script.resolve("build/test/keri-bindings.dll").toFilePath()) :  Platform.isIOS
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
        if(e.message.contains('Error while event processing')){
          throw UnavailableDirectoryException("The provided directory isn't available for writing. Consider changing the path.");
        }
        if(e.message.contains('error sending request for url')){
          throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
        }
      }
    }else{
      try{
        await api.initKel(inputAppDir: inputAppDir);
      }on FfiException catch(e){
        if(e.message.contains('Error while event processing')){
          throw UnavailableDirectoryException("The provided directory isn't available for writing. Consider changing the path.");
        }
      }
    }
  }

  ///Creates inception event that needs to be signed externally.
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
      if(e.message.contains('Improper witness prefix')){
        throw ImproperWitnessPrefixException("Improper witness prefix, should be basic prefix. Check the eid field.");
      }
      if(e.message.contains('error sending request for url')){
        throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
      }
      rethrow;
    }
  }

  ///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
  static Future<Controller> finalizeInception(
      {required String event, required Signature signature, dynamic hint}) async{
    try{
      return await api.finalizeInception(event: event, signature: signature);
    }on FfiException catch (e){
      if(e.message.contains('hex decode error')){
        throw IncorrectSignatureException('The signature provided is not a correct HEX string. Check the signature once again.');
      }
      if(e.message.contains('can\'t parse event')){
        throw WrongEventException('Provided string is not a correct icp event. Check the string once again.');
      }
      if(e.message.contains('Signature verification failed')){
        throw SignatureVerificationException('Signature verification failed - event signature does not match event keys.');
      }
      if(e.message.contains('Controller wasn\'t initiated')){
        throw ControllerNotInitializedException("Controller has not been initialized. Execute initKel() before incepting.");
      }
      rethrow;
    }

  }

  ///Creates rotation event that needs to be signed externally.
  static Future<String> rotate(
      {required Controller controller,
        required List<PublicKey> currentKeys,
        required List<PublicKey> newNextKeys,
        required List<String> witnessToAdd,
        required List<String> witnessToRemove,
        required int witnessThreshold,
        dynamic hint}) async{
    try{
      return await api.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: witnessToAdd, witnessToRemove: witnessToRemove, witnessThreshold: witnessThreshold);

    }on FfiException catch (e){
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if(e.message.contains('base64 decode error')){
        throw IncorrectKeyFormatException("The provided key is not a Base64 string. Check the string once again.");
      }
      if(e.message.contains('parse witnesses to add oobis')) {
        throw WitnessParsingException('Can\'t parse witnesses to add oobis. Check the wittnessToAdd field.');
      }
      if(e.message.contains('Can\'t parse witnesses to remove identifiers')){
        throw WitnessParsingException('Can\'t parse witnesses to remove identifiers. Check the wittnessToRemove field.');
      }
      if(e.message.contains('error sending request for url')){
        throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
      }
      if(e.message.contains('Improper witness prefix')){
        throw ImproperWitnessPrefixException("Improper witness prefix, should be basic prefix. Check the eid field.");
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  static Future<String> addWatcher(
      {required Controller controller,
        required String watcherOobi,
        dynamic hint}) async{
    try{
      return await api.addWatcher(controller: controller, watcherOobi: watcherOobi);
    }on FfiException catch(e){
      if(e.message.contains('expected value at line')){
        throw IncorrectWatcherOobiException('Provided watcher oobi is not a correct string. Check it once again.');
      }
      if(e.message.contains('EOF while parsing a value')){
        throw IncorrectWatcherOobiException('Provided watcher oobi is an empty string. Please provide a correct string.');
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if(e.message.contains('error sending request for url')){
        throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
      }
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      rethrow;
    }
  }

  static Future<void> finalizeEvent(
      {required Controller identifier,
        required String event,
        required Signature signature,
        dynamic hint}) async{
    try{
      await api.finalizeEvent(identifier: identifier, event: event, signature: signature);
    }on FfiException catch(e){
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
    }
  }

  static Future<void> resolveOobi({required String oobiJson, dynamic hint}) async{
    try{
      await api.resolveOobi(oobiJson: oobiJson);
    }on FfiException catch(e){
      if(e.message.contains('expected value at line')){
        throw IncorrectOobiException('Provided oobi is incorrect. Please check the JSON once again');
      }
      if(e.message.contains('EOF while parsing a value')){
        throw IncorrectOobiException('Provided oobi is an empty string. Please provide a correct string.');
      }
      if(e.message.contains('error sending request for url')){
        throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
      }
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier is incorrect. Check the eid field once again.');
      }
    }
  }

  static Future<void> query(
      {required Controller controller,
        required String oobisJson,
        dynamic hint}) async{
    try{
      await api.query(controller: controller, oobisJson: oobisJson);
    }on FfiException catch (e){
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if(e.message.contains('error sending request for url')){
        throw OobiResolvingErrorException("No service is listening under the provided port number. Consider changing it.");
      }
    }
  }

  //CZY JEST POTRZEBNA?
  Future<void> processStream({required String stream, dynamic hint}) async{
    await api.processStream(stream: stream);
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  static Future<String> getKel({required Controller cont, dynamic hint}) async{
    try{
      return await api.getKel(cont: cont);
    }on FfiException catch(e){
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller identifier.
  static Future<String> getKelByStr({required String contId, dynamic hint}) async{
    try{
      return await api.getKelByStr(contId: contId);
    }on FfiException catch(e){
      if(e.message.contains('Deserialize error')){
        throw IdentifierException('The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if(e.message.contains('unknown identifier')){
        throw IdentifierException('Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if(e.message.contains('Can\'t parse controller')){
        throw IdentifierException('Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  /// Returns pairs: public key encoded in base64 and signature encoded in hex
  static Future<List<PublicKeySignaturePair>> getCurrentPublicKey(
      {required String attachment, dynamic hint}) async{
    return await api.getCurrentPublicKey(attachment: attachment);
  }

}
