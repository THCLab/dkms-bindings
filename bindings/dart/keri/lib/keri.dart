import 'dart:ffi';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri/exceptions.dart';

import 'bridge_generated.dart';

class Keri {
  static final examplePath = Directory.current.absolute.path;
  static const base = 'dartkeriox';
  static final path = Platform.isWindows ? '$base.dll' : 'lib$base.so';

  static late final dylib = Platform.environment.containsKey('FLUTTER_TEST')
      ? DynamicLibrary.open(
          Platform.script.resolve("test/dartkeriox.dll").toFilePath())
      : Platform.isIOS
          ? DynamicLibrary.process()
          : Platform.isMacOS
              ? DynamicLibrary.executable()
              : DynamicLibrary.open(path);
  static late final api = KeriDartImpl(dylib);

  ///Initializes database for storing events.
  static Future<bool> initKel(
      {required String inputAppDir,
      Config? optionalConfigs,
      dynamic hint}) async {
    if (optionalConfigs != null) {
      try {
        return await api.initKel(
            inputAppDir: inputAppDir, optionalConfigs: optionalConfigs);
      } on FfiException catch (e) {
        if (e.message.contains('Improper location scheme structure')) {
          throw IncorrectOptionalConfigsException(
              "The provided argument optionalConfigs contains incorrect data.");
        }
        if (e.message.contains('Error while event processing')) {
          throw UnavailableDirectoryException(
              "The provided directory isn't available for writing. Consider changing the path.");
        }
        if (e.message.contains('error sending request for url')) {
          throw OobiResolvingErrorException(
              "No service is listening under the provided port number. Consider changing it.");
        }
        rethrow;
      }
    } else {
      try {
        return await api.initKel(inputAppDir: inputAppDir);
      } on FfiException catch (e) {
        if (e.message.contains('Error while event processing')) {
          throw UnavailableDirectoryException(
              "The provided directory isn't available for writing. Consider changing the path.");
        }
        rethrow;
      }
    }
  }

  ///Creates inception event that needs to be signed externally.
  static Future<String> incept(
      {required List<PublicKey> publicKeys,
      required List<PublicKey> nextPubKeys,
      required List<String> witnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    try {
      return await api.incept(
          publicKeys: publicKeys,
          nextPubKeys: nextPubKeys,
          witnesses: witnesses,
          witnessThreshold: witnessThreshold);
    } on FfiException catch (e) {
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      if (e.message.contains('Base64Error')) {
        throw IncorrectKeyFormatException(
            "The provided key is not a Base64 string. Check the string once again.");
      }
      if (e.message.contains('Can\'t parse oobi json')) {
        throw IncorrectWitnessOobiException(
            "The provided witness oobi is incorrect. Check the string once again.");
      }
      if (e.message.contains('Improper witness prefix')) {
        throw ImproperWitnessPrefixException(
            "Improper witness prefix, should be basic prefix. Check the eid field.");
      }
      if (e.message.contains('error sending request for url')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      rethrow;
    }
  }

  ///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
  static Future<Controller> finalizeInception(
      {required String event,
      required Signature signature,
      dynamic hint}) async {
    try {
      return await api.finalizeInception(event: event, signature: signature);
    } on FfiException catch (e) {
      if (e.message.contains('hex decode error')) {
        throw IncorrectSignatureException(
            'The signature provided is not a correct HEX string. Check the signature once again.');
      }
      if (e.message.contains('Can\'t parse event')) {
        throw WrongEventException(
            'Provided string is not a correct icp event. Check the string once again.');
      }
      if (e.message.contains('Signature verification failed')) {
        throw SignatureVerificationException(
            'Signature verification failed - event signature does not match event keys.');
      }
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
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
      dynamic hint}) async {
    try {
      return await api.rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: witnessToAdd,
          witnessToRemove: witnessToRemove,
          witnessThreshold: witnessThreshold);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('base64 decode error')) {
        throw IncorrectKeyFormatException(
            "The provided key is not a Base64 string. Check the string once again.");
      }
      if (e.message.contains('Can\'t parse witness identifier')) {
        throw WitnessParsingException(
            'Can\'t parse witness identifier. Check the wittnessToRemove field.');
      }
      if (e.message.contains('error sending request for url')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      if (e.message.contains('Improper witness prefix')) {
        throw ImproperWitnessPrefixException(
            "Improper witness prefix, should be basic prefix. Check the eid field.");
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse oobi json')) {
        throw IncorrectOobiException(
            'Provided oobi is incorrect. Please check the JSON once again');
      }
      rethrow;
    }
  }

  ///Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
  static Future<String> addWatcher(
      {required Controller controller,
      required String watcherOobi,
      dynamic hint}) async {
    try {
      return await api.addWatcher(
          controller: controller, watcherOobi: watcherOobi);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse oobi json:')) {
        throw IncorrectWatcherOobiException(
            'Provided watcher oobi is not a correct string. Check it once again.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('error sending request for url')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      rethrow;
    }
  }

  ///Verifies provided signatures against event and saves it.
  static Future<bool> finalizeEvent(
      {required Controller identifier,
      required String event,
      required Signature signature,
      dynamic hint}) async {
    try {
      return await api.finalizeEvent(
          identifier: identifier, event: event, signature: signature);
    } on FfiException catch (e) {
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Signature verification failed')) {
        throw SignatureVerificationException(
            'Signature verification failed - event signature does not match event keys.');
      }
      if (e.message.contains('Can\'t parse event')) {
        throw WrongEventException(
            'Provided string is not a correct event. Check the string once again.');
      }
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      rethrow;
    }
  }

  ///Checks and saves provided identifier's endpoint information.
  static Future<bool> resolveOobi(
      {required String oobiJson, dynamic hint}) async {
    try {
      return await api.resolveOobi(oobiJson: oobiJson);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse oobi json')) {
        throw IncorrectOobiException(
            'Provided oobi is incorrect. Please check the JSON once again');
      }
      if (e.message.contains('error sending request for url')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier is incorrect. Check the eid field once again.');
      }
      rethrow;
    }
  }

  ///Query designated watcher about other identifier's public keys data.
  static Future<bool> query(
      {required Controller controller,
      required String oobisJson,
      dynamic hint}) async {
    try {
      return await api.query(controller: controller, oobisJson: oobisJson);
    } on FfiException catch (e) {
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('error sending request for url')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      if (e.message.contains('Signature verification failed')) {
        throw SignatureVerificationException(
            'Signature verification failed - event signature does not match event keys.');
      }
      if (e.message.contains('Can\'t parse oobi json')) {
        throw IncorrectOobiException(
            'Provided oobi is incorrect. Please check the JSON once again');
      }
      rethrow;
    }
  }

  //CZY JEST POTRZEBNA?
  Future<void> processStream({required String stream, dynamic hint}) async {
    await api.processStream(stream: stream);
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  static Future<String> getKel({required Controller cont, dynamic hint}) async {
    try {
      return await api.getKel(cont: cont);
    } on FfiException catch (e) {
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller identifier.
  static Future<String> getKelByStr(
      {required String contId, dynamic hint}) async {
    try {
      return await api.getKelByStr(contId: contId);
    } on FfiException catch (e) {
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  /// Returns pairs: public key encoded in base64 and signature encoded in hex.
  static Future<List<PublicKeySignaturePair>> getCurrentPublicKey(
      {required String attachment, dynamic hint}) async {
    try {
      return await api.getCurrentPublicKey(attachment: attachment);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse attachment')) {
        throw AttachmentException(
            'Cannot parse provided attachment. Check the JSON string again.');
      }
      rethrow;
    }
  }

  ///Creates new Interaction Event along with provided Self Addressing Identifiers.
  static Future<String> anchorDigest(
      {required Controller controller,
      required List<String> sais,
      dynamic hint}) async {
    try {
      return await api.anchorDigest(controller: controller, sais: sais);
    } on FfiException catch (e) {
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Can\'t parse self addressing identifier')) {
        throw SelfAddressingIndentifierException(
            'The SAI provided to the anchor is incorrect. Check the list once again.');
      }
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      rethrow;
    }
  }

  ///Creates new Interaction Event along with arbitrary data.
  static Future<String> anchor(
      {required Controller controller,
      required String data,
      required DigestType algo,
      dynamic hint}) async {
    try {
      return await api.anchor(controller: controller, data: data, algo: algo);
    } on FfiException catch (e) {
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Can\'t parse controller')) {
        throw IdentifierException(
            'Can\'t parse controller prefix. Check the confroller for identifier once again.');
      }
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'The identifier provided to the controller is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Controller wasn\'t initialized')) {
        throw ControllerNotInitializedException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      rethrow;
    }
  }
}
