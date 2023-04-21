import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri_platform_interface/keri_platform_interface.dart';

import 'package:keri_platform_interface/bridge_generated.dart';
import 'dart:ffi';
import 'exceptions.dart';

class KeriMacos extends KeriPlatformInterface {
  static final dylib = DynamicLibrary.executable();
  static final api = KeriDartImpl(dylib);

  ///Registers new instance of [KeriPlatformInterface].
  static void registerWith() {
    KeriPlatformInterface.instance = KeriMacos();
  }

  ///Initializes database for storing events.
  @override
  Future<bool> initKel(
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
        if (e.message.contains('network error')) {
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
  @override
  Future<String> incept(
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
      if (e.message.contains('network error')) {
        throw OobiResolvingErrorException(
            "No service is listening under the provided port number. Consider changing it.");
      }
      rethrow;
    }
  }

  ///Finalizes inception (bootstrapping an Identifier and its Key Event Log).
  @override
  Future<Identifier> finalizeInception(
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
  @override
  Future<String> rotate(
      {required Identifier controller,
      required List<PublicKey> currentKeys,
      required List<PublicKey> newNextKeys,
      required List<String> witnessToAdd,
      required List<String> witnessToRemove,
      required int witnessThreshold,
      dynamic hint}) async {
    try {
      return await api.rotate(
          identifier: controller,
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
      if (e.message.contains('network error')) {
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
  @override
  Future<String> addWatcher(
      {required Identifier controller,
      required String watcherOobi,
      dynamic hint}) async {
    try {
      return await api.addWatcher(
          identifier: controller, watcherOobi: watcherOobi);
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
      if (e.message.contains('network error')) {
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
  @override
  Future<bool> finalizeEvent(
      {required Identifier identifier,
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
  @override
  Future<bool> resolveOobi({required String oobiJson, dynamic hint}) async {
    try {
      return await api.resolveOobi(oobiJson: oobiJson);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse oobi json')) {
        throw IncorrectOobiException(
            'Provided oobi is incorrect. Please check the JSON once again');
      }
      if (e.message.contains('network error')) {
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
  @override
  Future<void> processStream({required String stream, dynamic hint}) async {
    await api.processStream(stream: stream);
  }

  ///Returns Key Event Log in the CESR representation for current Identifier when given a controller.
  @override
  Future<String> getKel({required Identifier cont, dynamic hint}) async {
    try {
      return await api.getKel(identifier: cont);
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

  ///Creates new Interaction Event along with provided Self Addressing Identifiers.
  @override
  Future<String> anchorDigest(
      {required Identifier controller,
      required List<String> sais,
      dynamic hint}) async {
    try {
      return await api.anchorDigest(identifier: controller, sais: sais);
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
        throw IdentifierException(
            "Controller has not been initialized. Execute initKel() before incepting.");
      }
      rethrow;
    }
  }

  ///Creates new Interaction Event along with arbitrary data.
  @override
  Future<String> anchor(
      {required Identifier controller,
      required String data,
      required DigestType algo,
      dynamic hint}) async {
    try {
      return await api.anchor(identifier: controller, data: data, algo: algo);
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

  @override
  Future<Identifier> newIdentifier(
      {required String idStr, dynamic hint}) async {
    try {
      return await api.newFromStrStaticMethodIdentifier(idStr: idStr);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse identifier prefix')) {
        throw IdentifierException(
            'Can\'t parse identifier prefix. Check the confroller for identifier once again.');
      }
      rethrow;
    }
  }

  //ToDo
  @override
  Future<List<String>> queryMailbox(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      required List<String> witness,
      dynamic hint}) async {
    try {
      return await api.queryMailbox(
          whoAsk: whoAsk, aboutWho: aboutWho, witness: witness);
    } on FfiException catch (e) {
      if (e.message.contains('Can\'t parse identifier prefix')) {
        throw WitnessParsingException(
            'Can\'t parse witness prefix. Check the queryMailbox witness list again.');
      }
      if (e.message.contains('network error')) {
        throw NetworkErrorException(
            'The witness is not listening on the provided port. Turn it on or change the port.');
      }
      rethrow;
    }
  }

  @override
  Future<Signature> signatureFromHex(
      {required SignatureType st,
      required String signature,
      dynamic hint}) async {
    try {
      return await api.signatureFromHex(st: st, signature: signature);
    } on FfiException catch (e) {
      if (e.message.contains('hex decode error')) {
        throw IncorrectSignatureException(
            'The signature provided is not a correct HEX string. Check the signature once again.');
      }
      rethrow;
    }
  }

  @override
  Future<GroupInception> inceptGroup(
      {required Identifier identifier,
      required List<Identifier> participants,
      required int signatureThreshold,
      required List<String> initialWitnesses,
      required int witnessThreshold,
      dynamic hint}) async {
    try {
      return await api.inceptGroup(
          identifier: identifier,
          participants: participants,
          signatureThreshold: signatureThreshold,
          initialWitnesses: initialWitnesses,
          witnessThreshold: witnessThreshold);
    } on FfiException catch (e) {
      if (e.message.contains('Deserialize error')) {
        throw IdentifierException(
            'Provided witness id is incorrect. Check the identifier once again.');
      }
      if (e.message.contains('Improper signature threshold')) {
        throw ImproperSignatureThresholdException(
            'Provided signature threshold is incorrect. Should be higher than 0 and lower than key list length.');
      }
      if (e.message.contains('Improper witness threshold')) {
        throw ImproperWitnessThresholdException(
            'Provided witness threshold is incorrect. Should be higher than 0 and lower than witness list length.');
      }
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown identifier. Check the identifier or participants list for identifier once again.');
      }
      rethrow;
    }
  }

  @override
  Future<Identifier> finalizeGroupIncept(
      {required Identifier identifier,
      required String groupEvent,
      required Signature signature,
      required List<DataAndSignature> toForward,
      dynamic hint}) async {
    try {
      return await api.finalizeGroupIncept(
          identifier: identifier,
          groupEvent: groupEvent,
          signature: signature,
          toForward: toForward);
    } on FfiException catch (e) {
      if (e.message.contains('Unknown id')) {
        throw IdentifierException(
            'Unknown controller identifier. Check the confroller for identifier once again.');
      }
      if (e.message.contains('network error')) {
        throw NetworkErrorException(
            'The witness is not listening on the provided port. Turn it on or change the port.');
      }
      if (e.message.contains('Wrong event format')) {
        throw WrongEventException(
            'Provided string is not a correct group event. Check the string once again.');
      }
      rethrow;
    }
  }

  @override
  Future<PublicKey> newPublicKey(
      {required KeyType kt, required String keyB64, dynamic hint}) async {
    try {
      return await api.newPublicKey(kt: kt, keyB64UrlSafe: keyB64);
    } on FfiException catch (e) {
      if (e.message.contains('wrong key length')) {
        throw IncorrectKeyFormatException(
            "The provided key is not a Base64 string. Check the string once again.");
      }
      rethrow;
    }
  }

  @override
  Future<DataAndSignature> newDataAndSignature({
    required String data,
    dynamic hint,
    required Signature signature,
  }) async {
    return await api.newStaticMethodDataAndSignature(
        data: data, signature: signature);
  }

  @override
  Future<bool> sendOobiToWatcher(
      {required Identifier identifier,
      required String oobisJson,
      dynamic hint}) async {
    return await api.sendOobiToWatcher(
        identifier: identifier, oobisJson: oobisJson);
  }

  @override
  Future<List<String>> queryWatchers(
      {required Identifier whoAsk,
      required Identifier aboutWho,
      dynamic hint}) async {
    return await api.queryWatchers(whoAsk: whoAsk, aboutWho: aboutWho);
  }

  @override
  Future<List<ActionRequired>> finalizeQuery(
      {required Identifier identifier,
      required String queryEvent,
      required Signature signature,
      dynamic hint}) async {
    return await api.finalizeQuery(
        identifier: identifier, queryEvent: queryEvent, signature: signature);
  }

  @override
  Future<bool> notifyWitnesses(
      {required Identifier identifier, dynamic hint}) async {
    return await api.notifyWitnesses(identifier: identifier);
  }

  @override
  Future<bool> broadcastReceipts(
      {required Identifier identifier,
      required List<Identifier> witnessList,
      dynamic hint}) async {
    return await api.broadcastReceipts(
        identifier: identifier, witnessList: witnessList);
  }

  @override
  Future<String> signToCesr(
      {required Identifier identifier,
      required String data,
      required Signature signature,
      dynamic hint}) async {
    return await api.signToCesr(
        identifier: identifier, data: data, signature: signature);
  }

  @override
  Future<bool> verifyFromCesr({required String stream, dynamic hint}) async {
    try {
      return await api.verifyFromCesr(stream: stream);
    } on FfiException catch (e) {
      if (e.message.contains('Cesr error')) {
        throw CesrFormatException(
            "The format of provided string is not compliant with the CESR format. Check the string once again.");
      }
      if (e.message.contains('Wrong signature')) {
        throw WrongCesrSignatureException(
            "The signature for the provided cesr stream is incorrect.");
      }
      if (e.message.contains('Verification failed for following elements')) {
        throw CesrVerificationException(
            "Verification failed for provided stream and signature.");
      }
      rethrow;
    }
  }

  /// Splits parsed elements from stream into oobis to resolve and other signed
  /// data.
  @override
  Future<SplittingResult> splitOobisAndData(
      {required String stream, dynamic hint}) async {
    return await api.splitOobisAndData(stream: stream);
  }
}
