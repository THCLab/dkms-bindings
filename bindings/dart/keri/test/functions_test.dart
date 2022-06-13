import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keri/bridge_generated.dart';
import 'package:keri/exceptions.dart';
import 'package:keri/keri.dart';
import 'package:test/expect.dart' as ex;



void main(){
  var publicKey1 = '6gWY4Y+k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
  var publicKey2 = 'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
  const publicKey3 = 'vyr60mQ4dvwa5twsC7N7Nx0UAF4nqCDLfibDY0dJovE=';
  const privateKey1 = '7BMT7rSxnmBpoAkrlseH894ox8ypeA5//cIBLtCN4qbqBZjhj6Ta30oVlpKRHmNQic5gSg6W4AO1aZjGw+SWfQ==';
  const privateKey2 = 'pDRM5oADe+AYGUIap2O9r9mt7Ue7F3mwBD9UU2rt7Lsag/yqNdtRyekxa0N5G438BPSkDsXmAWOu/xR3GsQlbQ==';
  const privateKey3 = 'lfcTwZDsgE0ZcLv4YGBJVAaLE+BMSSlMk8v1eEQhqJm/KvrSZDh2/Brm3CwLs3s3HRQAXieoIMt+JsNjR0mi8Q==';

  group("initKel()", () {
    test('The kel fails to init as optionalConfigs contain incorrect data', () async{
      try {
        await Keri.initKel(inputAppDir: 'keritest', optionalConfigs: Config( initialOobis: 'cat'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOptionalConfigsException>());
      }
    });

    test('The kel fails to init as nobody is listening on the port provided in optionalConfigs', () async{
      var conf = Config(initialOobis: "[{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}]");
      try {
        await Keri.initKel(inputAppDir: 'keritest', optionalConfigs: conf);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });
  });

  group("incept()", () {
    test('The inception passes', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      expect(await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0),'{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}');
    });

    test('The inception fails, because the key is not a Base64 string', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: 'failKey'));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      try{
        var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
      }
    });

    test('The inception fails, because the provided witness oobi is incorrect', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: 'failKey'));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = ['incorrect'];
      try{
        var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectWitnessOobiException>());
      }
    });

    test('The inception fails, because the provided witness prefix is incorrect', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = ["{\"eid\":\"ESuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}"];
      try{
        var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test('The inception fails, because nobody is listening on the port provided for witness', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = ["{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"];
      try{
        var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The inception fails, because the controller wasn\'t initiated', () async{
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = ["{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"];
      try{
        var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<ControllerNotInitializedException>());
      }
    });
  });

  group('finalizeInception()', () {
    test('The finalize inception passes', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      expect(controller.identifier,'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40');
    });

    test('The finalize inception fails, because the signature is not a correct hex string', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'failSignature';
      try{
        var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectSignatureException>());
      }
    });

    test('The finalize inception fails, because the signature fails to verify', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A8390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try{
        var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<SignatureVerificationException>());
      }
    });

    test('The finalize inception fails, because the initKel() was not executed', () async{
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = '{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}';
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try{
        var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<ControllerNotInitializedException>());
      }
    });

    test('The finalize inception fails, because the icp event is not a correct string', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try{
        var controller = await Keri.finalizeInception(event: 'failEvent', signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<WrongEventException>());
      }
    });
  });

  group('rotate()', () {
    test('The rotation passes', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      expect(await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: [], witnessThreshold: 0),'{"v":"KERI10JSON000160_","t":"rot","d":"E0hQgEiZQAwTMZ6AM5xG6G0OqcJtCm449Ztn5MOWmnJ8","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"1","p":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","kt":"1","k":["BGoP8qjXbUcnpMWtDeRuN_AT0pA7F5gFjrv8UdxrEJW0"],"nt":"1","n":["ER70d4nGUCAA-S1gS5AwGjWQcunTErv6xFdh9gOIsbiQ"],"bt":"0","br":[],"ba":[],"a":[]}');
    });

    test('The rotation fails, because the key is not a Base64 string', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: 'failKey'));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
      }
    });

    test('The rotation fails, because of wrong witnessToAdd', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: ['fail'], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<WitnessParsingException>());
      }
    });

    test('The rotation fails, because of wrong witnessToRemove', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: ['fail'], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<WitnessParsingException>());
      }
    });

    test('The rotation fails, because of wrong witness prefix', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: ["{\"eid\":\"ESuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}"], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test('The rotation fails, because nobody is listening on the port provided to witness', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: ["{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The rotation fails, because of wrong controller string', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: Controller(identifier: 'fail'), currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('The rotation fails, because of unknown controller identifier', () async{
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
      var signature = 'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey1));
      newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: publicKey2));
      try{
        await Keri.rotate(controller: Controller(identifier: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'), currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: [], witnessThreshold: 0);
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('getKel()', () {
    test('the getKel passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      expect(await Keri.getKel(cont: Controller(identifier: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40')),'{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}-AABAAqTkN-gN0l9iH4r_x7SnalIC1_1m_4Pyv4ZuTlSnyX6yPHT8imfFkAu7WVN7hoVaEDHWEy2RVstEHZ0QfJ911Cg');
    });

    test('the getKel fails, because of unknown controller identifier', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try{
        await Keri.getKel(cont: Controller(identifier: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('the getKel fails, because of incorrect controller string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try{
        await Keri.getKel(cont: Controller(identifier: 'fail'));
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('getKelByStr()', () {
    test('the getKelByStr passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      expect(await Keri.getKelByStr(contId: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),'{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}-AABAAqTkN-gN0l9iH4r_x7SnalIC1_1m_4Pyv4ZuTlSnyX6yPHT8imfFkAu7WVN7hoVaEDHWEy2RVstEHZ0QfJ911Cg');
    });

    test('the getKelByStr fails, because of unknown controller identifier', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try{
        await Keri.getKelByStr(contId: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40');
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('the getKel fails, because of incorrect controller string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try{
        await Keri.getKelByStr(contId: 'fail');
        fail("exception not thrown");
      }catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

}