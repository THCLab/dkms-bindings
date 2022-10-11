import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keri/bridge_generated.dart';
import 'package:keri/exceptions.dart';
import 'package:keri/keri.dart';
import 'package:test/expect.dart' as ex;

void main() {
  var publicKey1 = '6gWY4Y+k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
  var publicKey2 = 'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
  const publicKey3 = 'vyr60mQ4dvwa5twsC7N7Nx0UAF4nqCDLfibDY0dJovE=';
  const privateKey1 =
      '7BMT7rSxnmBpoAkrlseH894ox8ypeA5//cIBLtCN4qbqBZjhj6Ta30oVlpKRHmNQic5gSg6W4AO1aZjGw+SWfQ==';
  const privateKey2 =
      'pDRM5oADe+AYGUIap2O9r9mt7Ue7F3mwBD9UU2rt7Lsag/yqNdtRyekxa0N5G438BPSkDsXmAWOu/xR3GsQlbQ==';
  const privateKey3 =
      'lfcTwZDsgE0ZcLv4YGBJVAaLE+BMSSlMk8v1eEQhqJm/KvrSZDh2/Brm3CwLs3s3HRQAXieoIMt+JsNjR0mi8Q==';

  group("initKel()", () {
    test('The kel fails to init as optionalConfigs contain incorrect data',
        () async {
      try {
        await Keri.initKel(
            inputAppDir: 'keritest',
            optionalConfigs: Config(initialOobis: 'cat'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOptionalConfigsException>());
      }
    });

    test(
        'The kel fails to init as nobody is listening on the port provided in optionalConfigs',
        () async {
      var conf = Config(
          initialOobis:
              "[{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}]");
      try {
        await Keri.initKel(inputAppDir: 'keritest', optionalConfigs: conf);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });
  });

  group("incept()", () {
    test('The inception passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      expect(
          await Keri.incept(
              publicKeys: vec1,
              nextPubKeys: vec2,
              witnesses: vec3,
              witnessThreshold: 0),
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}');
    });

    test('The inception fails, because the key is not a Base64 string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      try {
        var icp_event = await Keri.incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
      }
    });

    test('The inception fails, because the provided witness oobi is incorrect',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = ['incorrect'];
      try {
        var icp_event = await Keri.incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectWitnessOobiException>());
      }
    });

    test(
        'The inception fails, because the provided witness prefix is incorrect',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"ESuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}"
      ];
      try {
        var icp_event = await Keri.incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test(
        'The inception fails, because nobody is listening on the port provided for witness',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"
      ];
      try {
        var icp_event = await Keri.incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The inception fails, because the controller wasn\'t initiated',
        () async {
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"
      ];
      try {
        var icp_event = await Keri.incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('finalizeInception()', () {
    test('The finalize inception passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      expect(controller,
          'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40');
    });

    test(
        'The finalize inception fails, because the signature is not a correct hex string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature = 'failSignature';
      try {
        var controller = await Keri.finalizeInception(
            event: icp_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectSignatureException>());
      }
    });

    test('The finalize inception fails, because the signature fails to verify',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A8390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try {
        var controller = await Keri.finalizeInception(
            event: icp_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<SignatureVerificationException>());
      }
    });

    test('The finalize inception fails, because the initKel() was not executed',
        () async {
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event =
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}';
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try {
        var controller = await Keri.finalizeInception(
            event: icp_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test(
        'The finalize inception fails, because the icp event is not a correct string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try {
        var controller = await Keri.finalizeInception(
            event: 'failEvent',
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<WrongEventException>());
      }
    });
  });

  group('rotate()', () {
    test('The rotation passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      expect(
          await Keri.rotate(
              controller: controller,
              currentKeys: currentKeys,
              newNextKeys: newNextKeys,
              witnessToAdd: [],
              witnessToRemove: [],
              witnessThreshold: 0),
          '{"v":"KERI10JSON000160_","t":"rot","d":"E0hQgEiZQAwTMZ6AM5xG6G0OqcJtCm449Ztn5MOWmnJ8","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"1","p":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","kt":"1","k":["BGoP8qjXbUcnpMWtDeRuN_AT0pA7F5gFjrv8UdxrEJW0"],"nt":"1","n":["ER70d4nGUCAA-S1gS5AwGjWQcunTErv6xFdh9gOIsbiQ"],"bt":"0","br":[],"ba":[],"a":[]}');
    });

    test('The rotation fails, because the key is not a Base64 string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
      }
    });

    test('The rotation fails, because of wrong witnessToAdd', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: ['fail'],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOobiException>());
      }
    });

    test('The rotation fails, because of wrong witnessToRemove', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: ['fail'],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<WitnessParsingException>());
      }
    });

    test('The rotation fails, because of wrong witness prefix', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [
              "{\"eid\":\"ESuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}"
            ],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test(
        'The rotation fails, because nobody is listening on the port provided to witness',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [
              "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"
            ],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The rotation fails, because of wrong controller string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: await Keri.newIdentifier(idStr: 'fail'),
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('The rotation fails, because of unknown controller identifier',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await Keri.rotate(
            controller: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'),
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('addWatcher()', () {
    test(
        'addWatcher fails, because nobody is listening on the port provided in watcher.',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      try {
        await Keri.addWatcher(
            controller: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            watcherOobi:
                "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}");
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('addWatcher fails, because controller is incorrect', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      try {
        await Keri.addWatcher(
            controller: await Keri.newIdentifier(idStr: 'fail'),
            watcherOobi:
                "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}");
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('addWatcher fails, because watcher Oobi is incorrect.', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      try {
        await Keri.addWatcher(
            controller: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            watcherOobi: "fail");
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectWatcherOobiException>());
      }
    });
  });

  group('resolveOobi()', () {
    test('resolveOobi fails, because oobi is an empty string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try {
        await Keri.resolveOobi(oobiJson: '');
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOobiException>());
      }
    });

    test('resolveOobi fails, because oobi is an incorrect string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try {
        await Keri.resolveOobi(oobiJson: 'fail');
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOobiException>());
      }
    });

    test('resolveOobi fails, because nobody listens on port provided in oobi',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try {
        await Keri.resolveOobi(
            oobiJson:
                "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}");
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });
  });

  group('finalizeEvent()', () {
    test('finalizeEvent passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotation_event = await Keri.rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: rotation_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('finalizeEvent fails, because signature is incorrect', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotation_event = await Keri.rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
      try {
        var res = await Keri.finalizeEvent(
            identifier: controller,
            event: rotation_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<SignatureVerificationException>());
      }
    });

    test('finalizeEvent fails, because event string is not a correct string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotation_event = await Keri.rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
      try {
        var res = await Keri.finalizeEvent(
            identifier: controller,
            event: 'fail',
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<WrongEventException>());
      }
    });

    test(
        'finalizeEvent fails, because controller string is not a correct string',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotation_event = await Keri.rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
      try {
        var res = await Keri.finalizeEvent(
            identifier: await Keri.newIdentifier(idStr: 'fail'),
            event: rotation_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('query()', () {
    test('query passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}'
      ];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A3D27FC3B81BACD4DC121DE06D362551449A2350A4A8198C9E01E5CF3C37B037B6C0EECF580D55289224AF6408A877082657F34ECD7483383E1C4865F448FF08';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK WATCHER EVENT
      var watcher_event =
          '{"v":"KERI10JSON000113_","t":"rpy","d":"Emnz_fz7suVJmKAqC-Kt8VQu6cTXuWJ4ciSEnLGYIjLs","dt":"2022-06-20T15:16:52.679568+00:00","r":"/end/role/add","a":{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"watcher","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      var signature2 =
          '1F5BFC6876B6CD7A39CDC6F70A9F3FB9AB80F5E3C78EFD2BF78FAEAACA3DAB292BDC2DA8C267EAB4896CFDBF1BC19F76397245341F63CFDD4AC641CA4454D806';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: watcher_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      var oobiString =
          '[{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"},{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"witness","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}]';
      var res2 =
          await Keri.query(controller: controller, oobisJson: oobiString);
      expect(res2, true);
    });

    test('query fails, because nobody is listening on the port.', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}'
      ];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A3D27FC3B81BACD4DC121DE06D362551449A2350A4A8198C9E01E5CF3C37B037B6C0EECF580D55289224AF6408A877082657F34ECD7483383E1C4865F448FF08';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK WATCHER EVENT
      var watcher_event =
          '{"v":"KERI10JSON000113_","t":"rpy","d":"Emnz_fz7suVJmKAqC-Kt8VQu6cTXuWJ4ciSEnLGYIjLs","dt":"2022-06-20T15:16:52.679568+00:00","r":"/end/role/add","a":{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"watcher","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      var signature2 =
          '1F5BFC6876B6CD7A39CDC6F70A9F3FB9AB80F5E3C78EFD2BF78FAEAACA3DAB292BDC2DA8C267EAB4896CFDBF1BC19F76397245341F63CFDD4AC641CA4454D806';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: watcher_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      var oobiString =
          '[{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:8888/"},{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"witness","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}]';
      try {
        var res2 =
            await Keri.query(controller: controller, oobisJson: oobiString);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('query fails, because of incorrect oobi json', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}'
      ];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A3D27FC3B81BACD4DC121DE06D362551449A2350A4A8198C9E01E5CF3C37B037B6C0EECF580D55289224AF6408A877082657F34ECD7483383E1C4865F448FF08';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK WATCHER EVENT
      var watcher_event =
          '{"v":"KERI10JSON000113_","t":"rpy","d":"Emnz_fz7suVJmKAqC-Kt8VQu6cTXuWJ4ciSEnLGYIjLs","dt":"2022-06-20T15:16:52.679568+00:00","r":"/end/role/add","a":{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"watcher","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      var signature2 =
          '1F5BFC6876B6CD7A39CDC6F70A9F3FB9AB80F5E3C78EFD2BF78FAEAACA3DAB292BDC2DA8C267EAB4896CFDBF1BC19F76397245341F63CFDD4AC641CA4454D806';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: watcher_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      var oobiString =
          '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"},{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"witness","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}';
      try {
        var res2 =
            await Keri.query(controller: controller, oobisJson: oobiString);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IncorrectOobiException>());
      }
    });

    test('query fails, because the controller identifier is incorrect.',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}'
      ];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A3D27FC3B81BACD4DC121DE06D362551449A2350A4A8198C9E01E5CF3C37B037B6C0EECF580D55289224AF6408A877082657F34ECD7483383E1C4865F448FF08';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK WATCHER EVENT
      var watcher_event =
          '{"v":"KERI10JSON000113_","t":"rpy","d":"Emnz_fz7suVJmKAqC-Kt8VQu6cTXuWJ4ciSEnLGYIjLs","dt":"2022-06-20T15:16:52.679568+00:00","r":"/end/role/add","a":{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"watcher","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      var signature2 =
          '1F5BFC6876B6CD7A39CDC6F70A9F3FB9AB80F5E3C78EFD2BF78FAEAACA3DAB292BDC2DA8C267EAB4896CFDBF1BC19F76397245341F63CFDD4AC641CA4454D806';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: watcher_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      var oobiString =
          '[{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"},{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"witness","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}]';
      try {
        var res2 = await Keri.query(
            controller: await Keri.newIdentifier(idStr: 'fail'), oobisJson: oobiString);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('query fails, because the controller has not been initialized',
        () async {
      var oobiString =
          "[{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}]";
      try {
        var res2 = await Keri.query(
            controller: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            oobisJson: oobiString);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('getKel()', () {
    test('the getKel passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      expect(
          await Keri.getKel(
              cont: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40')),
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","i":"EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40","s":"0","kt":"1","k":["B6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["EPK9M59jg6y4kQRzd93kpYouxSIQ8M0hnnj8ajHKghFE"],"bt":"0","b":[],"c":[],"a":[]}-AABAAqTkN-gN0l9iH4r_x7SnalIC1_1m_4Pyv4ZuTlSnyX6yPHT8imfFkAu7WVN7hoVaEDHWEy2RVstEHZ0QfJ911Cg');
    });

    test('the getKel fails, because of unknown controller identifier',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try {
        await Keri.getKel(
            cont: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('the getKel fails, because of incorrect controller string', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      try {
        await Keri.getKel(cont: await Keri.newIdentifier(idStr: 'fail'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('getCurrentPublicKey()', () {
    test('getting key fails, because attachment string is not a correct JSON',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      var attachment = 'fail';
      try {
        await Keri.getCurrentPublicKey(attachment: attachment);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<AttachmentException>());
      }
    });
  });

  group('anchorDigest', () {
    test('anchorDigest passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      var anchor_event =
          await Keri.anchorDigest(controller: controller, sais: sais);
      var signature2 =
          '12380BB2BC3481F285337EB32AA40B335032F34B27CD09A5BD0660A2039E0F7CB2AD3982F97C96645BA3EBC19260EB7201D8B3FC476EA083E047FE75354CBC0D';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: anchor_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('anchor fails, because the sai is incorrect', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "fail";
      sais.add(sai);
      try {
        var anchor_event =
            await Keri.anchorDigest(controller: controller, sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<SelfAddressingIndentifierException>());
      }
    });

    test('anchor fails, because the controller is unknown', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var hexsig = await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature);
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: hexsig);
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var anchor_event = await Keri.anchorDigest(
            controller: await Keri.newIdentifier(idStr: 'E2e7tLvlVlER4kkV3bw36SN8Gz3fJ-3QR2xadxKyed10'),
            sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller is incorrect', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var anchor_event = await Keri.anchorDigest(
            controller: await Keri.newIdentifier(idStr: 'fail'), sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller was not initialized', () async {
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var anchor_event = await Keri.anchorDigest(
            controller: await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  group('anchor', () {
    test('anchor passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      var anchor_event = await Keri.anchor(
          controller: controller, data: 'data', algo: DigestType.blake3256());
      var signature2 =
          '629B2205FB6DC594F8368B031DEEAE5A4EB766222B7C008BDDB0668645681DEDFB8F72A93D6C9AE4938FF32637BD64A6D5D49AE3BDB5EC4932D91310EB67330D';
      var res = await Keri.finalizeEvent(
          identifier: controller,
          event: anchor_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('anchor fails, because the controller is unknown', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var anchor_event = await Keri.anchor(
            controller: await Keri.newIdentifier(idStr: 'E2e7tLvlVlER4kkV3bw36SN8Gz3fJ-3QR2xadxKyed10'),
            data: 'data',
            algo: DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller is incorrect', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icp_event = await Keri.incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var anchor_event = await Keri.anchor(
            controller: await Keri.newIdentifier(idStr: 'fail'),
            data: 'data',
            algo: DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller was not initialized', () async {
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var identifier = await Keri.newIdentifier(idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40');
        var anchor_event = await Keri.anchor(
            controller: identifier,
            data: 'data',
            algo: DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  test('Full use case', () async {
    await Keri.initKel(inputAppDir: 'keritest');
    List<PublicKey> vec1 = [];
    vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    List<PublicKey> vec2 = [];
    vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    List<String> vec3 = [];
    var icp_event = await Keri.incept(
        publicKeys: vec1,
        nextPubKeys: vec2,
        witnesses: vec3,
        witnessThreshold: 0);
    var signature =
        'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
    var controller = await Keri.finalizeInception(
        event: icp_event,
        signature:
            await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
    //MOCK ROTATION
    publicKey1 = publicKey2;
    publicKey2 = publicKey3;
    List<PublicKey> currentKeys = [];
    List<PublicKey> newNextKeys = [];
    currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    var rotation_event = await Keri.rotate(
        controller: controller,
        currentKeys: currentKeys,
        newNextKeys: newNextKeys,
        witnessToAdd: [],
        witnessToRemove: [],
        witnessThreshold: 0);
    var signature2 =
        'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
    var res = await Keri.finalizeEvent(
        identifier: controller,
        event: rotation_event,
        signature:
            await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
    var anchor_event = await Keri.anchor(
        controller: controller, data: 'data', algo: DigestType.blake3256());
    var signature3 =
        '05A12E80B0762363F4A088ABEB0991B4EE9ED63512DB71C9BD8EBA298F25DBFE093EA0DF3F5A6DE4A18F037C1BBB07633B3BB15156CF35F9273222CCDEB44D00';
    var res2 = await Keri.finalizeEvent(
        identifier: controller,
        event: anchor_event,
        signature:
            await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature3));
    expect(res2, true);
  });
}
