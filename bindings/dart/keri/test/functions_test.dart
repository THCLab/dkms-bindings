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
  const publicKey4 = 'u3q0mOY39YX67uFq3gi29UCfjXp+SB/iuTRg+kzbB2o=';
  const privateKey1 =
      '7BMT7rSxnmBpoAkrlseH894ox8ypeA5//cIBLtCN4qbqBZjhj6Ta30oVlpKRHmNQic5gSg6W4AO1aZjGw+SWfQ==';
  const privateKey2 =
      'pDRM5oADe+AYGUIap2O9r9mt7Ue7F3mwBD9UU2rt7Lsag/yqNdtRyekxa0N5G438BPSkDsXmAWOu/xR3GsQlbQ==';
  const privateKey3 =
      'lfcTwZDsgE0ZcLv4YGBJVAaLE+BMSSlMk8v1eEQhqJm/KvrSZDh2/Brm3CwLs3s3HRQAXieoIMt+JsNjR0mi8Q==';
  const privateKey4 =
      'lew7zHsQfEaxTjyNU/F3yJInfidMyaiCeJfjXiNTDZ67erSY5jf1hfru4WreCLb1QJ+Nen5IH+K5NGD6TNsHag==';
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
          '{"v":"KERI10JSON00012b_","t":"icp","d":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","i":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","s":"0","kt":"1","k":["D6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["ERnMydUxS3HsugRxKTx104D1YLQG6AouPwW0weJo9UYM"],"bt":"0","b":[],"c":[],"a":[]}');
    });

    // test('The inception fails, because the key is not a Base64 string',
    //     () async {
    //   await Keri.initKel(inputAppDir: 'keritest');
    //   List<PublicKey> vec1 = [];
    //   vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
    //   List<PublicKey> vec2 = [];
    //   vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   List<String> vec3 = [];
    //   try {
    //     var icp_event = await Keri.incept(
    //         publicKeys: vec1,
    //         nextPubKeys: vec2,
    //         witnesses: vec3,
    //         witnessThreshold: 0);
    //     fail("exception not thrown");
    //   } catch (e) {
    //     expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
    //   }
    // });

    test('The inception fails, because the provided witness oobi is incorrect',
        () async {
      await Keri.initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  publicKey1));
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
        expect(e, const ex.isInstanceOf<ControllerNotInitializedException>());
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      expect(controller.id,
          'ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE');
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
          '{"v":"KERI10JSON00012b_","t":"icp","d":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","i":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","s":"0","kt":"1","k":["D6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["ERnMydUxS3HsugRxKTx104D1YLQG6AouPwW0weJo9UYM"],"bt":"0","b":[],"c":[],"a":[]}';
      var signature =
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
      try {
        var controller = await Keri.finalizeInception(
            event: icp_event,
            signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<ControllerNotInitializedException>());
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '{"v":"KERI10JSON000160_","t":"rot","d":"EfKAkVAG1UnqNlCAhBVhjUi8PCmT9L7HE9DFmpSfjz0o","i":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","s":"1","p":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","kt":"1","k":["DGoP8qjXbUcnpMWtDeRuN_AT0pA7F5gFjrv8UdxrEJW0"],"nt":"1","n":["E2RmCrvZdY2MUx9CgSkpmXu2kQMcasbSbUDygJze9-LU"],"bt":"0","br":[],"ba":[],"a":[]}');
    });

    // test('The rotation fails, because the key is not a Base64 string',
    //     () async {
    //   await Keri.initKel(inputAppDir: 'keritest');
    //   List<PublicKey> vec1 = [];
    //   vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    //   List<PublicKey> vec2 = [];
    //   vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   List<String> vec3 = [];
    //   var icp_event = await Keri.incept(
    //       publicKeys: vec1,
    //       nextPubKeys: vec2,
    //       witnesses: vec3,
    //       witnessThreshold: 0);
    //   var signature =
    //       '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
    //   var controller = await Keri.finalizeInception(
    //       event: icp_event,
    //       signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
    //   //MOCK ROTATION
    //   publicKey1 = publicKey2;
    //   publicKey2 = publicKey3;
    //   List<PublicKey> currentKeys = [];
    //   List<PublicKey> newNextKeys = [];
    //   currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
    //   newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   try {
    //     await Keri.rotate(
    //         controller: controller,
    //         currentKeys: currentKeys,
    //         newNextKeys: newNextKeys,
    //         witnessToAdd: [],
    //         witnessToRemove: [],
    //         witnessThreshold: 0);
    //     fail("exception not thrown");
    //   } catch (e) {
    //     expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
    //   }
    // });

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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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

    // test('The rotation fails, because of wrong controller string', () async {
    //   await Keri.initKel(inputAppDir: 'keritest');
    //   List<PublicKey> vec1 = [];
    //   vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    //   List<PublicKey> vec2 = [];
    //   vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   List<String> vec3 = [];
    //   var icp_event = await Keri.incept(
    //       publicKeys: vec1,
    //       nextPubKeys: vec2,
    //       witnesses: vec3,
    //       witnessThreshold: 0);
    //   var signature =
    //       '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
    //   var controller = await Keri.finalizeInception(
    //       event: icp_event,
    //       signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
    //   //MOCK ROTATION
    //   publicKey1 = publicKey2;
    //   publicKey2 = publicKey3;
    //   List<PublicKey> currentKeys = [];
    //   List<PublicKey> newNextKeys = [];
    //   currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    //   newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   try {
    //     await Keri.rotate(
    //         controller: await Keri.newIdentifier(idStr: 'fail'),
    //         currentKeys: currentKeys,
    //         newNextKeys: newNextKeys,
    //         witnessToAdd: [],
    //         witnessToRemove: [],
    //         witnessThreshold: 0);
    //     fail("exception not thrown");
    //   } catch (e) {
    //     expect(e, const ex.isInstanceOf<IdentifierException>());
    //   }
    // });

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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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

    // test('addWatcher fails, because controller is incorrect', () async {
    //   await Keri.initKel(inputAppDir: 'keritest');
    //   List<PublicKey> vec1 = [];
    //   vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    //   List<PublicKey> vec2 = [];
    //   vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    //   List<String> vec3 = [];
    //   var icp_event = await Keri.incept(
    //       publicKeys: vec1,
    //       nextPubKeys: vec2,
    //       witnesses: vec3,
    //       witnessThreshold: 0);
    //   var signature =
    //       '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
    //   var controller = await Keri.finalizeInception(
    //       event: icp_event,
    //       signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
    //   try {
    //     await Keri.addWatcher(
    //         controller: await Keri.newIdentifier(idStr: 'fail'),
    //         watcherOobi:
    //             "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}");
    //     fail("exception not thrown");
    //   } catch (e) {
    //     expect(e, const ex.isInstanceOf<IdentifierException>());
    //   }
    // });

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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
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

  //   test(
  //       'finalizeEvent fails, because controller string is not a correct string',
  //       () async {
  //     await Keri.initKel(inputAppDir: 'keritest');
  //     List<PublicKey> vec1 = [];
  //     vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
  //     List<PublicKey> vec2 = [];
  //     vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
  //     List<String> vec3 = [];
  //     var icp_event = await Keri.incept(
  //         publicKeys: vec1,
  //         nextPubKeys: vec2,
  //         witnesses: vec3,
  //         witnessThreshold: 0);
  //     var signature =
  //         '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
  //     var controller = await Keri.finalizeInception(
  //         event: icp_event,
  //         signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
  //     //MOCK ROTATION
  //     publicKey1 = publicKey2;
  //     publicKey2 = publicKey3;
  //     List<PublicKey> currentKeys = [];
  //     List<PublicKey> newNextKeys = [];
  //     currentKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
  //     newNextKeys.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
  //     var rotation_event = await Keri.rotate(
  //         controller: controller,
  //         currentKeys: currentKeys,
  //         newNextKeys: newNextKeys,
  //         witnessToAdd: [],
  //         witnessToRemove: [],
  //         witnessThreshold: 0);
  //     var signature2 =
  //         '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
  //     try {
  //       var res = await Keri.finalizeEvent(
  //           identifier: await Keri.newIdentifier(idStr: 'fail'),
  //           event: rotation_event,
  //           signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
  //       fail("exception not thrown");
  //     } catch (e) {
  //       expect(e, const ex.isInstanceOf<IdentifierException>());
  //     }
  //   });
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
      print(icp_event);
      var signature =
          '5A6DF1A29EA3991A3F3C8A68ACCEDDD740AE0B51EFA8B66D49DC4A76DF09B973E75045583C90FA478016745B2C44E120F6527A3870FFC663AF4BC6DAEEEF2605';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK WATCHER EVENT
      var watcher_event = await Keri.addWatcher(controller: controller, watcherOobi:  '{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}');
         // '{"v":"KERI10JSON000113_","t":"rpy","d":"Emnz_fz7suVJmKAqC-Kt8VQu6cTXuWJ4ciSEnLGYIjLs","dt":"2022-06-20T15:16:52.679568+00:00","r":"/end/role/add","a":{"cid":"EY5lVApVptXa2Or0QBXnYJC4gp-sdQQ4wGMTJQsFUY7w","role":"watcher","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
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
          '5A6DF1A29EA3991A3F3C8A68ACCEDDD740AE0B51EFA8B66D49DC4A76DF09B973E75045583C90FA478016745B2C44E120F6527A3870FFC663AF4BC6DAEEEF2605';
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
          '5A6DF1A29EA3991A3F3C8A68ACCEDDD740AE0B51EFA8B66D49DC4A76DF09B973E75045583C90FA478016745B2C44E120F6527A3870FFC663AF4BC6DAEEEF2605';
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
          '5A6DF1A29EA3991A3F3C8A68ACCEDDD740AE0B51EFA8B66D49DC4A76DF09B973E75045583C90FA478016745B2C44E120F6527A3870FFC663AF4BC6DAEEEF2605';
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
        expect(e, const ex.isInstanceOf<ControllerNotInitializedException>());
      }
    });
  });

  group('getKel()', () {
    test('the getKel passes', () async {
      await Keri.initKel(inputAppDir: 'keritest');
      expect(
          await Keri.getKel(
              cont: await Keri.newIdentifier(idStr: 'ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE')),
          '{"v":"KERI10JSON00012b_","t":"icp","d":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","i":"ENHwqUzQVZqy6ugSvgpzzMVMB2PaymhQm9cU0cPdPlwE","s":"0","kt":"1","k":["D6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["ERnMydUxS3HsugRxKTx104D1YLQG6AouPwW0weJo9UYM"],"bt":"0","b":[],"c":[],"a":[]}-AABAADN2NR6T6QxFtYn4UEPhNtQFiUewE39_8A28jB-3UT-8n9_chNJ5P9AdAqJhHI73QO-Crqul3QUNtL0X7WI4OBQ');
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

    // test('the getKel fails, because of incorrect controller string', () async {
    //   await Keri.initKel(inputAppDir: 'keritest');
    //   try {
    //     await Keri.getKel(cont: await Keri.newIdentifier(idStr: 'fail'));
    //     fail("exception not thrown");
    //   } catch (e) {
    //     expect(e, const ex.isInstanceOf<IdentifierException>());
    //   }
    // });
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
      var controller = await Keri.finalizeInception(
          event: icp_event,
          signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      var anchor_event =
          await Keri.anchorDigest(controller: controller, sais: sais);
      print(anchor_event);
      var signature2 =
          '4217975CFDB10693AC0463FB399C9A8F26051C1BEB3DE2A71BCB7C6438C360AE73E2A2E2E86BDD300E8A7ABF01856EB4A19DCBFCCDDED098404063DD8A07A302';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
          '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
        '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
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
        '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
    var res = await Keri.finalizeEvent(
        identifier: controller,
        event: rotation_event,
        signature:
            await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));
    var anchor_event = await Keri.anchor(
        controller: controller, data: 'data', algo: DigestType.blake3256());
    print(anchor_event);
    var signature3 =
        'CB16207214C91415809068126F6846E86B0404D1ACFEEF5CE853DED53CD70EED2BC0368E048CB68ADC1D637FE2DB09F624126387FF02C2E48FD2E3B02BE4D30F';
    var res2 = await Keri.finalizeEvent(
        identifier: controller,
        event: anchor_event,
        signature:
            await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature3));
    expect(res2, true);
  });

  group('newPublicKey', () {
    test('The key creation fails, because the key is not a Base64 string',
            () async {
          await Keri.initKel(inputAppDir: 'keritest');
          List<PublicKey> vec1 = [];
          try {
            vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64:  'failKey'));
            fail("exception not thrown");
          } catch (e) {
            expect(e, const ex.isInstanceOf<IncorrectKeyFormatException>());
          }
        });
  });

  group('newIdentifier', () {
    test('The identifier creation fails, because of invalid identifier string ',
            () async {
      try {
        var controller =  await Keri.newIdentifier(idStr: 'fail');
        fail("exception not thrown");
      } catch (e) {
        expect(e, const ex.isInstanceOf<IdentifierException>());
      }
    });
  });

  test('Multisig use case', () async{
    await Keri.initKel(inputAppDir: 'keritest');

    String witness_id = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
    String wit_location = '{"eid":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

    List<PublicKey> vec1 = [];
    vec1.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    List<PublicKey> vec2 = [];
    vec2.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    List<String> vec3 = [wit_location];
    var icp_event = await Keri.incept(
        publicKeys: vec1,
        nextPubKeys: vec2,
        witnesses: vec3,
        witnessThreshold: 1);
    print(icp_event);
    var signature =
        'A2FA422FD0786321C44E6B16231EFB83A6BDC7A71EA7A35B50279C099DB9D6CE52941160E996351CC321832FF2D8C9757B89278B4C55B3BF35C7C23D38850102';
    var controller = await Keri.finalizeInception(
        event: icp_event,
        signature:
        await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature));

    List<String> vec4 = [];
    vec4.add(witness_id);

    //var query = await Keri.queryMailbox(whoAsk: controller, aboutWho: controller, witness: vec4);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query = '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature2 = 'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
    var finalizeQuery = await Keri.finalizeMailboxQuery(identifier: controller, queryEvent: query, signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature2));

    var initiatorKel = await Keri.getKel(cont: controller);
    var switchController = await Keri.api.changeController(dbPath: 'keritest2');

    var process = await Keri.processStream(stream: initiatorKel);
    List<PublicKey> vec11 = [];
    vec11.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
    List<PublicKey> vec22 = [];
    vec22.add(await Keri.newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
    List<String> vec33 = [wit_location];
    var icp_event2 = await Keri.incept(
        publicKeys: vec11,
        nextPubKeys: vec22,
        witnesses: vec33,
        witnessThreshold: 1);
    print(icp_event2);
    var signature3 = 'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
    var participant = await Keri.finalizeInception(
        event: icp_event2,
        signature:
        await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature3));

    //var query2 = await Keri.queryMailbox(whoAsk: participant, aboutWho: participant, witness: vec4);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query2 = '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature4 = '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
    var finalizeQuery2 = await Keri.finalizeMailboxQuery(identifier: participant, queryEvent: query2, signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature4));

    var participantKel = await Keri.getKel(cont: participant);
    var changeController = await Keri.api.changeController(dbPath: 'keritest');
    var process2 = await Keri.processStream(stream: participantKel);

    var icp = await Keri.inceptGroup(identifier: controller, participants: [participant], signatureThreshold: 2, initialWitnesses: vec4, witnessThreshold: 1);
    var signature5 = '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
    var signatureex = '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
    //
    var fgi = await Keri.finalizeGroupIncept(identifier: controller, groupEvent: icp.icpEvent, signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature5), toForward: [await Keri.newDataAndSignature(data: icp.exchanges[0], signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signatureex))]);

    //var changeController2 = await Keri.api.changeController(dbPath: 'keritest2');
    //var query3 = await Keri.queryMailbox(whoAsk: participant, aboutWho: participant, witness: vec4);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    //var query3 = '{"v":"KERI10JSON00018e_","t":"qry","d":"EDhRwPEWsAhk45GokK_eSX1HjWIkyuU0fDg-clNk4SrU","dt":"2022-10-21T15:09:49.403737+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    //var signature6 = 'BB07D321C483A5593CD9CFC3981046D5CFF61C2AC025020A11C780C20B0D8A1C1AE749002C44FAB52269CDB2C5D975CDF87447BD28D8FBEA67F590D57B89FF03';
    // var finalizeQuery3 = await Keri.finalizeMailboxQuery(identifier: participant, queryEvent: query3, signature: await Keri.signatureFromHex(st: SignatureType.Ed25519Sha512, signature: signature6));
    // print('finalize: $finalizeQuery3');
  });
}
