import 'package:flutter_test/flutter_test.dart';
import 'package:keri_android/exceptions.dart';
import 'package:keri/keri.dart';
//import 'package:test/expect.dart' as ex;

void main() {
  // var dylib = DynamicLibrary.open(Platform.script.resolve("example/windows/flutter/ephemeral/.plugin_symlinks/keri_windows/windows/dartkeriox/dartkeriox.dll").toFilePath());
  // var api = KeriDartImpl(dylib);

  var publicKey1 = '6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
  var publicKey2 = 'GoP8qjXbUcnpMWtDeRuN_AT0pA7F5gFjrv8UdxrEJW0=';
  const publicKey3 = 'vyr60mQ4dvwa5twsC7N7Nx0UAF4nqCDLfibDY0dJovE=';
  const publicKey4 = 'u3q0mOY39YX67uFq3gi29UCfjXp-SB_iuTRg-kzbB2o=';
  //const privateKey2 =
  'pDRM5oADe-AYGUIap2O9r9mt7Ue7F3mwBD9UU2rt7Lsag_yqNdtRyekxa0N5G438BPSkDsXmAWOu_xR3GsQlbQ==';
  //const privateKey3 =
  'lfcTwZDsgE0ZcLv4YGBJVAaLE-BMSSlMk8v1eEQhqJm_KvrSZDh2_Brm3CwLs3s3HRQAXieoIMt-JsNjR0mi8Q==';
  //const privateKey4 =
  'lew7zHsQfEaxTjyNU_F3yJInfidMyaiCeJfjXiNTDZ67erSY5jf1hfru4WreCLb1QJ-Nen5IH-K5NGD6TNsHag==';
  group("initKel()", () {
    test('The kel fails to init as optionalConfigs contain incorrect data',
        () async {
      try {
        await initKel(
            inputAppDir: 'keritest',
            optionalConfigs: const Config(initialOobis: 'cat'));
        fail("exception not thrown");
      } catch (e) {
        //expect(e, IncorrectOptionalConfigsException);
        expect(e, isInstanceOf<IncorrectOptionalConfigsException>());
      }
    });

    test(
        'The kel fails to init as nobody is listening on the port provided in optionalConfigs',
        () async {
      var conf = const Config(
          initialOobis:
              "[{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}]");
      try {
        await initKel(inputAppDir: 'keritest', optionalConfigs: conf);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<OobiResolvingErrorException>());
      }
    });
  });

  group("incept()", () {
    test('The inception passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      expect(
          await incept(
              publicKeys: vec1,
              nextPubKeys: vec2,
              witnesses: vec3,
              witnessThreshold: 0),
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","i":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","s":"0","kt":"1","k":["DOoFmOGPpNrfShWWkpEeY1CJzmBKDpbgA7VpmMbD5JZ9"],"nt":"1","n":["EFs9ie55d09gIphYTYGtz6IbnvnWoaQHf97aU5wAdbni"],"bt":"0","b":[],"c":[],"a":[]}');
    });

    test('The inception fails, because the provided witness oobi is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = ['incorrect'];
      try {
        await incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectWitnessOobiException>());
      }
    });

    test(
        'The inception fails, because the provided witness prefix is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"ESuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}"
      ];
      try {
        await incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test(
        'The inception fails, because nobody is listening on the port provided for witness',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"
      ];
      try {
        await incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The inception fails, because the controller wasn\'t initiated',
        () async {
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [
        "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}"
      ];
      try {
        await incept(
            publicKeys: vec1,
            nextPubKeys: vec2,
            witnesses: vec3,
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<ControllerNotInitializedException>());
      }
    });
  });

  group('finalizeInception()', () {
    test('The finalize inception passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      expect(controller.id, 'EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ');
    });

    test('The finalize inception fails, because the signature fails to verify',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'A8390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
      try {
        await finalizeInception(
            event: icpEvent,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<SignatureVerificationException>());
      }
    });

    test('The finalize inception fails, because the initKel() was not executed',
        () async {
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      //List<String> vec3 = [];
      var icpEvent =
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","i":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","s":"0","kt":"1","k":["D6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0"],"nt":"1","n":["ERnMydUxS3HsugRxKTx104D1YLQG6AouPwW0weJo9UYM"],"bt":"0","b":[],"c":[],"a":[]}';
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      try {
        await finalizeInception(
            event: icpEvent,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<ControllerNotInitializedException>());
      }
    });

    test(
        'The finalize inception fails, because the icp event is not a correct string',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      try {
        await finalizeInception(
            event: 'failEvent',
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WrongEventException>());
      }
    });
  });

  group('rotate()', () {
    test('The rotation passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      expect(
          await rotate(
              controller: controller,
              currentKeys: currentKeys,
              newNextKeys: newNextKeys,
              witnessToAdd: [],
              witnessToRemove: [],
              witnessThreshold: 0),
          '{"v":"KERI10JSON000160_","t":"rot","d":"EDtGs_F-nIvY8MzlciXqT0Rtwlte0XJlx8RGdUdK60HC","i":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","s":"1","p":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","kt":"1","k":["DBqD_Ko121HJ6TFrQ3kbjfwE9KQOxeYBY67_FHcaxCVt"],"nt":"1","n":["EDRC8v52LOzjDYLvTg-ttJavkQQ8rhJyBRH4s3nuIok8"],"bt":"0","br":[],"ba":[],"a":[]}');
    });

    test('The rotation fails, because of wrong witnessToAdd', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: ['fail'],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectOobiException>());
      }
    });

    test('The rotation fails, because of wrong witnessToRemove', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await rotate(
            controller: controller,
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: ['fail'],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WitnessParsingException>());
      }
    });

    test('The rotation fails, because of wrong witness prefix', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await rotate(
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
        expect(e, isInstanceOf<ImproperWitnessPrefixException>());
      }
    });

    test(
        'The rotation fails, because nobody is listening on the port provided to witness',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await rotate(
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
        expect(e, isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('The rotation fails, because of unknown controller identifier',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      try {
        await rotate(
            controller: await newIdentifier(
                idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'),
            currentKeys: currentKeys,
            newNextKeys: newNextKeys,
            witnessToAdd: [],
            witnessToRemove: [],
            witnessThreshold: 0);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  group('addWatcher()', () {
    test(
        'addWatcher fails, because nobody is listening on the port provided in watcher.',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      try {
        await addWatcher(
            controller: await newIdentifier(
                idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            watcherOobi:
                "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}");
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<OobiResolvingErrorException>());
      }
    });

    test('addWatcher fails, because watcher Oobi is incorrect.', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      try {
        await addWatcher(
            controller: await newIdentifier(
                idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            watcherOobi: "fail");
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectWatcherOobiException>());
      }
    });
  });

  group('resolveOobi()', () {
    test('resolveOobi fails, because oobi is an empty string', () async {
      await initKel(inputAppDir: 'keritest');
      try {
        await resolveOobi(oobiJson: '');
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectOobiException>());
      }
    });

    test('resolveOobi fails, because oobi is an incorrect string', () async {
      await initKel(inputAppDir: 'keritest');
      try {
        await resolveOobi(oobiJson: 'fail');
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectOobiException>());
      }
    });

    test('resolveOobi fails, because nobody listens on port provided in oobi',
        () async {
      await initKel(inputAppDir: 'keritest');
      try {
        await resolveOobi(
            oobiJson:
                "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}");
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<OobiResolvingErrorException>());
      }
    });
  });

  group('finalizeEvent()', () {
    test('finalizeEvent passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotationEvent = await rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          '85DA2F2263541482F38307091E891DB53779FF1436D80EC2741731B75A16B14711B29B18137042FEF6304DD0B3D90DC07AA5EC1116E33564A5A58544F7C55009';
      var res = await finalizeEvent(
          identifier: controller,
          event: rotationEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('finalizeEvent fails, because signature is incorrect', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      var rotationEvent = await rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      //var signature2 =
      '85DA2F2263541482F38307091E891DB53779FF1436D80EC2741731B75A16B14711B29B18137042FEF6304DD0B3D90DC07AA5EC1116E33564A5A58544F7C55009';
      try {
        await finalizeEvent(
            identifier: controller,
            event: rotationEvent,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<SignatureVerificationException>());
      }
    });

    test('finalizeEvent fails, because event string is not a correct string',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      //MOCK ROTATION
      publicKey1 = publicKey2;
      publicKey2 = publicKey3;
      List<PublicKey> currentKeys = [];
      List<PublicKey> newNextKeys = [];
      currentKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      newNextKeys
          .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      await rotate(
          controller: controller,
          currentKeys: currentKeys,
          newNextKeys: newNextKeys,
          witnessToAdd: [],
          witnessToRemove: [],
          witnessThreshold: 0);
      var signature2 =
          '85DA2F2263541482F38307091E891DB53779FF1436D80EC2741731B75A16B14711B29B18137042FEF6304DD0B3D90DC07AA5EC1116E33564A5A58544F7C55009';
      try {
        await finalizeEvent(
            identifier: controller,
            event: 'fail',
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WrongEventException>());
      }
    });
  });

  group('getKel()', () {
    test('the getKel passes', () async {
      await initKel(inputAppDir: 'keritest');
      expect(
          await getKel(
              cont: await newIdentifier(
                  idStr: 'EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ')),
          '{"v":"KERI10JSON00012b_","t":"icp","d":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","i":"EEdHeswXSuw6nl_T9tgjb5mDbJGVWy6mv1JeGQRmz4VQ","s":"0","kt":"1","k":["DOoFmOGPpNrfShWWkpEeY1CJzmBKDpbgA7VpmMbD5JZ9"],"nt":"1","n":["EFs9ie55d09gIphYTYGtz6IbnvnWoaQHf97aU5wAdbni"],"bt":"0","b":[],"c":[],"a":[]}-AABAACvZh1I9Km9vdSXTMUqCG-_qV7LQFGV9CBISG2yb2t8zu_JjFlN056bmqjB9If2jnLO9U5IBO-gjDYcfcRqYjYF');
    });

    test('the getKel fails, because of unknown controller identifier',
        () async {
      await initKel(inputAppDir: 'keritest');
      try {
        await getKel(
            cont: await newIdentifier(
                idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc5bx40'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  group('anchorDigest', () {
    test('anchorDigest passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      var anchorEvent = await anchorDigest(controller: controller, sais: sais);
      //print(anchorEvent);
      var signature2 =
          'ECF5CDCDDFB86D88F16FE600B242DD91F55E962330DBCD59E0DF304BE64A730B86215489104C9FE9638282F6027FE754E13E65522965F2364D1EA2B90EF7580A';
      var res = await finalizeEvent(
          identifier: controller,
          event: anchorEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('anchorDigest fails, because the sai is incorrect', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "fail";
      sais.add(sai);
      try {
        await anchorDigest(controller: controller, sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<SelfAddressingIndentifierException>());
      }
    });

    test('anchorDigest fails, because the controller is unknown', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var hexsig = await signatureFromHex(
          st: SignatureType.Ed25519Sha512, signature: signature);
      await finalizeInception(event: icpEvent, signature: hexsig);
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        await anchorDigest(
            controller: await newIdentifier(
                idStr: 'E2e7tLvlVlER4kkV3bw36SN8Gz3fJ-3QR2xadxKyed10'),
            sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('anchorDigest fails, because the controller is incorrect', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        await anchorDigest(
            controller: await newIdentifier(idStr: 'fail'), sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('anchorDigest fails, because the controller was not initialized',
        () async {
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        await anchorDigest(
            controller: await newIdentifier(
                idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40'),
            sais: sais);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  group('anchor', () {
    test('anchor passes', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      var controller = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      var anchorEvent = await anchor(
          controller: controller,
          data: 'data',
          algo: const DigestType.blake3256());
      //print(anchorEvent);
      var signature2 =
          '3252B33AADA0792408AE5681979F67C98DD9F5109AECF74DB09CDA1F5BDC754F7650C47625A584BE55E8265CB6F8D63190EF9CFA149997E7B4BFE11F428EE309';
      var res = await finalizeEvent(
          identifier: controller,
          event: anchorEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));
      expect(res, true);
    });

    test('anchor fails, because the controller is unknown', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        await anchor(
            controller: await newIdentifier(
                idStr: 'E2e7tLvlVlER4kkV3bw36SN8Gz3fJ-3QR2xadxKyed10'),
            data: 'data',
            algo: const DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller is incorrect', () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [];
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 0);
      var signature =
          'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        await anchor(
            controller: await newIdentifier(idStr: 'fail'),
            data: 'data',
            algo: const DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('anchor fails, because the controller was not initialized', () async {
      List<String> sais = [];
      var sai = "EsiSh2iv15yszfcbd5FegUmWgbeyIdb43nirSvl7bO_I";
      sais.add(sai);
      try {
        var identifier = await newIdentifier(
            idStr: 'EgSYLoqAIXEiQla3gRLudzeyWibl1hwmWcvxWlc6bx40');
        await anchor(
            controller: identifier,
            data: 'data',
            algo: const DigestType.blake3256());
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<ControllerNotInitializedException>());
      }
    });
  });

  test('Full use case', () async {
    await initKel(inputAppDir: 'keritest');
    List<PublicKey> vec1 = [];
    vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    List<PublicKey> vec2 = [];
    vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    List<String> vec3 = [];
    var icpEvent = await incept(
        publicKeys: vec1,
        nextPubKeys: vec2,
        witnesses: vec3,
        witnessThreshold: 0);
    var signature =
        'AF661D48F4A9BDBDD4974CC52A086FBFA95ECB405195F42048486DB26F6B7CCEEFC98C594DD39E9B9AA8C1F487F68E72CEF54E4804EFA08C361C7DC46A623605';
    var controller = await finalizeInception(
        event: icpEvent,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature));
    //MOCK ROTATION
    publicKey1 = publicKey2;
    publicKey2 = publicKey3;
    List<PublicKey> currentKeys = [];
    List<PublicKey> newNextKeys = [];
    currentKeys
        .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    newNextKeys
        .add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    var rotationEvent = await rotate(
        controller: controller,
        currentKeys: currentKeys,
        newNextKeys: newNextKeys,
        witnessToAdd: [],
        witnessToRemove: [],
        witnessThreshold: 0);
    var signature2 =
        '85DA2F2263541482F38307091E891DB53779FF1436D80EC2741731B75A16B14711B29B18137042FEF6304DD0B3D90DC07AA5EC1116E33564A5A58544F7C55009';
    await finalizeEvent(
        identifier: controller,
        event: rotationEvent,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature2));
    var anchorEvent = await anchor(
        controller: controller,
        data: 'data',
        algo: const DigestType.blake3256());
    //print(anchorEvent);
    var signature3 =
        '34A7E8215C0E0B8259E891214F44C343DCC8406E330FCDA8866BD79804F455F8FD0BC428B82374F6AA907417FB38BF13AD983AF0C20E62298151DD36988E6907';
    var res2 = await finalizeEvent(
        identifier: controller,
        event: anchorEvent,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature3));
    expect(res2, true);
  });

  group('newPublicKey', () {
    test('The key creation fails, because the key is not a Base64 string',
        () async {
      await initKel(inputAppDir: 'keritest');
      List<PublicKey> vec1 = [];
      try {
        vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: 'failKey'));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectKeyFormatException>());
      }
    });

    test('The key creation fails, because the key is of a wrong length',
        () async {
      List<PublicKey> vec1 = [];
      try {
        vec1.add(await newPublicKey(
            kt: KeyType.Ed25519,
            keyB64:
                'lew7zHsQfEaxTjyNU/F3yJInfidMyaiCeJfjXiNTDZ67erSY5jf1hfru4WreCLb1QJ+Nen5IH+K5NGD6TNsHag=='));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectKeyFormatException>());
      }
    });
  });

  group('newIdentifier', () {
    test('The identifier creation fails, because of invalid identifier string ',
        () async {
      try {
        await newIdentifier(idStr: 'fail');
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  group("signatureFromHex", () {
    //Fails
    test('signature creation fails because of invalid hex string', () async {
      try {
        await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: 'fail');
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IncorrectSignatureException>());
      }
    });
  });

  group("queryMailbox", () {
    test('queryMailbox fails, because provided witness is incorrect', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //print(icpEvent);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);
      try {
        await queryMailbox(
            whoAsk: identifier, aboutWho: identifier, witness: ['fail']);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WitnessParsingException>());
      }
    });

    //Fails, used to check functions only
    test('queryMailbox fails, because provided witness has incorrect letter',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);
      try {
        await queryMailbox(
            whoAsk: await newIdentifier(
                idStr: 'Efrtu2CqKiP7YbWQ0c7X0VJU2i5E4V4frrlB72ytPBjQ'),
            aboutWho: identifier,
            witness: ['BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA']);
        fail("exception not thrown");
      } catch (e) {
        expect(e, NetworkErrorException);
      }
    });
  });

  group("finalizeQuery", () {
    test('finalizeQuery fails, because signature is incorrect', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      try {
        await finalizeQuery(
            identifier: identifier,
            queryEvent: query,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<SignatureVerificationException>());
      }
    });

    test('finalizeQuery fails, because query event is incorrect', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //MOCK QUERY MAILBOX because signature changes with every test run.
      //var query =
      '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      try {
        await finalizeQuery(
            identifier: identifier,
            queryEvent: 'fail',
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WrongEventException>());
      }
    });

    //Fails, will be corrected soon
    test('finalizeQuery fails, because identifier is unknown', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      try {
        await finalizeQuery(
            identifier: await newIdentifier(
                idStr: 'Efrtu2CqKiP7YbWQ0c7X0VJU2i5E4V4frrlB72ytPBjQ'),
            queryEvent: query,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature2));
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<WrongEventException>());
      }
    });
  });

  group('inceptGroup', () {
    test('inceptGroup passes', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      var icp = await inceptGroup(
          identifier: identifier,
          participants: [participant],
          signatureThreshold: 2,
          initialWitnesses: witnessIdList,
          witnessThreshold: 1);
      expect(icp.icpEvent,
          '{"v":"KERI10JSON0001b7_","t":"icp","d":"EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80","i":"EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80","s":"0","kt":"2","k":["D6gWY4Y-k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0","Dvyr60mQ4dvwa5twsC7N7Nx0UAF4nqCDLfibDY0dJovE"],"nt":"1","n":["ERnMydUxS3HsugRxKTx104D1YLQG6AouPwW0weJo9UYM","EhWifOnJf1PdwY-5VeWNTYecSNOtOfyT9JWxiCdR5nAY"],"bt":"1","b":["DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"c":[],"a":[]}');
    });

    test('inceptGroup fails, because the signature treshold is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      try {
        await inceptGroup(
            identifier: identifier,
            participants: [participant],
            signatureThreshold: -2,
            initialWitnesses: witnessIdList,
            witnessThreshold: 1);
        fail("exception not thrown");
      } catch (e) {
        expect(e, ImproperSignatureThresholdException);
      }
    });

    test('inceptGroup fails, because the witness treshold is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      try {
        await inceptGroup(
            identifier: identifier,
            participants: [participant],
            signatureThreshold: 2,
            initialWitnesses: witnessIdList,
            witnessThreshold: -1);
        fail("exception not thrown");
      } catch (e) {
        expect(e, ImproperWitnessThresholdException);
      }
    });

    test('inceptGroup fails, because the initial witness id is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      try {
        await inceptGroup(
            identifier: identifier,
            participants: [participant],
            signatureThreshold: 2,
            initialWitnesses: ['fail'],
            witnessThreshold: 1);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('inceptGroup fails, because the participant is unknown', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      try {
        await inceptGroup(
            identifier: identifier,
            participants: [
              await newIdentifier(
                  idStr: 'Efrtu2CqKiP7YbWQ0c7X0VJU2i5E4V4frrlB72ytPBjQ')
            ],
            signatureThreshold: 2,
            initialWitnesses: witnessIdList,
            witnessThreshold: 1);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });

    test('inceptGroup fails, because the identifier is unknown', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      try {
        await inceptGroup(
            identifier: await newIdentifier(
                idStr: 'Efrtu2CqKiP7YbWQ0c7X0VJU2i5E4V4frrlB72ytPBjQ'),
            participants: [participant],
            signatureThreshold: 2,
            initialWitnesses: witnessIdList,
            witnessThreshold: 1);
        fail("exception not thrown");
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  group('finalizeGroupIncept', () {
    test('finalizeGroupIncept passes', () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      var icp = await inceptGroup(
          identifier: identifier,
          participants: [participant],
          signatureThreshold: 2,
          initialWitnesses: witnessIdList,
          witnessThreshold: 1);
      //Signed incept event from icp
      var signature5 =
          '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
      //Signed exchanges
      var signatureex =
          '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
      var groupIdentifier = await finalizeGroupIncept(
          identifier: identifier,
          groupEvent: icp.icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature5),
          toForward: [
            await newDataAndSignature(
                data: icp.exchanges[0],
                signature: await signatureFromHex(
                    st: SignatureType.Ed25519Sha512, signature: signatureex))
          ]);
      expect(
          groupIdentifier.id, 'EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80');
    });

    //Fails, should be corrected
    test(
        'finalizeGroupIncept fails, because the toForward signature is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      var icp = await inceptGroup(
          identifier: identifier,
          participants: [participant],
          signatureThreshold: 2,
          initialWitnesses: witnessIdList,
          witnessThreshold: 1);
      //Signed incept event from icp
      var signature5 =
          '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
      //Signed exchanges
      //var signatureex =
      '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
      await finalizeGroupIncept(
          identifier: identifier,
          groupEvent: icp.icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature5),
          toForward: [
            await newDataAndSignature(
                data: icp.exchanges[0],
                signature: await signatureFromHex(
                    st: SignatureType.Ed25519Sha512, signature: signature5))
          ]);
    });

    test('finalizeGroupIncept fails, because group event is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      var icp = await inceptGroup(
          identifier: identifier,
          participants: [participant],
          signatureThreshold: 2,
          initialWitnesses: witnessIdList,
          witnessThreshold: 1);
      //Signed incept event from icp
      var signature5 =
          '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
      //Signed exchanges
      var signatureex =
          '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
      try {
        await finalizeGroupIncept(
            identifier: identifier,
            groupEvent: 'fail',
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature5),
            toForward: [
              await newDataAndSignature(
                  data: icp.exchanges[0],
                  signature: await signatureFromHex(
                      st: SignatureType.Ed25519Sha512, signature: signatureex))
            ]);
      } catch (e) {
        expect(e, isInstanceOf<WrongEventException>());
      }
    });

    test('finalizeGroupIncept fails, because identifier is incorrect',
        () async {
      await initKel(inputAppDir: 'keritest');

      String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
      String witLocation =
          '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

      //Create identifier keys
      List<PublicKey> vec1 = [];
      vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
      List<PublicKey> vec2 = [];
      vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
      List<String> vec3 = [witLocation];

      //Incept identifier
      var icpEvent = await incept(
          publicKeys: vec1,
          nextPubKeys: vec2,
          witnesses: vec3,
          witnessThreshold: 1);
      //Signed icp_event
      var signature =
          'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
      var identifier = await finalizeInception(
          event: icpEvent,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature));

      List<String> witnessIdList = [];
      witnessIdList.add(witnessId);

      //Query mailbox
      //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query
      var signature2 =
          'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
      await finalizeQuery(
          identifier: identifier,
          queryEvent: query,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature2));

      var initiatorKel = await getKel(cont: identifier);
      await changeController(dbPath: 'keritest2');
      await processStream(stream: initiatorKel);

      //Create participant keys
      List<PublicKey> vec11 = [];
      vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
      List<PublicKey> vec22 = [];
      vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
      List<String> vec33 = [witLocation];

      //Incept participant
      var icpEvent2 = await incept(
          publicKeys: vec11,
          nextPubKeys: vec22,
          witnesses: vec33,
          witnessThreshold: 1);
      //Signed icp_event2
      var signature3 =
          'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
      var participant = await finalizeInception(
          event: icpEvent2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature3));

      //Query mailbox
      //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
      //MOCK QUERY MAILBOX because signature changes with every test run.
      var query2 =
          '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
      //Signed query2
      var signature4 =
          '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
      await finalizeQuery(
          identifier: participant,
          queryEvent: query2,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: signature4));

      var participantKel = await getKel(cont: participant);
      await changeController(dbPath: 'keritest');
      await processStream(stream: participantKel);

      //Incept group identifier
      var icp = await inceptGroup(
          identifier: identifier,
          participants: [participant],
          signatureThreshold: 2,
          initialWitnesses: witnessIdList,
          witnessThreshold: 1);
      //Signed incept event from icp
      var signature5 =
          '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
      //Signed exchanges
      var signatureex =
          '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
      try {
        await finalizeGroupIncept(
            identifier: await newIdentifier(
                idStr: 'Efrtu2CqKiP7YbWQ0c7X0VJU2i5E4V4frrlB72ytPBjQ'),
            groupEvent: icp.icpEvent,
            signature: await signatureFromHex(
                st: SignatureType.Ed25519Sha512, signature: signature5),
            toForward: [
              await newDataAndSignature(
                  data: icp.exchanges[0],
                  signature: await signatureFromHex(
                      st: SignatureType.Ed25519Sha512, signature: signatureex))
            ]);
      } catch (e) {
        expect(e, isInstanceOf<IdentifierException>());
      }
    });
  });

  test('Multisig use case', () async {
    await initKel(inputAppDir: 'keritest');

    String witnessId = "DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
    String witLocation =
        '{"eid":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}';

    //Create identifier keys
    List<PublicKey> vec1 = [];
    vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey1));
    List<PublicKey> vec2 = [];
    vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey2));
    List<String> vec3 = [witLocation];

    //Incept identifier
    var icpEvent = await incept(
        publicKeys: vec1,
        nextPubKeys: vec2,
        witnesses: vec3,
        witnessThreshold: 1);
    //Signed icp_event
    var signature =
        'FF0DF0EE9D25453DF225C897AAC2CE64F58DD070C07F5FDB080C475A0E297AEDB630919AC9442F6FE8C834A9A1C176C21F19ED6AA1B5683ADADC294947E8CC09';
    var identifier = await finalizeInception(
        event: icpEvent,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature));

    List<String> witnessIdList = [];
    witnessIdList.add(witnessId);

    //Query mailbox
    //var query = await queryMailbox(whoAsk: controller, aboutWho: controller, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"EOsIfpnrmxFwD1OPC6k06BkUBmaf0jdzZUqy-SD4ZqI8","dt":"2022-10-21T11:32:22.157953+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    //Signed query
    var signature2 =
        'AEF84C04A84C12EBC20735AAEC54AC1DE8964754E35B0C9B92F7AA0E1FF9C835050A14EFC26A2DCE3CCD7100795AD9CAC0DC3DE1CE6E823393837069336C540A';
    await finalizeQuery(
        identifier: identifier,
        queryEvent: query,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature2));

    var initiatorKel = await getKel(cont: identifier);
    await changeController(dbPath: 'keritest2');
    await processStream(stream: initiatorKel);

    //Create participant keys
    List<PublicKey> vec11 = [];
    vec11.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey3));
    List<PublicKey> vec22 = [];
    vec22.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: publicKey4));
    List<String> vec33 = [witLocation];

    //Incept participant
    var icpEvent2 = await incept(
        publicKeys: vec11,
        nextPubKeys: vec22,
        witnesses: vec33,
        witnessThreshold: 1);
    //Signed icp_event2
    var signature3 =
        'DBD3BA4A8254FBFB496C8BEFEF0F8F51F3BE165731FAA9ECF641CC96ADA2704803A967B55275960B49FDECD68CD58289AADBCADA950C8B54548842DF4EAE0D0C';
    var participant = await finalizeInception(
        event: icpEvent2,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature3));

    //Query mailbox
    //var query2 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query2 =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"E5d9qJagbXKqYJGc3JQG4e7s9aeuRioljXYr2_GjLBP0","dt":"2022-10-21T14:51:32.655073+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    //Signed query2
    var signature4 =
        '5079E6644087D3AD854E8C8EBC5215671190EB407BA4A99A2C4B292C185BBB72849276284FE9BD9CFE85F00D02F710BA6399F1F3919E76680207D75CEEDF5102';
    await finalizeQuery(
        identifier: participant,
        queryEvent: query2,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature4));

    var participantKel = await getKel(cont: participant);
    await changeController(dbPath: 'keritest');
    await processStream(stream: participantKel);

    //Incept group identifier
    var icp = await inceptGroup(
        identifier: identifier,
        participants: [participant],
        signatureThreshold: 2,
        initialWitnesses: witnessIdList,
        witnessThreshold: 1);
    //Signed incept event from icp
    var signature5 =
        '4F9782BF238408908344FD36D66D7A3507F7D70A26A40F608247F5BD57F51B3F6E15886B268592A5F64D37BAAFE5D003564DC3AC7352F1D7F6B46789BE0C7504';
    //Signed exchanges
    var signatureex =
        '353B6251889958472BE0A033208960CA510722FEDB9C2B67CE4DD190F75665C0EA663E01E1091D9C60E24D4D080BAC76859EE52B057B6C422466581AFF648608';
    var groupIdentifier = await finalizeGroupIncept(
        identifier: identifier,
        groupEvent: icp.icpEvent,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature5),
        toForward: [
          await newDataAndSignature(
              data: icp.exchanges[0],
              signature: await signatureFromHex(
                  st: SignatureType.Ed25519Sha512, signature: signatureex))
        ]);

    await changeController(dbPath: 'keritest2');

    //Query mailbox to get participant signature. Mailbox content should contain MultisigRequest
    //var query3 = await queryMailbox(whoAsk: participant, aboutWho: participant, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query3 =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"EDhRwPEWsAhk45GokK_eSX1HjWIkyuU0fDg-clNk4SrU","dt":"2022-10-21T15:09:49.403737+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature6 =
        'BB07D321C483A5593CD9CFC3981046D5CFF61C2AC025020A11C780C20B0D8A1C1AE749002C44FAB52269CDB2C5D975CDF87447BD28D8FBEA67F590D57B89FF03';
    List<ActionRequired> finalizeQuery3 = await finalizeQuery(
        identifier: participant,
        queryEvent: query3,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature6));

    //Process multisig request
    if (finalizeQuery3[0].action == Action.MultisigRequest) {
      //Signed icp event from finalizeQuery3[0].data
      var icpsignature =
          '51605A9F3B371AB9D615EB11E045B21E5AF31170DF46A69B4C9359A52ACD0F2C3041EEC4ED8402828D540716DDD631FDFBD91F2F157E295EEDB228169DCC0902';
      //Signed every element from finalizeQuery[0].additionalData
      var icpexsignature =
          '250BD709C82FEF02DF09D84CAC9E7891E5976C69205BC0EFACDF43E6FB6F6A06E8F1DF6FCE4AE9EDA2954BEFD463131F3256D5ECD371C35AE0394FF018553309';
      await finalizeGroupIncept(
          identifier: participant,
          groupEvent: finalizeQuery3[0].data,
          signature: await signatureFromHex(
              st: SignatureType.Ed25519Sha512, signature: icpsignature),
          toForward: [
            await newDataAndSignature(
                data: finalizeQuery3[0].additionaData,
                signature: await signatureFromHex(
                    st: SignatureType.Ed25519Sha512, signature: icpexsignature))
          ]);
    }

    await changeController(dbPath: 'keritest');

    //Query group mailbox
    //var query4 = await queryMailbox(whoAsk: controller, aboutWho: group_identifier, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query4 =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"E2PheXm-3wCE0QrmeQm0RUxPZOWPio-CHHVftt3tPMdk","dt":"2022-10-24T11:47:52.172662+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature7 =
        '2E849AD6255F2680A3CD64561FBC3EF27A8C8B10EDE673E4EDEB00FE75AAB9FF4A2B497D00C9C2B9BE77A44A3FB81E15779C1C47F379DBE1224D4ADC2DBC8F0C';
    await finalizeQuery(
        identifier: identifier,
        queryEvent: query4,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature7));

    //Query mailbox to get group inception receipt - identifier
    //var query5 = await queryMailbox(whoAsk: controller, aboutWho: group_identifier, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query5 =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"Enr4_i6V2cn15u1gVdh6scKDGTEelTiV3gmxpzoPniQw","dt":"2022-10-24T11:52:03.898695+00:00","r":"mbx","rr":"","q":{"pre":"Efrtu1CqKiP7YbWQys7X0VJU2i5E4V4frrlB72ytPBjQ","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature8 =
        '3B770222210028A459489FB4590575B98BFC47F983A748415DCEC9452C76A9A0BCD1887C95214AAEE2E789F32D15581E9029750C1FCEC8FA660DA485CD1E4D04';
    await finalizeQuery(
        identifier: identifier,
        queryEvent: query5,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature8));

    await changeController(dbPath: 'keritest2');

    //Query mailbox to get group inception receipt - participant
    //var query6 = await queryMailbox(whoAsk: participant, aboutWho: group_identifier, witness: witness_id_list);
    //MOCK QUERY MAILBOX because signature changes with every test run.
    var query6 =
        '{"v":"KERI10JSON00018e_","t":"qry","d":"Ejc77kBLkrBfLVkSub8IKcgySzzvwiaOSytQswZBZhv0","dt":"2022-10-24T11:55:45.251661+00:00","r":"mbx","rr":"","q":{"pre":"EHoKPbM5hQpXdVfSDXk82rCFmHWWLAmku1mh1RbogZ0w","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EwjoX5xdJTPoAR5XeNzuxsFZHO3EMPVg7e5eSRCfps80","src":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"}}';
    var signature9 =
        '668A2F1EDB09E2E8268B5F8B4E822A8DB89DE62FA8DB1CD3D9A482D33A044BF28E4D42DC04DCED71A8911F3EE59D041A39F81AB18B99257A6EA10C4859ED1E04';
    await finalizeQuery(
        identifier: participant,
        queryEvent: query6,
        signature: await signatureFromHex(
            st: SignatureType.Ed25519Sha512, signature: signature9));

    await getKel(cont: groupIdentifier);
    //print(kel);
  });
}
