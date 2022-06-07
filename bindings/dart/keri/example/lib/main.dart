import 'package:asymmetric_crypto_primitives/asymmetric_crypto_primitives.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:keri/bridge_generated.dart';
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _platformVersion = 'Unknown';
  final _keriPlugin = Keri();

  @override
  void initState() {
    initKel();
    super.initState();
  }

  Future<void> initKel()async {
    var signer = await AsymmetricCryptoPrimitives.establishForEd25519();
    var dir = await getLocalPath();
    var conf = Config(initialOobis: "[{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}]");
    var oobiString = "[\"{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:3232/\"}\"]";
    print(conf);
    await Keri.initKel(inputAppDir: dir);
    print('initialized');
    //var key_pub_1 = '6gWY4Y+k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
   // var key_pub_2 = 'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
    var key_pub_1 = await signer.getCurrentPubKey();
    var key_pub_2 = await signer.getNextPubKey();
    List<PublicKey> vec1 = [];
    vec1.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_1));
    List<PublicKey> vec2 = [];
    vec2.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_2));
    List<String> vec3 = [];
    var icp_event = await Keri.incept(publicKeys: vec1, nextPubKeys: vec2, witnesses: vec3, witnessThreshold: 0);
    print('icp');
    var signature = await signer.sign(icp_event);
    print(signature);
    //print(icp_event);
    //var ev = '{"v":"kotki","t":"icp","d":"E1IsYB9Ei_F9cJvtrnsug5aopeU62OF2kej-YBtMuLRo","i":"E1IsYB9Ei_F9cJvtrnsug5aopeU62OF2kej-YBtMuLRo","s":"0","kt":"1","k":["Bv4AzLgC8riN3ZKWz8NERNdLmYvgCjYCrc0l8OZql1aM"],"nt":"1","n":["EHODwKX9ygXX033OrDW9P_PTmfAmL9xM6DOqya2heG0Y"],"bt":"0","b":[],"c":[],"a":[]}';
    var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
    //var kel = await Keri.getKel(cont: Controller(identifier: 'cat'));
    await signer.rotateForEd25519();
    var key_pub_3 = await signer.getCurrentPubKey();
    var key_pub_4 = await signer.getNextPubKey();
    List<PublicKey> currentKeys = [];
    List<PublicKey> newNextKeys = [];
    currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_3));
    newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_4));

    var result = await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: ['cat'], witnessThreshold: 0);

  }


  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Text('Running on: $_platformVersion\n'),
        ),
      ),
    );
  }

  Future<String> getLocalPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
}
