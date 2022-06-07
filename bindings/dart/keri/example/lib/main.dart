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
    var oobiString = "{\"eid\":\"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\",\"scheme\":\"http\",\"url\":\"http://sandbox.argo.colossi.network:8888/\"}";
    print(conf);
    //var kel = await Keri.getKel(cont: Controller(identifier: 'E4ipTizaI6dOOi_F0POXLG4l9mqrCoBmB0-gnk8Lag5U'));
    //var key_temp_1 = '6gWY4Y+k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
    //var key_temp_2 = 'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
    //var ev = '{"v":"KERI10JSON00012b_","t":"icp","d":"ET63RU-HSU3PSgHYqCr4o2veyL0GiThI_kcabIWK3mlk","i":"ET63RU-HSU3PSgHYqCr4o2veyL0GiThI_kcabIWK3mlk","s":"0","kt":"1","k":["B3-pfSEBecCc6FGwYzyJ83Nndkbq24LAhGzqc9vZlb0E"],"nt":"1","n":["EVqsf_2iPF9bl9cqh4ZK32k_ed4XczosHlvJuCeb7zlw"],"bt":"0","b":[],"c":[],"a":[]}';
    //var sig2 = await signer.sign(ev);
    // var controller = await Keri.finalizeInception(event: ev, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: sig2));
    //await Keri.finalizeEvent(identifier: Controller(identifier: 'Ea_iehzZAjq-EscCPBm7DKEQc_VVr84gJeGfpGG83ocs'), event: ev, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: sig2));

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
    print(icp_event);
    var controller = await Keri.finalizeInception(event: icp_event, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature));
    //var kel = await Keri.getKel(cont: Controller(identifier: 'cat'));
    print('controller: ${controller.identifier}');
    await signer.rotateForEd25519();
    var key_pub_3 = await signer.getCurrentPubKey();
    var key_pub_4 = await signer.getNextPubKey();
    List<PublicKey> currentKeys = [];
    List<PublicKey> newNextKeys = [];
    currentKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_3));
    newNextKeys.add(PublicKey(algorithm: KeyType.Ed25519, key: key_pub_4));

    var result = await Keri.rotate(controller: controller, currentKeys: currentKeys, newNextKeys: newNextKeys, witnessToAdd: [], witnessToRemove: [], witnessThreshold: 0);
    print('second event: $result');
    //var secev = 'kotki';
    var secev = '{"v":"KERI10JSON000160_","t":"rot","d":"E7WpdgyPc747YTx4ZKLInpN0js-OZBQPkjjTq3MzCsvI","i":"EK9RlxdIhQMgS77QjijZKOujG_vY1m3yXjfFG5KEglFQ","s":"1","p":"EK9RlxdIhQMgS77QjijZKOujG_vY1m3yXjfFG5KEglFQ","kt":"1","k":["BRuGG4-_v5eYlLM2XRpcWPSJXzsaLCnBEor5AdnBBfDo"],"nt":"1","n":["ENeOuHv0XDf--bEmm8G5g-zkTML1lRMBa9YuJkMwxuzY"],"bt":"0","br":[],"ba":[],"a":[]}';
    var signature2 = await signer.sign(result);
    await Keri.finalizeEvent(identifier: controller, event: result, signature: Signature(algorithm: SignatureType.Ed25519Sha512, key: signature2));
    print('finalized');
    await AsymmetricCryptoPrimitives.cleanUp(signer);

    var kelkel = await Keri.getKelByStr(contId: 'Eqq7GNTmaF9ELjAuL3f_hWFLK4NoO014dxdUbrJRAVG0');
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
