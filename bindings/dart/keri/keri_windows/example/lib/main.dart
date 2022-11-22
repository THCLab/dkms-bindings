import 'package:flutter/material.dart';
import 'package:keri_platform_interface/bridge_generated.dart';
import 'dart:async';
import 'package:keri_platform_interface/keri_platform_interface.dart';

//import 'package:keri_windows/bridge_generated.dart';
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
  String currentKey = '';
  String nextKey = '';
  String icpEvent = '';
  List<PublicKey> vec1 = [];
  List<PublicKey> vec2 = [];
  List<String> vec3 = [];
  String signature = '';
  late Identifier controller;
  String controllerId = '';
  List<PublicKey> currentKeys = [];
  List<PublicKey> newNextKeys = [];
  String rotationEvent = '';
  String signature2 = '';
  bool finalizedEvent = false;
  String dataForAnchor = 'data';
  String anchorEvent = '';
  String signature3 = '';
  bool finalizedAnchor = false;

  @override
  void initState() {
    initKel();
    super.initState();
  }

  Future<void> initKel() async {
    var dir = await getLocalPath();
    print(dir);
    var inited = await KeriPlatformInterface.instance.initKel(inputAppDir: dir);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: SingleChildScrollView(
          child: Center(
            child: Column(
              children: [
                RawMaterialButton(
                    onPressed: () async {
                      currentKey =
                          '6gWY4Y+k2t9KFZaSkR5jUInOYEoOluADtWmYxsPkln0=';
                      nextKey = 'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
                      vec1.add(await KeriPlatformInterface.instance
                          .newPublicKey(
                              kt: KeyType.Ed25519, keyB64: currentKey));
                      vec2.add(await KeriPlatformInterface.instance
                          .newPublicKey(kt: KeyType.Ed25519, keyB64: nextKey));
                      setState(() {});
                    },
                    child: const Text('Get keys'),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(18.0),
                        side: BorderSide(width: 1))),
                currentKey.isNotEmpty
                    ? Text(
                        "Public keys",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                Text(currentKey),
                Text(nextKey),
                currentKey.isNotEmpty ? const Divider() : Container(),
                currentKey.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          icpEvent = await KeriPlatformInterface.instance
                              .incept(
                                  publicKeys: vec1,
                                  nextPubKeys: vec2,
                                  witnesses: vec3,
                                  witnessThreshold: 0);
                          setState(() {});
                          print(icpEvent);
                        },
                        child: const Text('Incept'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                icpEvent.isNotEmpty
                    ? Text(
                        "ICP event",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                icpEvent.isNotEmpty ? Text(icpEvent) : Container(),
                icpEvent.isNotEmpty ? const Divider() : Container(),
                icpEvent.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          signature =
                              '0CDD8D47A4FA43116D627E1410F84DB5016251EC04DFDFFC036F2307EDD44FEF27F7F721349E4FF40740A8984723BDD03BE0ABAAE97741436D2F45FB588E0E05';
                          setState(() {});
                        },
                        child: const Text('Sign event'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                signature.isNotEmpty
                    ? Text(
                        "Signature",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                signature.isNotEmpty ? Text(signature) : Container(),
                signature.isNotEmpty ? const Divider() : Container(),
                signature.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          controller = await KeriPlatformInterface.instance
                              .finalizeInception(
                                  event: icpEvent,
                                  signature: await KeriPlatformInterface
                                      .instance
                                      .signatureFromHex(
                                          st: SignatureType.Ed25519Sha512,
                                          signature: signature));
                          controllerId = controller.id;
                          setState(() {});
                        },
                        child: const Text('Finalize Inception'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                controllerId.isNotEmpty
                    ? Text(
                        "Controller identifier",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                controllerId.isNotEmpty ? Text(controllerId) : Container(),
                controllerId.isNotEmpty ? const Divider() : Container(),
                controllerId.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          currentKey =
                              'GoP8qjXbUcnpMWtDeRuN/AT0pA7F5gFjrv8UdxrEJW0=';
                          nextKey =
                              'vyr60mQ4dvwa5twsC7N7Nx0UAF4nqCDLfibDY0dJovE=';
                          currentKeys.add(await KeriPlatformInterface.instance
                              .newPublicKey(
                                  kt: KeyType.Ed25519, keyB64: currentKey));
                          newNextKeys.add(await KeriPlatformInterface.instance
                              .newPublicKey(
                                  kt: KeyType.Ed25519, keyB64: nextKey));
                          rotationEvent = await KeriPlatformInterface.instance
                              .rotate(
                                  controller: controller,
                                  currentKeys: currentKeys,
                                  newNextKeys: newNextKeys,
                                  witnessToAdd: [],
                                  witnessToRemove: [],
                                  witnessThreshold: 0);
                          setState(() {});
                          print(rotationEvent);
                        },
                        child: const Text('Rotate'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                rotationEvent.isNotEmpty
                    ? Text(
                        "Rotation event",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                rotationEvent.isNotEmpty ? Text(rotationEvent) : Container(),
                rotationEvent.isNotEmpty ? const Divider() : Container(),
                rotationEvent.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          signature2 =
                              '29FA3CD56DD1F6DED19A035A48CBDFB010F64158824BA66825423413C56E90B5B4D85DBFBA15D5A0029E838967FA119888DFD44DAAF38AA66336A16F55C01000';
                          setState(() {});
                        },
                        child: const Text('Sign event'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                signature2.isNotEmpty
                    ? Text(
                        "Signature",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                signature2.isNotEmpty ? Text(signature2) : Container(),
                signature2.isNotEmpty ? const Divider() : Container(),
                signature2.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          finalizedEvent = await KeriPlatformInterface.instance
                              .finalizeEvent(
                                  identifier: controller,
                                  event: rotationEvent,
                                  signature: await KeriPlatformInterface
                                      .instance
                                      .signatureFromHex(
                                          st: SignatureType.Ed25519Sha512,
                                          signature: signature2));
                          setState(() {});
                        },
                        child: const Text('Finalize event'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                finalizedEvent
                    ? Text(
                        "Rotation event finalized",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                finalizedEvent ? const Divider() : Container(),
                finalizedEvent
                    ? Text(
                        "Data for anchor",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                finalizedEvent ? Text(dataForAnchor) : Container(),
                finalizedEvent ? const Divider() : Container(),
                finalizedEvent
                    ? RawMaterialButton(
                        onPressed: () async {
                          anchorEvent = await KeriPlatformInterface.instance
                              .anchor(
                                  controller: controller,
                                  data: dataForAnchor,
                                  algo: DigestType.blake3256());
                          setState(() {});
                          print(anchorEvent);
                        },
                        child: const Text('Anchor'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                anchorEvent.isNotEmpty
                    ? Text(
                        "Anchor event",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                anchorEvent.isNotEmpty ? Text(anchorEvent) : Container(),
                anchorEvent.isNotEmpty ? const Divider() : Container(),
                anchorEvent.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          signature3 =
                              'CB16207214C91415809068126F6846E86B0404D1ACFEEF5CE853DED53CD70EED2BC0368E048CB68ADC1D637FE2DB09F624126387FF02C2E48FD2E3B02BE4D30F';
                          setState(() {});
                        },
                        child: const Text('Sign event'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                signature3.isNotEmpty
                    ? Text(
                        "Signature",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                signature3.isNotEmpty ? Text(signature3) : Container(),
                signature3.isNotEmpty ? const Divider() : Container(),
                signature3.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          finalizedAnchor = await KeriPlatformInterface.instance
                              .finalizeEvent(
                                  identifier: controller,
                                  event: anchorEvent,
                                  signature: await KeriPlatformInterface
                                      .instance
                                      .signatureFromHex(
                                          st: SignatureType.Ed25519Sha512,
                                          signature: signature3));
                          setState(() {});
                        },
                        child: const Text('Finalize event'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                finalizedAnchor
                    ? Text(
                        "Anchor event finalized",
                        style: TextStyle(color: Colors.green),
                      )
                    : Container(),
                finalizedAnchor ? const Divider() : Container(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<String> getLocalPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
}
