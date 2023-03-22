import 'dart:io';

import 'package:asymmetric_crypto_primitives/asymmetric_crypto_primitives.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:keri_platform_interface/keri_platform_interface.dart';
import 'package:keri_platform_interface/bridge_generated.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  late var signer;
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
  String dataForAnchor = 'important data';
  String anchorEvent = '';
  String signature3 = '';
  bool finalizedAnchor = false;
  var dataToSign = '{"hello":"world"}';
  bool isCesrSigned = false;
  bool isCesrVerified = false;
  late var signed;

  @override
  void initState() {
    initKel();
    super.initState();
  }

  Future<void> initKel() async {
    signer = await AsymmetricCryptoPrimitives.establishForEd25519();
    var dir = await getLocalPath();
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
                      currentKey = await signer.getCurrentPubKey();
                      nextKey = await signer.getNextPubKey();
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
                          signature = await signer.sign(icpEvent);
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
                          await signer.rotateForEd25519();
                          currentKey = await signer.getCurrentPubKey();
                          nextKey = await signer.getNextPubKey();
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
                          signature2 = await signer.sign(rotationEvent);
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
                          signature3 = await signer.sign(anchorEvent);
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
                Divider(),
                Text("data to sign: $dataToSign"),
                controllerId.isNotEmpty
                    ? RawMaterialButton(
                        onPressed: () async {
                          var hexSig = await signer.sign(dataToSign);
                          await KeriPlatformInterface.instance
                              .signToCesr(
                                  identifier: controller,
                                  data: dataToSign,
                                  signature: await KeriPlatformInterface
                                      .instance
                                      .signatureFromHex(
                                          st: SignatureType.Ed25519Sha512,
                                          signature: hexSig))
                              .then((value) {
                            if (value.isNotEmpty) {
                              print(value);
                              setState(() {
                                isCesrSigned = true;
                                signed = value;
                              });
                            }
                          });
                        },
                        child: const Text('Sign'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                isCesrSigned ? Text("Successfully signed!") : Container(),
                isCesrSigned
                    ? RawMaterialButton(
                        onPressed: () async {
                          var verified = await KeriPlatformInterface.instance
                              .verifyFromCesr(stream: signed)
                              .then((value) {
                            if (value) {
                              setState(() {
                                isCesrVerified = true;
                              });
                            }
                          });
                        },
                        child: const Text('Verify'),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18.0),
                            side: BorderSide(width: 1)))
                    : Container(),
                isCesrVerified ? Text("Successfully verified!") : Container(),
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
