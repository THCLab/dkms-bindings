import 'dart:io';

import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:keri/bridge_generated.dart';
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;

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
  late var controller;
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
    var inited = await Keri.initKel(inputAppDir: dir);
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
                      vec1.add(PublicKey(
                          algorithm: KeyType.Ed25519, key: currentKey));
                      vec2.add(
                          PublicKey(algorithm: KeyType.Ed25519, key: nextKey));
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
                      icpEvent = await Keri.incept(
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
                      signature =
                      'A9390DFA037497D887E2BFF1ED29DA9480B5FF59BFE0FCAFE19B939529F25FAC8F1D3F2299F16402EED654DEE1A156840C7584CB6455B2D10767441F27DD750A';
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
                      controller = await Keri.finalizeInception(
                          event: icpEvent,
                          signature: Signature(
                              algorithm: SignatureType.Ed25519Sha512,
                              key: signature));
                      controllerId = controller.identifier;
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
                      currentKeys.add(PublicKey(
                          algorithm: KeyType.Ed25519, key: currentKey));
                      newNextKeys.add(PublicKey(
                          algorithm: KeyType.Ed25519, key: nextKey));
                      rotationEvent = await Keri.rotate(
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
                      signature2 =
                      'AAE6871AE38588FCA317AD78B1DEF05AB0A0BFE9D85FBFCB627926E35BB0FAB705A660B2B5C6E2177C72E8254BC0448784A575E73481FD153FE2BEA83961040A';
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
                      finalizedEvent = await Keri.finalizeEvent(
                          identifier: controller,
                          event: rotationEvent,
                          signature: Signature(
                              algorithm: SignatureType.Ed25519Sha512,
                              key: signature2));
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
                      anchorEvent = await Keri.anchor(
                          controller: controller,
                          data: dataForAnchor,
                          algo: DigestType.Blake3_256);
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
                      signature3 =
                      '05A12E80B0762363F4A088ABEB0991B4EE9ED63512DB71C9BD8EBA298F25DBFE093EA0DF3F5A6DE4A18F037C1BBB07633B3BB15156CF35F9273222CCDEB44D00';
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
                      finalizedAnchor = await Keri.finalizeEvent(
                          identifier: controller,
                          event: anchorEvent,
                          signature: Signature(
                              algorithm: SignatureType.Ed25519Sha512,
                              key: signature3));
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