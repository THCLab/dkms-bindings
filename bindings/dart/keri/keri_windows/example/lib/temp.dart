import 'dart:async';

import 'package:asymmetric_crypto_primitives/asymmetric_crypto_primitives.dart';
import 'package:asymmetric_crypto_primitives/ed25519_signer.dart';
import 'package:flutter/material.dart';
import 'package:keri_platform_interface/bridge_generated.dart';
import 'package:keri_platform_interface/keri_platform_interface.dart';
import 'package:path_provider/path_provider.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  var signer = await AsymmetricCryptoPrimitives.establishForEd25519();
  runApp(MaterialApp(
    home: MyApp(
      signer: signer,
    ),
    debugShowCheckedModeBanner: false,
  ));
}

class MyApp extends StatefulWidget {
  final Ed25519Signer signer;
  const MyApp({super.key, required this.signer});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String current_b64_key = '';
  String next_b64_key = '';
  String witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC";
  String wit_location =
      '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}';
  late Ed25519Signer signer;
  List<String> witness_id_list = [];
  var initiatorKel = '';
  var isIncepting = false;
  var isInceptionError = false;
  List<Identifier> participants = [];
  List<bool> selectedParticipants = [];
  late Identifier identifier;

  @override
  void initState() {
    signer = widget.signer;
    initParameters();
    super.initState();
  }

  Future<void> initParameters() async {
    String dbPath = await getLocalPath();
    dbPath = '$dbPath/new';
    current_b64_key = await signer.getCurrentPubKey();
    next_b64_key = await signer.getNextPubKey();
    await KeriPlatformInterface.instance.initKel(inputAppDir: dbPath);
  }

  Future<String> getLocalPath() async {
    final directory = await getApplicationDocumentsDirectory();
    print(directory);
    return directory.path;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Multisig demo"),
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            RawMaterialButton(
                onPressed: () async {
                  List<PublicKey> vec1 = [];
                  vec1.add(await KeriPlatformInterface.instance.newPublicKey(
                      kt: KeyType.Ed25519, keyB64: current_b64_key));
                  List<PublicKey> vec2 = [];
                  vec2.add(await KeriPlatformInterface.instance
                      .newPublicKey(kt: KeyType.Ed25519, keyB64: next_b64_key));
                  List<String> vec3 = [wit_location];
                  setState(() {
                    isIncepting = true;
                  });
                  var icp_event = null;
                  try {
                    icp_event = await KeriPlatformInterface.instance.incept(
                        publicKeys: vec1,
                        nextPubKeys: vec2,
                        witnesses: vec3,
                        witnessThreshold: 1);
                    setState(() {
                      isIncepting = false;
                    });
                  } catch (e) {
                    print(e);
                    setState(() {
                      isInceptionError = true;
                    });
                  }
                  var signature = await signer.sign(icp_event);
                  print(icp_event);
                  print(signature);
                  identifier = await KeriPlatformInterface.instance
                      .finalizeInception(
                          event: icp_event,
                          signature: await KeriPlatformInterface.instance
                              .signatureFromHex(
                                  st: SignatureType.Ed25519Sha512,
                                  signature: signature));

                  witness_id_list.add(witness_id);
                  var query = await KeriPlatformInterface.instance.queryMailbox(
                      whoAsk: identifier,
                      aboutWho: identifier,
                      witness: witness_id_list);
                  print(query);
                  var sig_query = await signer.sign(query[0]);
                  await KeriPlatformInterface.instance.finalizeQuery(
                      identifier: identifier,
                      queryEvent: query[0],
                      signature: await KeriPlatformInterface.instance
                          .signatureFromHex(
                              st: SignatureType.Ed25519Sha512,
                              signature: sig_query));

                  var kel = await KeriPlatformInterface.instance
                      .getKel(cont: identifier);

                  var watcher_oobi =
                      '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://127.0.0.1:3236/"}';
                  await KeriPlatformInterface.instance
                      .resolveOobi(oobiJson: watcher_oobi);
                  var add_watcher_message = await KeriPlatformInterface.instance
                      .addWatcher(
                          controller: identifier, watcherOobi: watcher_oobi);
                  print(
                      "\nController generate end role message to add witness: $add_watcher_message");
                  var watcher_sig = await signer.sign(add_watcher_message);
                  var ev = await KeriPlatformInterface.instance.finalizeEvent(
                      identifier: identifier,
                      event: add_watcher_message,
                      signature: await KeriPlatformInterface.instance
                          .signatureFromHex(
                              st: SignatureType.Ed25519Sha512,
                              signature: watcher_sig));

                  query = await KeriPlatformInterface.instance.queryMailbox(
                      whoAsk: identifier,
                      aboutWho: identifier,
                      witness: witness_id_list);
                  sig_query = await signer.sign(query[0]);
                  await KeriPlatformInterface.instance.finalizeQuery(
                      identifier: identifier,
                      queryEvent: query[0],
                      signature: await KeriPlatformInterface.instance
                          .signatureFromHex(
                              st: SignatureType.Ed25519Sha512,
                              signature: sig_query));
                  initiatorKel = await KeriPlatformInterface.instance
                      .getKel(cont: identifier);
                  setState(() {});
                  final Timer periodicTimer = Timer.periodic(
                    const Duration(seconds: 10),
                    (Timer t) async {
                      await KeriPlatformInterface.instance.queryMailbox(
                          whoAsk: identifier,
                          aboutWho: identifier,
                          witness: witness_id_list);
                      print('querying');
                    },
                  );
                  print('here');
                },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text(
                    "Incept identifier",
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2))),
            isIncepting ? connectingToWitness() : Container(),
            isInceptionError ? inceptionError() : Container(),
            initiatorKel.isNotEmpty
                ? Text(
                    "Identifier kel:",
                    style: TextStyle(fontWeight: FontWeight.bold),
                  )
                : Container(),
            initiatorKel.isNotEmpty
                ? Text(
                    initiatorKel,
                    style: TextStyle(color: Colors.green),
                  )
                : Container(),
            initiatorKel.isNotEmpty
                ? SizedBox(
                    height: 10,
                  )
                : Container(),
            initiatorKel.isNotEmpty
                ? Text(
                    "Scan this QR code with another device to add this device to their list of participants",
                    style: TextStyle(fontWeight: FontWeight.bold),
                    textAlign: TextAlign.center,
                  )
                : Container(),
            Divider(),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.import_contacts),
                Text(
                  "Participants",
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                Icon(Icons.import_contacts),
              ],
            ),
            Container(
              width: MediaQuery.of(context).size.width - 100,
              height: 150,
              decoration: BoxDecoration(
                border: Border.all(width: 2.0),
                borderRadius: BorderRadius.all(Radius.circular(18.0)),
              ),
              child: ListView.builder(
                  itemCount: participants.length,
                  itemBuilder: (BuildContext context, int index) {
                    return CheckboxListTile(
                      value: selectedParticipants[index],
                      onChanged: (bool? selected) {
                        selectedParticipants[index] =
                            !selectedParticipants[index];
                      },
                      title: Text(participants[index].id),
                    );
                  }),
            ),
            initiatorKel.isNotEmpty
                ? RawMaterialButton(
                    onPressed: () async {
                      var icp = await KeriPlatformInterface.instance
                          .inceptGroup(
                              identifier: identifier,
                              participants: participants,
                              signatureThreshold: 2,
                              initialWitnesses: witness_id_list,
                              witnessThreshold: 1);
                      var signature = await signer.sign(icp.icpEvent);
                      List<String> signaturesEx = [];
                      List<DataAndSignature> toForward = [];
                      for (var exchange in icp.exchanges) {
                        signaturesEx.add(await signer.sign(exchange));
                      }
                      for (int i = 0; i < signaturesEx.length; i++) {
                        toForward.add(await KeriPlatformInterface.instance
                            .newDataAndSignature(
                                data: icp.exchanges[i],
                                signature: await KeriPlatformInterface.instance
                                    .signatureFromHex(
                                        st: SignatureType.Ed25519Sha512,
                                        signature: signaturesEx[i])));
                      }
                      var group_identifier = await KeriPlatformInterface
                          .instance
                          .finalizeGroupIncept(
                              identifier: identifier,
                              groupEvent: icp.icpEvent,
                              signature: await KeriPlatformInterface.instance
                                  .signatureFromHex(
                                      st: SignatureType.Ed25519Sha512,
                                      signature: signature),
                              toForward: toForward);
                    },
                    child: Padding(
                      padding: const EdgeInsets.all(8.0),
                      child: const Text(
                        "Incept group",
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                    ),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(18.0),
                        side: const BorderSide(width: 2)))
                : Container(),
          ],
        ),
      ),
    );
  }

  Widget connectingToWitness() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        CircularProgressIndicator(),
        Text("Connecting to witness..."),
      ],
    );
  }

  Widget inceptionError() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(
          Icons.not_interested,
          color: Colors.red,
        ),
        Text(
          "Couldn't connect to witness!",
          style: TextStyle(color: Colors.red),
        ),
      ],
    );
  }
}
