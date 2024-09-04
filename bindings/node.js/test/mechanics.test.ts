import KeyPair from "./support/key_pair";
import { mechanics } from "../client/src/index";
import * as path from "path";
import { tmpdir } from "os";
import { VcState } from "mechanics";

/**
 * Helper function for sending new events to witnesses and collecting their receipts
 */
async function publish(identifier, sigType, currentKeyManager) {
  await identifier.notifyWitness();

  let qry = (await identifier.queryMailbox())[0];
  console.log(qry.toString());
  let qry_signature = currentKeyManager.sign(qry);

  let qrySignaturePrefix = new mechanics.Signature(
    sigType,
    Buffer.from(qry_signature)
  );

  await identifier.finalizeQueryMailbox([qry], [qrySignaturePrefix]);
}

describe("Mechanics", () => {
  it("Issue VC", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new mechanics.ConfigBuilder().withDbPath(tmpFileName).build();

    console.log(config);
    console.log(typeof config);
    let controller = new mechanics.Controller(config);

    let keyType = mechanics.KeyType.Ed25519;
    let pk = new mechanics.PublicKey(
      keyType,
      Buffer.from(currentKeyManager.pubKey)
    );
    let pk2 = new mechanics.PublicKey(
      keyType,
      Buffer.from(nextKeyManager.pubKey)
    );

    console.log(pk.getKey());
    let witnessOobi = `{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
    // let witness_oobi=`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}`;
    let inceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let inceptionEvent = await controller.incept(inceptionConfiguration);
    console.log(inceptionEvent.toString());

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = mechanics.SignatureType.Ed25519Sha512;
    let signaturePrefix = new mechanics.Signature(
      sigType,
      Buffer.from(signature)
    );

    let signingIdentifier = await controller.finalizeInception(inceptionEvent, [
      signaturePrefix,
    ]);

    await publish(signingIdentifier, sigType, currentKeyManager);

    let registryData = await signingIdentifier.inceptRegistry();
    let ixn = registryData.ixn;
    let registry_id = registryData.registryId;
    let ixnSignature = currentKeyManager.sign(ixn);
    let ixnSignaturePrefix = new mechanics.Signature(
      sigType,
      Buffer.from(ixnSignature)
    );
    signingIdentifier.finalizeInceptRegistry(ixn, ixnSignaturePrefix);
    await publish(signingIdentifier, sigType, currentKeyManager);

    let json = { hello: "world1", ri: registry_id };
    console.log(JSON.stringify(json));

    let issueData = await signingIdentifier.issue(
      Buffer.from(JSON.stringify(json))
    );
    let issueIxnSignature = currentKeyManager.sign(issueData.ixn);
    let vcHash = issueData.vcHash;
    let issueIxnSignaturePrefix = new mechanics.Signature(
      sigType,
      Buffer.from(issueIxnSignature)
    );
    signingIdentifier.finalizeInceptRegistry(
      issueData.ixn,
      issueIxnSignaturePrefix
    );

    await publish(signingIdentifier, sigType, currentKeyManager);
    console.log(await signingIdentifier.getKel());

    await signingIdentifier.notifyBackers();

    let tel_state = await signingIdentifier.vcState(vcHash);
    console.log(tel_state);

    // Setup identifier for verification
    const currentVerifierKeyManager = new KeyPair();
    const nextVerifierKeyManager = new KeyPair();

    const verifierTmpFileName = path.join(
      tmpdir(),
      `verifier-tmpfile-${Date.now()}.txt`
    );
    let verifierConfig = new mechanics.ConfigBuilder()
      .withDbPath(verifierTmpFileName)
      .build();
    let verifier = new mechanics.Controller(verifierConfig);

    let verifierPk = new mechanics.PublicKey(
      keyType,
      Buffer.from(currentVerifierKeyManager.pubKey)
    );
    let verifierPk2 = new mechanics.PublicKey(
      keyType,
      Buffer.from(nextVerifierKeyManager.pubKey)
    );

    let verifierInceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([verifierPk])
      .withNextKeys([verifierPk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);
    let verifierInceptionEvent = await verifier.incept(
      verifierInceptionConfiguration
    );

    let verifierSignature = currentVerifierKeyManager.sign(
      verifierInceptionEvent
    );

    let verifierSignaturePrefix = new mechanics.Signature(
      sigType,
      Buffer.from(verifierSignature)
    );

    let verifierIdentifier = await verifier.finalizeInception(
      verifierInceptionEvent,
      [verifierSignaturePrefix]
    );

    await publish(verifierIdentifier, sigType, currentVerifierKeyManager);

    let watcherOobi =
      '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    // let watcherOobi = ' {"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://172.17.0.1:3235/"}';
    let add_watcher_event = await verifierIdentifier.addWatcher(watcherOobi);

    let addWatcherSignature = currentVerifierKeyManager.sign(
      Buffer.from(add_watcher_event)
    );
    let addWatcherSignaturePrefix = new mechanics.Signature(
      sigType,
      Buffer.from(addWatcherSignature)
    );

    await verifierIdentifier.finalizeAddWatcher(
      add_watcher_event,
      addWatcherSignaturePrefix
    );

    // Query KEL
    let oobis = await signingIdentifier.oobi();
    console.log(oobis);
    for (let item of oobis) {
      console.log(item);
      await verifierIdentifier.sendOobiToWatcher(item);
    }

    let kelQueries = await verifierIdentifier.queryFullKel(
      await signingIdentifier.getId()
    );
    for (let item of kelQueries) {
      let kelQrySignature = currentVerifierKeyManager.sign(item);
      let kelQrySigPrefix = new mechanics.Signature(
        sigType,
        Buffer.from(kelQrySignature)
      );

      let resp = await verifierIdentifier.finalizeQueryKel(
        [item],
        [kelQrySigPrefix]
      );
      while (!resp) {
        await sleep(1000);
        resp = await verifierIdentifier.finalizeQueryKel(
          [item],
          [kelQrySigPrefix]
        );
        console.log(resp);
      }
    }

    let st = await verifierIdentifier.findState(
      await signingIdentifier.getId()
    );
    console.log(st);

    // Query TEL
    let registry_oobi = await signingIdentifier.registryIdOobi();
    for (let item of registry_oobi) {
      await verifierIdentifier.sendOobiToWatcher(item);
    }

    for (var element of [1, 2, 3, 4, 5]) {
      await sleep(2000);
      let telQry = await verifierIdentifier.queryTel(registry_id, vcHash);
      let telQrySignature = currentVerifierKeyManager.sign(telQry);
      let telQrySigPrefix = new mechanics.Signature(
        sigType,
        Buffer.from(telQrySignature)
      );
      await verifierIdentifier.finalizeQueryTel(telQry, telQrySigPrefix);
    }
    let tst = await verifierIdentifier.vcState(vcHash);
    expect(tst).toEqual(VcState.Issued);
  });
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));