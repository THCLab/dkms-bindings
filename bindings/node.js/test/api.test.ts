import KeyPair from "./support/key_pair";
import { Controller, KeyType, SignatureType, ConfigBuilder, PublicKey, Signature, InceptionConfiguration} from "index";
import * as path from 'path';
import { tmpdir } from 'os';

/**
 * Helper function for sending new events to witnesses and collecting their receipts
*/  
async function publish(identifier, sigType, currentKeyManager) {
  await identifier.notifyWitness();

    let qry = (await identifier.queryMailbox())[0];
    console.log(qry.toString())
    let qry_signature = currentKeyManager.sign(qry);

    let qrySignaturePrefix = new Signature(sigType, Buffer.from(qry_signature));

    await identifier.finalizeQueryMailbox([qry], [qrySignaturePrefix]);
}

describe("Managing controller", () => {
  it("Issue VC", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new ConfigBuilder().withDbPath(tmpFileName).build();

    console.log(config)
    console.log(typeof(config))
    let controller = new Controller(config);

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));

    console.log(pk.getKey())
    let witnessOobi =`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
    // let witness_oobi=`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}`;
    let inceptionConfiguration = (new InceptionConfiguration)
	  	.withCurrentKeys([pk])
	  	.withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let inceptionEvent = await controller.incept(
      inceptionConfiguration
    );
    console.log(inceptionEvent.toString())

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new Signature(sigType, Buffer.from(signature));

    let signingIdentifier = await controller.finalizeInception(
      inceptionEvent,
      [signaturePrefix]
    );

    await publish(signingIdentifier, sigType, currentKeyManager)

  
    let registryData = await signingIdentifier.inceptRegistry();
    let ixn = registryData.ixn;
    let registry_id = registryData.registryId;
    let ixnSignature = currentKeyManager.sign(ixn);
    let ixnSignaturePrefix = new Signature(sigType, Buffer.from(ixnSignature));
    signingIdentifier.finalizeInceptRegistry(ixn, ixnSignaturePrefix)
    await publish(signingIdentifier, sigType, currentKeyManager)
    
    let json = {"hello":"world1","ri":registry_id};
    console.log(JSON.stringify(json));

    let issueData = await signingIdentifier.issue(Buffer.from(JSON.stringify(json)));
    let issueIxnSignature = currentKeyManager.sign(issueData.ixn);
    let vcHash = issueData.vcHash;
    let issueIxnSignaturePrefix = new Signature(sigType, Buffer.from(issueIxnSignature));
    signingIdentifier.finalizeInceptRegistry(issueData.ixn, issueIxnSignaturePrefix)

    await publish(signingIdentifier, sigType, currentKeyManager)
    console.log(await signingIdentifier.getKel())

    await signingIdentifier.notifyBackers()

    let tel_state = await signingIdentifier.vcState(vcHash)
    console.log(tel_state);

    // Setup identifier for verification
    const currentVerifierKeyManager = new KeyPair();
    const nextVerifierKeyManager = new KeyPair();

    const verifierTmpFileName = path.join(tmpdir(), `verifier-tmpfile-${Date.now()}.txt`);
    let verifierConfig = new ConfigBuilder().withDbPath(verifierTmpFileName).build();
    let verifier = new Controller(verifierConfig);

    let verifierPk = new PublicKey(keyType, Buffer.from(currentVerifierKeyManager.pubKey));
    let verifierPk2 = new PublicKey(keyType, Buffer.from(nextVerifierKeyManager.pubKey));

     let verifierInceptionConfiguration = (new InceptionConfiguration)
	  	.withCurrentKeys([verifierPk])
	  	.withNextKeys([verifierPk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);
    let verifierInceptionEvent = await verifier.incept(
      verifierInceptionConfiguration
    );

    let verifierSignature = currentVerifierKeyManager.sign(verifierInceptionEvent);

    let verifierSignaturePrefix = new Signature(sigType, Buffer.from(verifierSignature));

    let verifierIdentifier = await verifier.finalizeInception(
      verifierInceptionEvent,
      [verifierSignaturePrefix]
    );

    await publish(verifierIdentifier, sigType, currentVerifierKeyManager)

    let watcherOobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    // let watcherOobi = ' {"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://172.17.0.1:3235/"}';
    let add_watcher_event = await verifierIdentifier.addWatcher(watcherOobi);

    let addWatcherSignature = currentVerifierKeyManager.sign(Buffer.from(add_watcher_event));
    let addWatcherSignaturePrefix = new Signature(sigType, Buffer.from(addWatcherSignature));

    await verifierIdentifier.finalizeAddWatcher(add_watcher_event, addWatcherSignaturePrefix);

    // Query KEL
    let oobis = await signingIdentifier.oobi();
    console.log(oobis)
    for (let item of oobis) {
      console.log(item);
      await verifierIdentifier.sendOobiToWatcher(item);
    }

    let kelQueries = await verifierIdentifier.queryFullKel(await signingIdentifier.getId());
    for (let item of kelQueries) {
      let kelQrySignature = currentVerifierKeyManager.sign(item);
      let kelQrySigPrefix= new Signature(sigType, Buffer.from(kelQrySignature));

      let resp = await verifierIdentifier.finalizeQueryKel([item], [kelQrySigPrefix]);
      while (!resp) {
        await sleep(1000);
        resp = await verifierIdentifier.finalizeQueryKel([item], [kelQrySigPrefix]);
        console.log(resp)
      }
    }   

    let st = await verifierIdentifier.findState(await signingIdentifier.getId());
    console.log(st);

    // Query TEL
    let registry_oobi = await signingIdentifier.registryIdOobi();
    for (let item of registry_oobi) {
      await verifierIdentifier.sendOobiToWatcher(item)
    }
    
    for (var element of [1,2,3, 4, 5]) {
      await sleep(2000)
      let telQry = await verifierIdentifier.queryTel(registry_id, vcHash);
      let telQrySignature = currentVerifierKeyManager.sign(telQry);
      let telQrySigPrefix= new Signature(sigType, Buffer.from(telQrySignature));
      await verifierIdentifier.finalizeQueryTel(telQry, telQrySigPrefix);

    }
    let tst = await verifierIdentifier.vcState(vcHash);
    console.log(tst)

  });
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));