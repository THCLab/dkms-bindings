import KeyPair from "./support/key_pair";
import { incept, inceptRegistry, addWatcher } from "../client/src/incept";
import { issue } from "../client/src/issue";
import { queryKel, queryTel } from "../client/src/query";
import {
  Controller,
  KeyType,
  SignatureType,
  ConfigBuilder,
  PublicKey,
  Signature,
  InceptionConfiguration,
} from "index";
import * as path from "path";
import { tmpdir } from "os";

describe("Managing controller", () => {
  it("Issue VC", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new ConfigBuilder().withDbPath(tmpFileName).build();

    let controller = new Controller(config);

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));

    // let witnessOobi =`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
    let witnessOobi = `{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}`;
    let inceptionConfiguration = new InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let signing_op = (payload) => {
      let signature = currentKeyManager.sign(payload);
      return new Signature(SignatureType.Ed25519Sha512, Buffer.from(signature));
    };

    let signingIdentifier = await incept(
      controller,
      inceptionConfiguration,
      signing_op
    );

    let registryId = await inceptRegistry(signingIdentifier, signing_op);

    let json = { hello: "world1", ri: registryId };
    console.log(JSON.stringify(json));

    let vcHash = await issue(signingIdentifier, json, signing_op);

    console.log(await signingIdentifier.getKel());

    let tel_state = await signingIdentifier.vcState(vcHash);
    console.log(tel_state);

    // Setup identifier for verification
    const currentVerifierKeyManager = new KeyPair();
    const nextVerifierKeyManager = new KeyPair();

    const verifierTmpFileName = path.join(
      tmpdir(),
      `verifier-tmpfile-${Date.now()}.txt`
    );
    let verifierConfig = new ConfigBuilder()
      .withDbPath(verifierTmpFileName)
      .build();
    let verifier = new Controller(verifierConfig);

    let verifierPk = new PublicKey(
      keyType,
      Buffer.from(currentVerifierKeyManager.pubKey)
    );
    let verifierPk2 = new PublicKey(
      keyType,
      Buffer.from(nextVerifierKeyManager.pubKey)
    );

    let verifier_signing_op = (payload) => {
      let signature = currentVerifierKeyManager.sign(payload);
      return new Signature(SignatureType.Ed25519Sha512, Buffer.from(signature));
    };

    let verifierInceptionConfiguration = new InceptionConfiguration()
      .withCurrentKeys([verifierPk])
      .withNextKeys([verifierPk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let verifierIdentifier = await incept(
      verifier,
      verifierInceptionConfiguration,
      verifier_signing_op
    );

    // let watcherOobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    let watcherOobi =
      '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://172.17.0.1:3235/"}';
    await addWatcher(verifierIdentifier, watcherOobi, verifier_signing_op);

    // Query KEL
    let oobis = await signingIdentifier.oobi();

    await queryKel(
      verifierIdentifier,
      signingIdentifier.getId(),
      oobis,
      verifier_signing_op
    );

    let st = await verifierIdentifier.findState(
      await signingIdentifier.getId()
    );
    console.log(st);

    // Query TEL
    let registryOobi = await signingIdentifier.registryIdOobi();

    await queryTel(
      verifierIdentifier,
      vcHash,
      registryId,
      registryOobi,
      verifier_signing_op
    );

    let tst = await verifierIdentifier.vcState(vcHash);
    console.log(tst);
  });
});
