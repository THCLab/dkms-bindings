import KeyPair from "./support/key_pair";
import { inception, inceptRegistry, addWatcher } from "../client/src/utils/incept";
import { issuance } from "../client/src/utils/issue";
import { queryKel, queryTel } from "../client/src/utils/query";
import * as path from "path";
import { tmpdir } from "os";

import { mechanics } from "index";

describe("Utils", () => {
  it("Issue VC", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new mechanics.ConfigBuilder().withDbPath(tmpFileName).build();

    let controller = new mechanics.Controller(config);

    let keyType = mechanics.KeyType.Ed25519;
    let pk = new mechanics.PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new mechanics.PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));

    // let witnessOobi =`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
    let witnessOobi = `{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}`;
    let inceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let signing_op = (payload) => {
      let signature = currentKeyManager.sign(payload);
      return new mechanics.Signature(mechanics.SignatureType.Ed25519Sha512, Buffer.from(signature));
    };

    let signingIdentifier = await inception(
      controller,
      inceptionConfiguration,
      signing_op
    );

    let registryId = await inceptRegistry(signingIdentifier, signing_op);

    let json = JSON.stringify({ hello: "world1", ri: registryId });
    console.log(json);

    let vcHash = await issuance(signingIdentifier, json, signing_op);

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

    let verifier_signing_op = (payload) => {
      let signature = currentVerifierKeyManager.sign(payload);
      return new mechanics.Signature(mechanics.SignatureType.Ed25519Sha512, Buffer.from(signature));
    };

    let verifierInceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([verifierPk])
      .withNextKeys([verifierPk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let verifierIdentifier = await inception(
      verifier,
      verifierInceptionConfiguration,
      verifier_signing_op
    );

    let watcherOobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}';
    // let watcherOobi =
    //   '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://172.17.0.1:3235/"}';
  await addWatcher(verifierIdentifier, watcherOobi, verifier_signing_op);

    // Query KEL
    let oobis = await signingIdentifier.oobi();
    let signerId = await signingIdentifier.getId();

    await queryKel(
      verifierIdentifier,
      signerId,
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
