import KeyPair from "./support/key_pair";
import * as path from "path";
import { tmpdir } from "os";

import { mechanics, issuing, signing } from "../client/src/index";

describe("Signing", () => {
  it("Signing payload", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new mechanics.ConfigBuilder().withDbPath(tmpFileName).build();

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

    // let witnessOobi =`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
    let witnessOobi = `{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}`;
    let inceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let signing_op = (payload) => {
      let signature = currentKeyManager.sign(payload);
      return new mechanics.Signature(
        mechanics.SignatureType.Ed25519Sha512,
        Buffer.from(signature)
      );
    };

    let signingIdentifier = await issuing.incept(
      controller,
      inceptionConfiguration,
      [], //no watchers
      signing_op
    );
    let stream = await signing.sign(
      signingIdentifier,
      '{"hello":"world"}',
      signing_op
    );

    // Setup verifying identifier
    const verifierCurrentKeyManager = new KeyPair();
    const verifierNextKeyManager = new KeyPair();
    const verifierTmpFileName = path.join(
      tmpdir(),
      `tmpfile-${Date.now()}.txt`
    );

    let verifierConfig = new mechanics.ConfigBuilder()
      .withDbPath(verifierTmpFileName)
      .build();

    let verifierController = new mechanics.Controller(verifierConfig);

    let verifierPk = new mechanics.PublicKey(
      keyType,
      Buffer.from(currentKeyManager.pubKey)
    );
    let verifierPk2 = new mechanics.PublicKey(
      keyType,
      Buffer.from(nextKeyManager.pubKey)
    );

    let verifierInceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness([witnessOobi])
      .withWitnessThreshold(1);

    let verifierSigningOp = (payload) => {
      let signature = currentKeyManager.sign(payload);
      return new mechanics.Signature(
        mechanics.SignatureType.Ed25519Sha512,
        Buffer.from(signature)
      );
    };

    let watcherOobis = [
      '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://172.17.0.1:3235/"}',
    ];
    // let watcherOobis = ['{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}'];
    let verifiengIdentifier = await issuing.incept(
      verifierController,
      verifierInceptionConfiguration,
      watcherOobis,
      verifierSigningOp
    );

    let signerOobi = await signingIdentifier.oobi();

    let ver = await signing.verify(
      verifiengIdentifier,
      signerOobi,
      stream,
      verifierSigningOp
    );
     expect(ver).toEqual(true);
  });
});
