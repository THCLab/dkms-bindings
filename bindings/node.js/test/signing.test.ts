import KeyPair from "./support/key_pair";
import * as path from "path";
import { tmpdir } from "os";

import { mechanics, signing } from "../client/src/index";

let infra = require('./infrastructure.json');

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

    let witnessOobi = infra.witnesses.map(witness => JSON.stringify(witness));
    let inceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([pk])
      .withNextKeys([pk2])
      .withWitness(witnessOobi)
      .withWitnessThreshold(1);

    let signer = (payload) => {
      let signature = currentKeyManager.sign(payload);
      return new mechanics.Signature(
        mechanics.SignatureType.Ed25519Sha512,
        Buffer.from(signature)
      );
    };

    let signingIdentifier = await signing.incept(
      controller,
      inceptionConfiguration,
      [], //no watchers
      signer
    );
    let streamCipher = await signing.sign(
      signingIdentifier,
      '{"hello":"world"}',
      signer
    );

    let wrongStreamCipher = streamCipher.replace("hello", "wrong");

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
      Buffer.from(verifierCurrentKeyManager.pubKey)
    );
    let verifierPk2 = new mechanics.PublicKey(
      keyType,
      Buffer.from(verifierNextKeyManager.pubKey)
    );

    let verifierInceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([verifierPk])
      .withNextKeys([verifierPk2])
      .withWitness(witnessOobi)
      .withWitnessThreshold(1);

    let verifierSigner = (payload) => {
      let signature = verifierCurrentKeyManager.sign(payload);
      return new mechanics.Signature(
        mechanics.SignatureType.Ed25519Sha512,
        Buffer.from(signature)
      );
    };

    let watcherOobis = infra.watchers.map(watcher => JSON.stringify(watcher));
    let verifiengIdentifier = await signing.incept(
      verifierController,
      verifierInceptionConfiguration,
      watcherOobis,
      verifierSigner
    );

    let signerOobi = await signingIdentifier.oobi();

    let okVer = await signing.verify(
      verifiengIdentifier,
      signerOobi,
      streamCipher,
      verifierSigner
    );
     expect(okVer).toEqual(true);

    let wrongVer = await signing.verify(
      verifiengIdentifier,
      signerOobi,
      wrongStreamCipher,
      verifierSigner
    );
    expect(wrongVer).toEqual(false);
  });
});
