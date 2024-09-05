import KeyPair from "./support/key_pair";
import * as path from "path";
import { tmpdir } from "os";

import { mechanics, issuing } from "../client/src/index";

let infra = require('./infrastructure.json');

describe("Issuing", () => {
  it("Issue VC", async () => {
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
    console.log(witnessOobi);
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

    let signingIdentifier = await issuing.incept(
      controller,
      inceptionConfiguration,
      [], // no watchers
      signer
    );

    let registryId = await signingIdentifier.registryId();
    console.log(registryId);

    let json = { hello: "world", ri: registryId };
    console.log(JSON.stringify(json));

    let vcHash = await issuing.issue(
      signingIdentifier,
      JSON.stringify(json),
      signer
    );

    console.log(await signingIdentifier.getKel());

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

    let verifierSigner = (payload) => {
      let signature = currentVerifierKeyManager.sign(payload);
      return new mechanics.Signature(
        mechanics.SignatureType.Ed25519Sha512,
        Buffer.from(signature)
      );
    };

    let verifierInceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([verifierPk])
      .withNextKeys([verifierPk2])
      .withWitness(witnessOobi)
      .withWitnessThreshold(1);

    let watcherOobis = infra.watchers.map(watcher => JSON.stringify(watcher));
    let verifierIdentifier = await issuing.incept(
      verifier,
      verifierInceptionConfiguration,
      watcherOobis,
      verifierSigner
    );

    // Query KEL
    let oobis = await signingIdentifier.oobi();
    let registryOobi = await signingIdentifier.registryIdOobi();
    console.log(registryOobi[0]);
    console.log(oobis[0]);

    let res = await issuing.verify(
      verifierIdentifier,
      vcHash,
      await signingIdentifier.getId(),
      oobis,
      await signingIdentifier.registryId(),
      registryOobi,
      verifierSigner
    );
    var parsedData = JSON.parse(res);
    expect(parsedData.verified).toEqual(true);
    expect(parsedData.status).toEqual("issued");

    issuing.revoke(signingIdentifier, vcHash, signer);

    let revoked_res = await issuing.verify(
      verifierIdentifier,
      vcHash,
      await signingIdentifier.getId(),
      oobis,
      await signingIdentifier.registryId(),
      registryOobi,
      verifierSigner
    );
    var parsedData = JSON.parse(revoked_res);
    expect(parsedData.verified).toEqual(false);
    expect(parsedData.status).toEqual("revoked");

  });
});
