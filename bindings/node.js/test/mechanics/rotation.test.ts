import { tmpdir } from "os";
import KeyPair from "../support/key_pair";
import path from "path";
import { mechanics, signing, rotating } from "../../client/src/index";

let infra = require("../infrastructure.json");

describe("Rotating", () => {
  it("Rotate keys", async () => {
    var currentKeyManager = new KeyPair();
    var nextKeyManager = new KeyPair();
    const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);

    let config = new mechanics.ConfigBuilder().withDbPath(tmpFileName).build();

    let controller = new mechanics.Controller(config);

    let keyType = mechanics.KeyType.Ed25519;
    let currentKey = new mechanics.PublicKey(
      keyType,
      Buffer.from(currentKeyManager.pubKey)
    );
    let nextKey = new mechanics.PublicKey(
      keyType,
      Buffer.from(nextKeyManager.pubKey)
    );

    let witnessOobi = infra.witnesses.map((witness) => JSON.stringify(witness));
    let inceptionConfiguration = new mechanics.InceptionConfiguration()
      .withCurrentKeys([currentKey])
      .withNextKeys([nextKey])
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
      [], // no watchers
      signer
    );

    let state = JSON.parse(
      await signingIdentifier.findState(await signingIdentifier.getId())
    );
    expect(state.s).toEqual("0");

    currentKeyManager = nextKeyManager;
    nextKeyManager = new KeyPair();
    let newNextKey = new mechanics.PublicKey(
      keyType,
      Buffer.from(nextKeyManager.pubKey)
    );

    let rotationConfiguration = new mechanics.RotationConfiguration()
      .withCurrentKeys([nextKey])
      .withNextKeys([newNextKey])
      .withWitnessThreshold(1);
    await rotating.rotate(signingIdentifier, rotationConfiguration, signer);

    let stateAfterRot = JSON.parse(
      await signingIdentifier.findState(await signingIdentifier.getId())
    );
    expect(stateAfterRot.s).toEqual("1");
  });
});
