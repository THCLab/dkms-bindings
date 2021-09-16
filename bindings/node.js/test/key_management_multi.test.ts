import keri from "index";
import Tpm from "./support/tpm";
import { expect } from "chai";
import { prefixedDerivative, prefixedSignature } from "./support/sai";
import { b64EncodeUrlSafe } from "./support/b64";
import { countEvents } from "./support/kel";

describe("Key management multi", () => {
  it("Allows 1 as fraction threshold", () => {
    const currentKeyManager = new Tpm();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager = new Tpm();

    let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
    let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));

    let inceptionEvent = keri.incept([[curKeySai, nextKeySai, "1"]]);

  });
  it("Allows for key rotation", () => {
    const currentKeyManager0 = new Tpm();
    const currentKeyManager1 = new Tpm();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager0 = new Tpm();
    const nextKeyManager1 = new Tpm();

    let curKeySai0 = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager0.pubKey));
    let nextKeySai0 = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager0.pubKey));

    let curKeySai1 = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager1.pubKey));
    let nextKeySai1 = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager1.pubKey));

    let inceptionEvent = keri.incept([[curKeySai0, nextKeySai0, "1", "1/2"], [curKeySai1, nextKeySai1, "1", "1/2"]]);

    let signature = currentKeyManager0.sign(inceptionEvent);

    let controller = keri.finalizeIncept(
      inceptionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );

    expect(countEvents(controller.getKel())).to.eq(1);

    // Start rotation process, so prepare another key pair and commit
    // to change to this key pair in a next rotation.
    const nextNextKeyManager0 = new Tpm();
    const nextNextKeyManager1 = new Tpm();
    let nextNextKeySai0 = prefixedDerivative(b64EncodeUrlSafe(nextNextKeyManager0.pubKey));
    let nextNextKeySai1 = prefixedDerivative(b64EncodeUrlSafe(nextNextKeyManager1.pubKey));

    let rotationEvent = controller.rotate([[nextKeySai0, nextNextKeySai0, "1/2", "1"], [nextKeySai1, nextNextKeySai1, "1/2", "1"]])

    let signature0 = nextKeyManager0.sign(rotationEvent);
    let signature1 = nextKeyManager1.sign(rotationEvent);

    let result = controller.finalizeRotation(
      rotationEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature0)), prefixedSignature(b64EncodeUrlSafe(signature1))]
    );
    expect(result).to.be.true;

    expect(countEvents(controller.getKel())).to.eq(2);
  });

describe("negative", () => {
  it("fails for improper threshold argument", () => {
      const currentKeyManager = new Tpm();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager = new Tpm();

    let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
    let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));

    expect(() => keri.incept([[curKeySai, nextKeySai, "2"]]))
    .to.throw("Wrong fraction. Should be not greater than 1");
    expect(() => keri.incept([[curKeySai, nextKeySai, "2/1"]]))
    .to.throw("Wrong fraction. Should be not greater than 1");
    expect(() => keri.incept([[curKeySai, nextKeySai, "2.1"]]))
    .to.throw("Wrong threshold format. Can't parse numerator");
    });
  })
});
