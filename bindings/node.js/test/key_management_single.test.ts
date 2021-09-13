import keri from "index";
import Tpm from "./support/tpm";
import { expect } from "chai";
import { prefixedDerivative, prefixedSignature } from "./support/sai";
import { b64EncodeUrlSafe } from "./support/b64";
import { countEvents } from "./support/kel";

describe("Key management simple", () => {
  it("Allows for key rotation", () => {
    const currentKeyManager = new Tpm();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager = new Tpm();

    let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
    let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));

    let inceptionEvent = keri.incept([[curKeySai, nextKeySai]]);

    let signature = currentKeyManager.sign(inceptionEvent);

    let controller = keri.finalizeIncept(
      inceptionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );

    expect(controller.prefix).to.eql(curKeySai);
    expect(countEvents(controller.getKel())).to.eq(1);

    // Start rotation process, so prepare another key pair and commit
    // to change to this key pair in a next rotation.
    const nextNextKeyManager = new Tpm();
    let nextNextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextNextKeyManager.pubKey));

    let rotationEvent = controller.rotate([[nextKeySai, nextNextKeySai]])

    signature = nextKeyManager.sign(rotationEvent);

    let result = controller.finalizeRotation(
      rotationEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );
    expect(result).to.be.true;

    expect(countEvents(controller.getKel())).to.eq(2);
  });
});
