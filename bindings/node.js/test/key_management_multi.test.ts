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
