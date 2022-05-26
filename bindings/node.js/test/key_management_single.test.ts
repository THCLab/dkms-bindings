import keri from "index";
import KeyPair from "./support/tpm";
import { expect } from "chai";
import { prefixedDerivative, prefixedSignature } from "./support/sai";
import { b64EncodeUrlSafe } from "./support/b64";
import { countEvents } from "./support/kel";
import inceptor from "./support/inceptor";

describe("Key management simple", () => {
  it("Allows for key rotation", () => {
    const currentKeyManager = new KeyPair();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager = new KeyPair();

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
    const nextNextKeyManager = new KeyPair();
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

  describe("negative", () => {
    describe("for incepting", () => {
      it("fails for missing next public key", () => {
        const currentKeyManager = new KeyPair();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        expect(() => keri.incept([[curKeySai]])).to.throw("Missing public key argument");

      });

      it("fails for invalid public key", () => {
        const currentKeyManager = new KeyPair();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        expect(() => keri.incept([[curKeySai, "ble bla"]])).to.throw("Can't parse public key prefix");
        expect(() => keri.incept([["bla ble", "ble bla"]])).to.throw("Can't parse public key prefix");
        expect(() => keri.incept([["bla ble"]])).to.throw("Can't parse public key prefix");

      });

      it("fails for finalizing invalid inception event", () => {
        const currentKeyManager = new KeyPair();
        const nextKeyManager = new KeyPair();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));

        let inceptionEvent = keri.incept([[curKeySai, nextKeySai]]);

        let signature = currentKeyManager.sign(inceptionEvent);

        expect(() => keri.finalizeIncept(Buffer.from("whatever"), [prefixedSignature(b64EncodeUrlSafe(signature))]))
        .to.throw("Invalid inception event");

        // TODO
        // expect(() => keri.finalizeIncept("whatever" as any, [prefixedSignature(b64EncodeUrlSafe(signature))]))
        // .to.throw("Invalid inception event");

        expect(() => keri.finalizeIncept(inceptionEvent, [b64EncodeUrlSafe(signature)]))
        .to.throw("Can't parse signature prefix");
      });

      it("fails for finalizing invalid inception signature", () => {
        const currentKeyManager = new KeyPair();
        const nextKeyManager = new KeyPair();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));

        let inceptionEvent = keri.incept([[curKeySai, nextKeySai]]);

        expect(() => keri.finalizeIncept(inceptionEvent, ["whatever"]))
        .to.throw("Can't parse signature prefix");
      });
    }),
    describe("for rotating", () => {
      it("fails for finalizing rotation with incorrect signature", () => {
        let [ controller ] = inceptor();
        const nextKeyManager = new KeyPair();
        const newNextKeyManager = new KeyPair();

        let nextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextKeyManager.pubKey));
        let newNextKeySai = prefixedDerivative(b64EncodeUrlSafe(newNextKeyManager.pubKey));
        let rotationEvent = controller.rotate([[nextKeySai, newNextKeySai]]);
        let signature = prefixedSignature(b64EncodeUrlSafe(nextKeyManager.sign(rotationEvent)));

        expect(() => controller.finalizeRotation(
          Buffer.from("whatever"),
          [signature]
        )).to.throw("Invalid rotation event");

        expect(() => controller.finalizeRotation(rotationEvent, ["whatever"]))
        .to.throw("Can't parse signature prefix");
      });
    })
  });
});

describe("Event processing", () => {
  it("Allows for event stream processing", () => {
    let controller = keri.new();

    let stream = '{"v":"KERI10JSON0000ed_","i":"Df8yygohMOcTVRxLr74Zbk5DKtRjT35gg9hcr2lOlEh4","s":"0","t":"icp","kt":"1","k":["Df8yygohMOcTVRxLr74Zbk5DKtRjT35gg9hcr2lOlEh4"],"n":"EMFLLpV9jSGyGGIBx4IdOQlTa6LZX6kC6QwDlS_0L_Gk","bt":"0","b":[],"c":[],"a":[]}-AABAATe_FOqPrp6JUNv0_i5Xmm4Y30YJWrNwx-7-o2c63p_u0UF9ptiAobv8getj5HOtllChT2Gb3Li_g-CYmpONpAw{"v":"KERI10JSON000122_","i":"Df8yygohMOcTVRxLr74Zbk5DKtRjT35gg9hcr2lOlEh4","s":"1","t":"rot","p":"EIOBKs0FH5A_IlE7SRJMmRBqHj5QZuXWx2mKwdGKwESk","kt":"1","k":["DAZ4CXhMsI_Ix-iK-QoMvFrHVSKg1TfEJjIhy0whYDXU"],"n":"EO_vdGoQQRqmKM2089bNnB7tNc1XMse3wX0vVN79-bpU","bt":"0","br":[],"ba":[],"a":[]}-AABAAP74qL41Eq2js3xSbHBXlQEN_BSRyM2xjyI0cjjYd7xU0hgWPNGBD_mfx7Fx5H4W8KTTNafxaIS2CDWYUKt6zCg{"v":"KERI10JSON000098_","i":"Df8yygohMOcTVRxLr74Zbk5DKtRjT35gg9hcr2lOlEh4","s":"2","t":"ixn","p":"EVP3aOimJHaDcHLiFeKQ27woiZaspY3dKjh7YcfQChSM","a":[]}-AABAArtb0OPt5ZDbFdUJqWxmURTvQMrPGcz1U0hd88CNsy9fWs2cGeF3hQ3f4-utB6jHSbXgVAU_IgOVF7lKmYNnzBQ'
    controller.process(Buffer.from(stream))

    let kel = controller.get_kel_for_prefix("Df8yygohMOcTVRxLr74Zbk5DKtRjT35gg9hcr2lOlEh4")

    expect(kel).to.eql(stream);
    expect(countEvents(kel)).to.eq(3);
    });
  });
