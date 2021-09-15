import keri from "index";
import Tpm from "./support/tpm";
import { expect } from "chai";
import { prefixedDerivative, prefixedSignature } from "./support/sai";
import { b64EncodeUrlSafe } from "./support/b64";
import { countEvents } from "./support/kel";
import inceptor from "./support/inceptor";

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

  describe("negative", () => {
    describe("for incepting", () => {
      it("fails for missing next public key", () => {
        const currentKeyManager = new Tpm();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        expect(() => keri.incept([[curKeySai]])).to.throw("Missing next public key argument");

      });

      it("fails for invalid public key", () => {
        const currentKeyManager = new Tpm();

        let curKeySai = prefixedDerivative(b64EncodeUrlSafe(currentKeyManager.pubKey));
        expect(() => keri.incept([[curKeySai, "ble bla"]])).to.throw("Can't parse public key prefix");
        expect(() => keri.incept([["bla ble", "ble bla"]])).to.throw("Can't parse public key prefix");
        expect(() => keri.incept([["bla ble"]])).to.throw("Can't parse public key prefix");

      });

      it("fails for finalizing invalid inception event", () => {
        const currentKeyManager = new Tpm();
        const nextKeyManager = new Tpm();

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
        const currentKeyManager = new Tpm();
        const nextKeyManager = new Tpm();

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
        const nextKeyManager = new Tpm();
        const newNextKeyManager = new Tpm();

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
