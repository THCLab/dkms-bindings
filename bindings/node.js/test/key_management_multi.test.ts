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

 it("Allows actor removing", () => {
   const currentKeyManager0 = new Tpm();
   const currentKeyManager1 = new Tpm();
   // nextKeyManager is required for prerotation to be known
   const nextKeyManager0 = new Tpm();
   const nextKeyManager1 = new Tpm();
   
   let actor1 = {
     currentKeyPrefix: prefixedDerivative(b64EncodeUrlSafe(currentKeyManager0.pubKey)),
     nextKeyPrefix: prefixedDerivative(b64EncodeUrlSafe(nextKeyManager0.pubKey)),
     currentKeyMan: currentKeyManager0,
     currentThreshold: "1/2", 
     nextKeyManager: nextKeyManager0, 
     nextThreshold: "1"
    }
    let actor2 = {
     currentKeyPrefix: prefixedDerivative(b64EncodeUrlSafe(currentKeyManager1.pubKey)),
     nextKeyPrefix: prefixedDerivative(b64EncodeUrlSafe(nextKeyManager1.pubKey)),
     currentKeyMan: currentKeyManager1, 
     currentThreshold: "1/2", 
     nextKeyManager: nextKeyManager1, 
     nextThreshold: "1"
    }

    let inceptionEvent = keri.incept(
      [
        [actor1.currentKeyPrefix, actor1.nextKeyPrefix, actor1.currentThreshold, actor1.nextThreshold],
        [actor2.currentKeyPrefix, actor2.nextKeyPrefix, actor2.currentThreshold, actor2.nextThreshold]
      ]);

    let signature1 = actor1.currentKeyMan.sign(inceptionEvent);
    let signature2 = actor2.currentKeyMan.sign(inceptionEvent);

    let controller = keri.finalizeIncept(
      inceptionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature1)), prefixedSignature(b64EncodeUrlSafe(signature2))]
    );

    expect(countEvents(controller.getKel())).to.eq(1);

    // Check if message signed by actors can be verified.
    let some_message = Buffer.from("to be signed");
    let actor1_signature = prefixedSignature(b64EncodeUrlSafe(actor1.currentKeyMan.sign(some_message)))
    let actor2_signature = prefixedSignature(b64EncodeUrlSafe(actor2.currentKeyMan.sign(some_message)))
    let prefix = controller.getPrefix()
    let ver = controller.verify(some_message, [actor1_signature, actor2_signature], prefix)
    expect(ver).to.be.true

    // Start removing actor2 from group. Prepare new next keypair for
    // actor1 and rotate his keys.
    let newNextKeyManager = new Tpm();
    actor1.currentKeyMan = actor1.nextKeyManager
    actor1.currentKeyPrefix = actor1.nextKeyPrefix
    actor1.currentThreshold = actor1.nextThreshold
    actor1.nextKeyManager = newNextKeyManager;
    actor1.nextKeyPrefix = prefixedDerivative(b64EncodeUrlSafe(newNextKeyManager.pubKey));
    actor1.nextThreshold = "1"

    // Set next key of actor2 to null
    let rotationEvent = controller.rotate(
      [
        [actor1.currentKeyPrefix, actor1.nextKeyPrefix, actor1.currentThreshold, actor1.nextThreshold], 
        [actor2.nextKeyPrefix, null, actor2.nextThreshold]
      ])

    let signature0 = actor1.currentKeyMan.sign(rotationEvent);

    let result = controller.finalizeRotation(
      rotationEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature0))]
    );
    expect(result).to.be.true;
    expect(countEvents(controller.getKel())).to.eq(2);

    // Prepare second rotation, which will remove actor2 from the group.
    // Rotate actors1 keys again.
    let newKeyManager = new Tpm();
    actor1.currentKeyMan = actor1.nextKeyManager
    actor1.currentThreshold = actor1.nextThreshold
    actor1.currentKeyPrefix = actor1.nextKeyPrefix
    actor1.nextKeyManager = newKeyManager;
    actor1.nextKeyPrefix = prefixedDerivative(b64EncodeUrlSafe(newKeyManager.pubKey));
    actor1.nextThreshold = "1"

    let secondRotationEvent = controller.rotate(
      [
        [actor1.currentKeyPrefix, actor1.nextKeyPrefix, actor1.currentThreshold, actor1.nextThreshold]
      ])

    signature0 = actor1.currentKeyMan.sign(secondRotationEvent);

    result = controller.finalizeRotation(
      secondRotationEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature0))]
    );
    expect(result).to.be.true;

    // Check if message signed by actor2 can be verified.
    actor2_signature = prefixedSignature(b64EncodeUrlSafe(actor2.currentKeyMan.sign(some_message)))
    
    expect(() => controller.verify(some_message, [actor2_signature], prefix)).to.throw("Error while verifing: Signature doesn't match any public key")


    expect(countEvents(controller.getKel())).to.eq(3);
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
