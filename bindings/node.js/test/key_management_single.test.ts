import keri from "index"
import Tpm from "./support/tpm";
import URLSafeBase64 from 'urlsafe-base64';
import { expect } from "chai";

let b64EncodeUrlSafe = (p: Uint8Array) => URLSafeBase64.encode(Buffer.from(p));

// See https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#base64-master-code-table
// for count codes explanation.
let sai = (derivative: string) => `D${derivative}`;
let prefixedSignature = (signature: string) => `0B${signature}`;
let countJSONs = (KEL: string) => KEL.match(/{.*?}/g).length;

describe("Key management simple", () => {
  it("Allows for key rotation", () => {
    const currentKeyManager = new Tpm();
    // nextKeyManager is required for prerotation to be known
    const nextKeyManager = new Tpm();

    let curKeySai = sai(b64EncodeUrlSafe(currentKeyManager.pubKey));
    let nextKeySai = sai(b64EncodeUrlSafe(nextKeyManager.pubKey));

    let inceptionEvent = keri.incept([[curKeySai, nextKeySai]]);

    let signature = currentKeyManager.sign(inceptionEvent);

    let controller = keri.finalizeIncept(
      inceptionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );

    expect(controller.prefix).to.eql(curKeySai);
    expect(countJSONs(controller.getKel())).to.eq(1);

    // Start rotation process, so prepare another key pair and commit
    // to change to this key pair in a next rotation.
    const nextNextKeyManager = new Tpm();
    let nextNextKeySai = sai(b64EncodeUrlSafe(nextNextKeyManager.pubKey));

    let rotationEvent = controller.rotate([[nextKeySai, nextNextKeySai]])

    signature = nextKeyManager.sign(rotationEvent);

    let result = controller.finalizeRotation(
      rotationEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );
    expect(result).to.be.true;

    expect(countJSONs(controller.getKel())).to.eq(2);
  });
});
