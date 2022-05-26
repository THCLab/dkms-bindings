import { expect } from "chai";
import { prefixedBlake3Digest, prefixedSignature } from "./support/sai";
import { b64EncodeUrlSafe } from "./support/b64";
import { countEvents } from "./support/kel";
import inceptor from "./support/inceptor";
import {randomBytes} from "crypto";

describe("Anchoring on ledger", () => {
  it("Allows for anchoring one digest", () => {
    let [ controller, currentKeyManager ] = inceptor(
      ['{ "eid": "BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA", "scheme": "http", "url": "http://localhost:3232/" }']
    );

    let interactionEvent = controller.anchor(["E6ISnmMK-TfP0uN2lLp5vL6JxxBNjXLZ7bpDBkjxngdE"])

    let signature = currentKeyManager.sign(interactionEvent);

    let result = controller.finalizeAnchor(
      interactionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );
    expect(result).to.be.true;

    expect(countEvents(controller.getKel())).to.eq(2);
  });

  it("Allows for anchoring multiple digests into one event", () => {
    let [ controller, currentKeyManager ] = inceptor();

    let firstDigest = prefixedBlake3Digest(b64EncodeUrlSafe(randomBytes(32)));
    let secondDigest = prefixedBlake3Digest(b64EncodeUrlSafe(randomBytes(32)));
    let thirdDigest = prefixedBlake3Digest(b64EncodeUrlSafe(randomBytes(32)));

    let interactionEvent = controller.anchor([ firstDigest, secondDigest, thirdDigest ]);

    let signature = currentKeyManager.sign(interactionEvent);

    let result = controller.finalizeAnchor(
      interactionEvent,
      [prefixedSignature(b64EncodeUrlSafe(signature))]
    );
    expect(result).to.be.true;

    let kel = controller.getKel();
    expect(countEvents(kel)).to.eq(2);

    expect(controller.isAnchored(firstDigest));
    expect(controller.isAnchored(secondDigest));
    expect(controller.isAnchored(thirdDigest));

  });

  describe("negative", () => {
    it("fails for not recognized digest format", () => {
      let [ controller ] = inceptor();

      expect(() => controller.anchor([ "whatever" ])).to.throw("Can't parse sai prefix");
    });
  });
});
