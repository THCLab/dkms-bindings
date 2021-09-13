import keri, {KeriController} from "index";
import {b64EncodeUrlSafe} from "./b64";
import {prefixedDerivative, prefixedSignature} from "./sai";
import Tpm from "./tpm";

export default (): [KeriController, Tpm] => {
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

  return [ controller, currentKeyManager ];
};
