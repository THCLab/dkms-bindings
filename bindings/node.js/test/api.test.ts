import Tpm from "./support/tpm";
import keri from "../index";

describe("Managing controller", () => {
  it("", () => {
  const currentKeyManager = new Tpm();
  const nextKeyManager = new Tpm();
  const nextNextKeyManager = new Tpm();

  let controller = keri.Controller.init();

  let key_type = keri.KeyType.Ed25519;
  let pk = new keri.PublicKey(key_type, Buffer.from(currentKeyManager.pubKey));
  let pk2 = new keri.PublicKey(key_type, Buffer.from(nextKeyManager.pubKey));
  let pk3 = new keri.PublicKey(key_type, Buffer.from(nextNextKeyManager.pubKey));

  console.log(pk.getKey())

  let inceptionEvent = keri.incept(
    [pk.getKey()], 
    [pk2.getKey()], 
    ["BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE", "BZFIYlHDQAHxHH3TJsjMhZFbVR_knDzSc3na_VHBZSBs", "BYSUc5ahFNbTaqesfY-6YJwzALaXSx-_Mvbs6y3I74js"],
    1
    );
  console.log(inceptionEvent.toString())

  let signature = currentKeyManager.sign(inceptionEvent);
  
  let sigType = keri.SignatureType.Ed25519Sha512;
  let signaturePrefix = new keri.SignatureBuilder(sigType, Buffer.from(signature));

  let inceptedController = controller.finalizeInception(
    inceptionEvent,
    [signaturePrefix.getSignature()]
  );

  console.log(inceptedController.getKel())

  let rotationEvent = inceptedController.rotate([pk2.getKey()], [pk3.getKey()], [], ["BYSUc5ahFNbTaqesfY-6YJwzALaXSx-_Mvbs6y3I74js"], 2);
  console.log(rotationEvent.toString())

  let signature2 = nextKeyManager.sign(rotationEvent);
  let signaturePrefix2 = new keri.SignatureBuilder(sigType, Buffer.from(signature2));

  inceptedController.finalizeEvent(rotationEvent, [signaturePrefix2.getSignature()])
  console.log(inceptedController.getKel())

  let interactionEvent = inceptedController.interact(["E3WFzw8WgDMFPpup9UJI3Wwu41h16NNJVzkKclj2_6Rc"]);
  let signature3 = nextKeyManager.sign(interactionEvent);
  let signaturePrefix3 = new keri.SignatureBuilder(sigType, Buffer.from(signature3));

  inceptedController.finalizeEvent(interactionEvent, [signaturePrefix3.getSignature()])
  console.log(inceptedController.getKel())

  // let id_cont = cont.getByIdentifier(controller)
  // console.log(cont)

  });
});
