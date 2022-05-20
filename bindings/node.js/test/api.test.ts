import Tpm from "./support/tpm";
import keri from "../index";

describe("Managing controller", () => {
  it("", () => {
  const currentKeyManager = new Tpm();
  const nextKeyManager = new Tpm();
  const nextNextKeyManager = new Tpm();

  const known_oobis = `[
		{
			"eid": "BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
			"scheme": "http",
			"url": "http://localhost:3232/"
		}
	]`;
  let controller = keri.Controller.init(known_oobis);

  let key_type = keri.KeyType.Ed25519;
  let pk = new keri.PublicKey(key_type, Buffer.from(currentKeyManager.pubKey));
  let pk2 = new keri.PublicKey(key_type, Buffer.from(nextKeyManager.pubKey));
  let pk3 = new keri.PublicKey(key_type, Buffer.from(nextNextKeyManager.pubKey));

  console.log(pk.getKey())

  let inceptionEvent = keri.incept(
    [pk.getKey()], 
    [pk2.getKey()], 
    ["BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],
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

  console.log(inceptedController.getId())
  // let id_cont = cont.getByIdentifier(controller)
  // console.log(cont)
  let stringData = `{"data":"important data"}`
  let dataToSign = Buffer.from(stringData)
  let dataSignature = nextKeyManager.sign(dataToSign);
  let dataSignaturePrefix = new keri.SignatureBuilder(sigType, Buffer.from(dataSignature));
  let attachedSignature = inceptedController.signData(dataSignaturePrefix.getSignature());

  let signedACDC = stringData.concat(attachedSignature);
  console.log(signedACDC)
  });
});
