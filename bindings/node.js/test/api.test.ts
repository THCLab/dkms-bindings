import KeyPair from "./support/key_pair";
import { ConfigBuilder, Controller, KeyType, PublicKey, SignatureBuilder, SignatureType } from "index";

describe("Managing controller", () => {
  it("", () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const nextNextKeyManager = new KeyPair();

    let config = new ConfigBuilder().withDbPath("./database").build();
    let controller = new Controller(config);

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));
    let pk3 = new PublicKey(keyType, Buffer.from(nextNextKeyManager.pubKey));

    console.log(pk.getKey())

    let inceptionEvent = controller.incept(
      [pk.getKey()],
      [pk2.getKey()],
      [`{
      "eid": "BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
      "scheme": "http",
      "url": "http://localhost:3232/"
    }`],
      1
    );
    console.log(inceptionEvent.toString())

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    let inceptedController = controller.finalizeInception(
      inceptionEvent,
      [signaturePrefix.getSignature()]
    );

    console.log(inceptedController.getKel())

    let rotationEvent = inceptedController.rotate([pk2.getKey()], [pk3.getKey()], [], ["BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"], 0);
    console.log(rotationEvent.toString())

    let signature2 = nextKeyManager.sign(rotationEvent);
    let signaturePrefix2 = new SignatureBuilder(sigType, Buffer.from(signature2));

    inceptedController.finalizeEvent(rotationEvent, [signaturePrefix2.getSignature()])
    console.log(inceptedController.getKel())

    let interactionEvent = inceptedController.anchor(["E3WFzw8WgDMFPpup9UJI3Wwu41h16NNJVzkKclj2_6Rc"]);
    let signature3 = nextKeyManager.sign(interactionEvent);
    let signaturePrefix3 = new SignatureBuilder(sigType, Buffer.from(signature3));

    inceptedController.finalizeEvent(interactionEvent, [signaturePrefix3.getSignature()])
    console.log(inceptedController.getKel())

    console.log(inceptedController.getId())
    // let id_cont = cont.getByIdentifier(controller)
    // console.log(cont)
    let stringData = `{"data":"important data"}`
    let dataToSign = Buffer.from(stringData)
    let dataSignature = nextKeyManager.sign(dataToSign);
    let dataSignaturePrefix = new SignatureBuilder(sigType, Buffer.from(dataSignature));
    let attachedSignature = inceptedController.signData(dataSignaturePrefix.getSignature());

    let signedACDC = stringData.concat(attachedSignature);
    console.log(signedACDC)
  });
});
