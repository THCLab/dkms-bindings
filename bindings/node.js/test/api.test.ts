import KeyPair from "./support/key_pair";
// import { ConfigBuilder, Controller, KeyType, PublicKey, SignatureBuilder, SignatureType } from "index";
import { Controller, KeyType, SignatureType, ConfigBuilder, PublicKey, SignatureBuilder} from "index";

describe("Managing controller", () => {
  it("", async () => {
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const nextNextKeyManager = new KeyPair();

    let config = new ConfigBuilder().withDbPath("./database").build();
    console.log(config)
    console.log(typeof(config))
    let controller = new Controller(config);
    // console.log(controller);
    // controller.init(config)

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));
    let pk3 = new PublicKey(keyType, Buffer.from(nextNextKeyManager.pubKey));

    console.log(pk.getKey())
    let witness_oobi=`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;

    let inceptionEvent = await controller.incept(
      [pk.getKey()],
      [pk2.getKey()],
      [witness_oobi],
      1
    );
    console.log(inceptionEvent.toString())

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    let inceptedIdentifier = await controller.finalizeInception(
      inceptionEvent,
      [signaturePrefix.getSignature()]
    );

    await inceptedIdentifier.notifyWitness();

    let qry = (await inceptedIdentifier.queryMailbox())[0];
    console.log(qry.toString())
    let qry_signature = currentKeyManager.sign(qry);

    let qrySignaturePrefix = new SignatureBuilder(sigType, Buffer.from(qry_signature));

    await inceptedIdentifier.finalizeQueryMailbox([qry], [qrySignaturePrefix.getSignature()]);

    console.log(await inceptedIdentifier.getKel())

    // let rotationEvent = inceptedController.rotate([pk2.getKey()], [pk3.getKey()], [], ["BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"], 0);
    // console.log(rotationEvent.toString())

    // let signature2 = nextKeyManager.sign(rotationEvent);
    // let signaturePrefix2 = new SignatureBuilder(sigType, Buffer.from(signature2));

    // inceptedController.finalizeEvent(rotationEvent, [signaturePrefix2.getSignature()])
    // console.log(inceptedController.getKel())

    // let interactionEvent = inceptedController.anchor(["E3WFzw8WgDMFPpup9UJI3Wwu41h16NNJVzkKclj2_6Rc"]);
    // let signature3 = nextKeyManager.sign(interactionEvent);
    // let signaturePrefix3 = new SignatureBuilder(sigType, Buffer.from(signature3));

    // inceptedController.finalizeEvent(interactionEvent, [signaturePrefix3.getSignature()])
    // console.log(inceptedController.getKel())

    // console.log(inceptedController.getId())
    // // let id_cont = cont.getByIdentifier(controller)
    // // console.log(cont)
    // let stringData = `{"data":"important data"}`
    // let dataToSign = Buffer.from(stringData)
    // let dataSignature = nextKeyManager.sign(dataToSign);
    // let dataSignaturePrefix = new SignatureBuilder(sigType, Buffer.from(dataSignature));
    // let attachedSignature = inceptedController.signData(dataSignaturePrefix.getSignature());

    // let signedACDC = stringData.concat(attachedSignature);
    // console.log(signedACDC)
  });
});
