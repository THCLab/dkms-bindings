import { tmpdir } from "os";
import KeyPair from "./support/key_pair";
import * as path from 'path';
import { ConfigBuilder, Controller, PublicKey, KeyType, InceptionConfiguration, SignatureType, SignatureBuilder } from "index";

/**
 * Helper function for sending new events to witnesses and collecting their receipts
*/  
async function publish(identifier, sigType, currentKeyManager) {
  await identifier.notifyWitness();

    let qry = (await identifier.queryMailbox())[0];
    console.log(qry.toString())
    let qry_signature = currentKeyManager.sign(qry);

    let qrySignaturePrefix = new SignatureBuilder(sigType, Buffer.from(qry_signature));

    await identifier.finalizeQueryMailbox([qry], [qrySignaturePrefix.getSignature()]);
}

describe("Incepting", () => {
	it("incept", async () => {
	  const currentKeyManager = new KeyPair();
	  const nextKeyManager = new KeyPair();
	  const tmpFileName = path.join(tmpdir(), `tmpfile-${Date.now()}.txt`);
  
	  let config = new ConfigBuilder().withDbPath(tmpFileName).build();
  
	  console.log(config)
	  console.log(typeof(config))
	  let controller = new Controller(config);
  
	  let keyType = KeyType.Ed25519;
	  let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
	  let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));
  
	  console.log(pk.getKey())
	  let witness_oobi =`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}`;
  
	  let inceptionConfiguration = (new InceptionConfiguration)
	  	.withCurrentKeys([pk])
	  	.withNextKeys([pk2])
		.withWitness([witness_oobi])
		.withWitnessThreshold(1);

	  let inceptionEvent = await controller.incept(
		inceptionConfiguration,
	  );
	  console.log(inceptionEvent.toString())
  
	  let signature = currentKeyManager.sign(inceptionEvent);
  
	  let sigType = SignatureType.Ed25519Sha512;
	  let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));
  
	  let signingIdentifier = await controller.finalizeInception(
		inceptionEvent,
		[signaturePrefix]
	  );
  
	  await publish(signingIdentifier, sigType, currentKeyManager)
  
	});
  });
  