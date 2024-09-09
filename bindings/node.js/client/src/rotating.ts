import { mechanics } from "index";
import { publish } from "./utils/publish";

export async function rotate(
  identifier: mechanics.JsIdentifier,
  rotationConfiguration: mechanics.RotationConfiguration,
  signingOperation: (payload: any) => any
) {
	let rotationEvent = await identifier.rotate(rotationConfiguration);
  
	let rotSignature = signingOperation(rotationEvent);
	await identifier.finalizeRotation(rotationEvent, rotSignature);

	await publish(identifier, signingOperation);
}