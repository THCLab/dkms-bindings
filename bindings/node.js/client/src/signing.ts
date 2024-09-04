import { mechanics } from "./index";
import { addWatcher, inception, inceptRegistry } from "./utils/incept";
import { issuance } from "./utils/issue";
import { queryKel, queryKelWithSeal, queryTel } from "./utils/query";

export async function incept(
  controller: mechanics.Controller,
  inceptionConfiguration: mechanics.InceptionConfiguration,
  watcherOobis: string[],
  signingOperation: (payload: any) => any
) {
  let identifier = await inception(
    controller,
    inceptionConfiguration,
    signingOperation
  );
  for (let item of watcherOobis) {
    await addWatcher(identifier, item, signingOperation);
  }

  return identifier;
}

export async function sign(
  identifier: mechanics.JsIdentifier,
  payload: string,
  signingOperation: (payload: any) => any
) {
	let signature = signingOperation(Buffer.from(payload));
	let stream = await identifier.sign(payload, [signature])
	return stream
}

export async function verify(
  identifier: mechanics.JsIdentifier,
  oobi: string[],
  stream: string,
  signingOperation: (payload: any) => any
){

	try {
		await identifier.verify(stream);
		return true

	} catch (error) {
		 // Extract JSON part from the error message
		const jsonRegex = /\{ prefix:[^]+, sn:[^]+, event_digest:[^]+ \}/;
    	const jsonMatch = error.message.match(jsonRegex); 

		if (jsonMatch) {
			try {
        // KEL need to be find
				let jsonString = jsonMatch[0];
				// Step 1: Add quotes around keys
				jsonString = jsonString.replace(/(\w+):/g, '"$1":');

				// Step 2: Replace SelfAddressing("...") with just the content inside the quotes
				jsonString = jsonString.replace(/SelfAddressing\("([^"]+)"\)/g, '"$1"');

				const seal = JSON.parse(jsonString);

				await queryKelWithSeal(identifier, seal.prefix, seal.sn, seal.event_digest, oobi, signingOperation)
        } catch (jsonError) {
            console.error(jsonError);
        }

		let ver = await identifier.verify(stream);
		return true
	}
}
}
