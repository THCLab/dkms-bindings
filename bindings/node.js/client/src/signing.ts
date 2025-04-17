import { mechanics } from "./index";
import { addWatcher, inception, inceptRegistry } from "./utils/incept";
import { queryKelWithSeal } from "./utils/query";

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
		return await identifier.verify(stream)

	} catch (error) {
		 // Extract JSON part from the error message
		const jsonRegex = /\{"i":".*?","s":".*?","d":".*?"\}/;
    const jsonMatch = error.message.match(jsonRegex); 

		if (jsonMatch) {
			try {
        // KEL need to be find
				const seal = JSON.parse(jsonMatch[0]);

				await queryKelWithSeal(identifier, seal.i, Number(seal.s), seal.d, oobi, signingOperation)
        } catch (jsonError) {
            console.error(jsonError);
        }

		return await identifier.verify(stream)
	}
}
}
