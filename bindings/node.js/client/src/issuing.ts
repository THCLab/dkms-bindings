import { mechanics } from "index";
import { inception, inceptRegistry } from "./utils/incept";
import { issuance } from "./utils/issue";
import { queryKel, queryTel } from "./utils/query";
import { VcState } from "mechanics";

export async function incept(controller: mechanics.Controller,
  inceptionConfiguration: mechanics.InceptionConfiguration,
  signingOperation: (payload: any) => any) {
	let identifier = await inception(controller, inceptionConfiguration, signingOperation);
	await inceptRegistry(identifier, signingOperation);
	return identifier
}


export async function issue(identifier: mechanics.JsIdentifier,
  acdc: string,
  signingOperation: (payload: any) => any
) {
	let vcHash = await issuance(identifier, acdc, signingOperation);
	return vcHash
}

export async function verify(identifier: mechanics.JsIdentifier,
	vcHash: string,
	signerId: string,
  	oobi: string[],
	registryId: string,
  	registryOobi: string[],
  	signingOperation: (payload: any) => any
) {
	await queryKel(
      identifier,
      signerId,
      oobi,
      signingOperation
    );

    let st = await identifier.findState(
      await signerId
    );

    // Query TEL
    await queryTel(
      identifier,
      vcHash,
      registryId,
      registryOobi,
      signingOperation
    );

    let tst = await identifier.vcState(vcHash);
	switch (tst) {
    case VcState.Issued:
		return JSON.stringify({"status":"issued"})
        break;
    case VcState.NotIssued:
		return JSON.stringify({"status":"not issued"})
        break;
    case VcState.Revoked:
		return JSON.stringify({"status":"revoked"})
        break;
    default:
        console.log("No match found");
}
}