import { mechanics } from "index";
import { addWatcher, inception, inceptRegistry } from "./utils/incept";
import { issuance, revocation } from "./utils/issue";
import { queryKel, queryTel } from "./utils/query";
import { VcState } from "mechanics";

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
  await inceptRegistry(identifier, signingOperation);
  for (let item of watcherOobis) {
    await addWatcher(identifier, item, signingOperation);
  }

  return identifier;
}

export async function issue(
  identifier: mechanics.JsIdentifier,
  acdc: string,
  signingOperation: (payload: any) => any
) {
  let vcHash = await issuance(identifier, acdc, signingOperation);
  return vcHash;
}

export async function revoke(
  identifier: mechanics.JsIdentifier,
  vcHash: string,
  signingOperation: (payload: any) => any
) {
    await revocation(identifier, vcHash, signingOperation);
}

export async function verify(
  identifier: mechanics.JsIdentifier,
  vcHash: string,
  signerId: string,
  oobi: string[],
  registryId: string,
  registryOobi: string[],
  signingOperation: (payload: any) => any
) {
  await queryKel(identifier, signerId, oobi, signingOperation);

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
      return JSON.stringify({ verified: true, status: "issued" });
      break;
    case VcState.NotIssued:
      return JSON.stringify({ verified: false, status: "not issued" });
      break;
    case VcState.Revoked:
      return JSON.stringify({ verified: false, status: "revoked" });
      break;
    default:
      console.log("No match found");
  }
}
