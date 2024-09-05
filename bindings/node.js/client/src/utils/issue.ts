import { publish } from "./publish";
import { mechanics } from "index";

export async function issuance(
  identifier: mechanics.JsIdentifier,
  acdcJSON: string,
  signingOperation: (payload: any) => any
) {
  let issueData = await identifier.issue(Buffer.from(JSON.stringify(acdcJSON)));
  let issueIxnSignature = signingOperation(issueData.ixn);
  let vcHash = issueData.vcHash;
  identifier.finalizeIssue(issueData.ixn, issueIxnSignature);

  await publish(identifier, signingOperation);
  await identifier.notifyBackers();
  return vcHash;
}

export async function revocation(
  identifier: mechanics.JsIdentifier,
  vcHash: string,
  signingOperation: (payload: any) => any
) {
  let ixn = await identifier.revoke(vcHash);
  let revokeIxnSignature = signingOperation(ixn);
  await identifier.finalizeRevoke(ixn, revokeIxnSignature);

  await publish(identifier, signingOperation);
  await identifier.notifyBackers();
}

