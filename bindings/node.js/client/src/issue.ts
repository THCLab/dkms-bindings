import { publish } from "./publish";

export async function issue(identifier, acdcJSON, signingOperation) {
  let issueData = await identifier.issue(Buffer.from(JSON.stringify(acdcJSON)));
  let issueIxnSignature = signingOperation(issueData.ixn);
  let vcHash = issueData.vcHash;
  identifier.finalizeInceptRegistry(issueData.ixn, issueIxnSignature);

  await publish(identifier, signingOperation);
  await identifier.notifyBackers();
  return vcHash;
}
