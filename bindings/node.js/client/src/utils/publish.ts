import { mechanics } from "index";

export async function publish(identifier: mechanics.JsIdentifier, signingOperation: (payload: any) => any) {
  await identifier.notifyWitness();

  let qry = await identifier.queryMailbox();
  qry.forEach(async (qry) => {
    let qrySignaturePrefix = signingOperation(qry);
    await identifier.finalizeQueryMailbox([qry], [qrySignaturePrefix]);
  });
}
