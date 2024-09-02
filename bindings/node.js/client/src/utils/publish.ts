export async function publish(identifier, signingOperation) {
  await identifier.notifyWitness();

  let qry = await identifier.queryMailbox();
  qry.forEach(async (qry) => {
    let qrySignaturePrefix = signingOperation(qry);
    await identifier.finalizeQueryMailbox([qry], [qrySignaturePrefix]);
  });
}
