export async function queryKel(
  identifier,
  aboutIdentifier,
  oobis,
  signingOperation
) {
  for (let item of oobis) {
    await identifier.sendOobiToWatcher(item);
  }

  let kelQueries = await identifier.queryFullKel(await aboutIdentifier);
  for (let item of kelQueries) {
    let kelQrySignature = signingOperation(item);

    let resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
    while (!resp) {
      await sleep(1000);
      resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
      console.log(resp);
    }
  }
}

export async function queryTel(
  identifier,
  vcHash,
  registryId,
  oobis,
  signingOperation
) {
  for (let item of oobis) {
    await identifier.sendOobiToWatcher(item);
  }

  while ((await identifier.vcState(vcHash)) == "None") {
    await sleep(1000);
    let telQry = await identifier.queryTel(registryId, vcHash);
    let telQrySigPrefix = signingOperation(telQry);
    await identifier.finalizeQueryTel(telQry, telQrySigPrefix);
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
