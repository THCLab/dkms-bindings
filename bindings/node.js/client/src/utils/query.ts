import { mechanics } from "index";

export async function queryKel(
  identifier: mechanics.JsIdentifier,
  aboutIdentifier: string,
  oobis: string[],
  signingOperation: (payload: any) => any
) {
  for (let item of oobis) {
    await identifier.sendOobiToWatcher(item);
  }

  let kelQueries = await identifier.queryFullKel(await aboutIdentifier);
  for (let item of kelQueries) {
    let kelQrySignature = signingOperation(item);

    for (let retryCount = 1; retryCount <= 10; retryCount++) {
      var resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
      if (resp) {
        break
      }
      const delay = Math.min(2000 ** retryCount, 16000);
      await sleep(delay);
    }
  }
}

export async function queryKelWithSeal(
  identifier: mechanics.JsIdentifier,
  aboutIdentifier: string,
  sn: number,
  digest: string,
  oobis: string[],
  signingOperation: (payload: any) => any
) {
  for (let item of oobis) {
    await identifier.sendOobiToWatcher(item);
  }

  let kelQueries = await identifier.queryKel(aboutIdentifier,sn, digest);
  for (let item of kelQueries) {
    let kelQrySignature = signingOperation(item);

    for (let retryCount = 1; retryCount <= 10; retryCount++) {
      var resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
      if (resp) {
        break
      }
      const delay = Math.min(2000 ** retryCount, 16000);
      await sleep(delay);
      
    }
  }
}

export async function queryTel(
  identifier: mechanics.JsIdentifier,
  vcHash: string,
  registryId: string,
  oobis: string[],
  signingOperation: (payload: any) => any
) {
  for (let item of oobis) {
    await identifier.sendOobiToWatcher(item);
  }

  let cached_state = await identifier.vcState(vcHash);
  for (let retryCount = 1; retryCount <= 10; retryCount++) {
      let telQry = await identifier.queryTel(registryId, vcHash);
      let telQrySigPrefix = signingOperation(telQry);
      await identifier.finalizeQueryTel(telQry, telQrySigPrefix);
      let st = await identifier.vcState(vcHash);
      if (st != cached_state) {
        break
      }
      const delay = Math.min(2000 ** retryCount, 16000);
      await sleep(delay);
      
    }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
