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
  console.log("cached state", cached_state);
  for (let retryCount = 1; retryCount <= 2; retryCount++) {
      console.log("query tel attempt", retryCount);
      let telQry = await identifier.queryTel(registryId, vcHash);
      console.log("tel query", telQry);
      let telQrySigPrefix = signingOperation(telQry);
      await identifier.finalizeQueryTel(telQry, telQrySigPrefix);
      let st = await identifier.vcState(vcHash);
      console.log("queried state", st);
      if (st != cached_state) {
        break
      } else {
      }
    }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
