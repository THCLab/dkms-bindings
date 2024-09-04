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

    for (let count = 1; count <= 10; count++) {
      var resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
      if (resp) {
        break
      }
      await sleep(1000);
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

    for (let count = 1; count <= 10; count++) {
      var resp = await identifier.finalizeQueryKel([item], [kelQrySignature]);
      if (resp) {
        break
      }
      await sleep(1000);
      
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

  for (let count = 1; count <= 10; count++) {
      let telQry = await identifier.queryTel(registryId, vcHash);
      let telQrySigPrefix = signingOperation(telQry);
      await identifier.finalizeQueryTel(telQry, telQrySigPrefix);
      let st = await identifier.vcState(vcHash);
      if (st != null) {
        break
      }
      await sleep(1000);
      
    }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
