import { publish } from "./publish";
import { mechanics } from "index";

export async function inception(
  controller: mechanics.Controller,
  inceptionConfiguration: mechanics.InceptionConfiguration,
  signingOperation: (payload: any) => any
) {
  let inceptionEvent = await controller.incept(inceptionConfiguration);

  let signaturePrefix = signingOperation(inceptionEvent);

  let signingIdentifier = await controller.finalizeInception(inceptionEvent, [
    signaturePrefix,
  ]);

  await publish(signingIdentifier, signingOperation);
  return signingIdentifier;
}

export async function inceptRegistry(identifier: mechanics.JsIdentifier, signingOperation: (payload: any) => any) {
  let registryData = await identifier.inceptRegistry();
  let ixn = registryData.ixn;
  let registryId = registryData.registryId;
  let ixnSignaturePrefix = signingOperation(ixn);
  identifier.finalizeInceptRegistry(ixn, ixnSignaturePrefix);
  await publish(identifier, signingOperation);

  return registryId;
}

export async function addWatcher(identifier: mechanics.JsIdentifier, watcherOobi: string, signingOperation: (payload: any) => any) {
  let add_watcher_event = await identifier.addWatcher(watcherOobi);
  let addWatcherSignaturePrefix = signingOperation(add_watcher_event);
  await identifier.finalizeAddWatcher(
    add_watcher_event,
    addWatcherSignaturePrefix
  );
}
