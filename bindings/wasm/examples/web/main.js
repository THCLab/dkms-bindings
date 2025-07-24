import init, { JsController } from "dkms-wasm";

let controller;
let identifier;

async function initialize() {
  await init();

  controller = new JsController();
  setTimeout(() => {
    const aliases = controller.get_identifier_aliases();

    if (aliases.length === 0) {
      identifier = controller.incept();
      identifier.set_alias("testing_identifier");
    } else {
      const alias = aliases[0]
      identifier = controller.load_identifier(alias)
    }

    if (!identifier.get_watcher()) {
      identifier.add_watcher("http://wa1.ea.argo.colossi.network/").then(() => {
        console.log("Watcher added successfully");
      }).catch(error => {
        console.error("Error adding watcher:", error);
      });
    }
  }, 2000)

  console.log("Controller and Identifier initialized successfully");
}

initialize().catch(console.error);

export async function verify(acdcString, oobiString) {
  if (!controller || !identifier) {
    console.log("Controller not initialized yet, initializing now...");
    await initialize();
  }

  try {
    const acdc = JSON.parse(acdcString);
    const oobi = JSON.parse(oobiString);

    return await controller.verify(identifier, oobi, JSON.stringify(acdc));
  } catch (error) {
    console.error("Verification error:", error);
    return false;
  }
}
