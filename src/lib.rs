use keri::{
    derivation::self_signing::SelfSigning,
    prefix::{AttachedSignaturePrefix, Prefix},
    signer::{CryptoBox, KeyManager},
};
use neon::prelude::*;
use tempfile::Builder;
pub mod kerl;
use base64::{self, URL_SAFE};
use kerl::{error::Error, KERL};

pub struct Controller {
    km: CryptoBox,
    kerl: KERL,
}

impl Controller {
    pub fn get_prefix(&self) -> String {
        self.kerl.get_prefix().to_str()
    }

    pub fn get_kerl(&self) -> Result<String, Error> {
        Ok(String::from_utf8(
            self.kerl
                .get_kerl()?
                .ok_or(Error::Generic("There is no kerl".into()))?,
        )?)
    }

    pub fn rotate(&mut self) -> Result<String, Error> {
        self.km.rotate()?;
        let rot = self.kerl.rotate(&self.km);
        Ok(String::from_utf8(rot?.serialize()?)?)
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Result<String, Error> {
        Ok(base64::encode_config(self.km.sign(msg)?, URL_SAFE))
    }

    pub fn process(&self, kerl: &[u8]) -> Result<(), Error> {
        self.kerl.process_stream(kerl)
    }

    pub fn verify(&self, message: &[u8], signature: &str, prefix: &str) -> Result<bool, Error> {
        let prefix = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kerl
            .get_state_for_prefix(&prefix)?
            .ok_or(Error::Generic("There is no state".into()))?
            .current;
        let sigs = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature.to_vec(),
            0,
        )];
        key_conf
            .verify(message, &sigs)
            .map_err(|e| Error::Generic(e.to_string()))
    }
}

declare_types! {
    pub class JsController for Controller {
        init(mut _cx) {
            let root = Builder::new().prefix("test-db").tempdir().expect("Temporary dir ectory error");
            let mut kerl = KERL::new(root.path()).expect("Error while creating kerl");
            let km = CryptoBox::new().expect("Error while generating keys");
            kerl.incept(&km).expect("Error while creating inception event");
            Ok(Controller {km, kerl})
        }

        method get_kerl(mut cx) {
            let this = cx.this();
            let kerl = {
                this.borrow(&cx.lock()).get_kerl().expect("Can't get kerl")
            };
            Ok(cx.string(kerl).upcast())
        }

        method rotate(mut cx) {
            let mut this = cx.this();
            let rot_event = this.borrow_mut(&cx.lock()).rotate().expect("No rotation event");
            Ok(cx.string(rot_event).upcast())
        }

        method sign(mut cx) {
            let message: String = cx.argument::<JsString>(0)?.value();
            let this = cx.this();
            let signature = {
                this.borrow(&cx.lock()).sign(&message.as_bytes().to_vec()).expect("Error while signing")
            };
            Ok(cx.string(signature).upcast())
        }

        method process_kerl(mut cx) {
            let kerl: String = cx.argument::<JsString>(0)?.value();
            let this = cx.this();

            this.borrow(&cx.lock()).process(&kerl.as_bytes()).expect("Error while processing events");

            Ok(cx.string("ok").upcast())
        }

        method verify(mut cx) {
            let message: String = cx.argument::<JsString>(0)?.value();
            let signature: String = cx.argument::<JsString>(1)?.value();
            let identifier: String = cx.argument::<JsString>(2)?.value();
            let this = cx.this();

            let ver_result = {
                this.borrow(&cx.lock()).verify(&message.as_bytes(), &signature, &identifier).expect("Error while verifing")
            };

            Ok(cx.boolean(ver_result).upcast())
        }

        method get_prefix(mut cx) {
            let this = cx.this();
            let prefix = {
                this.borrow(&cx.lock()).get_prefix()
            };
            Ok(cx.string(prefix).upcast())
        }

        }

}

register_module!(mut m, {
    m.export_class::<JsController>("Controller")?;
    Ok(())
});
