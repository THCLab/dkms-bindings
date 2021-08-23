use keri::{
    derivation::self_signing::SelfSigning,
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix},
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

    pub fn rotate(&mut self) -> String {
        self.km.rotate();
        let rot = self.kerl.rotate(&self.km);
        String::from_utf8(rot.unwrap().serialize().unwrap()).unwrap()
    }

    pub fn sign(&self, msg: &Vec<u8>) -> String {
        base64::encode_config(self.km.sign(msg).unwrap(), URL_SAFE)
    }

    pub fn process(&self, kerl: &[u8]) -> () {
        self.kerl.process_stream(kerl).unwrap();
    }

    pub fn verify(&self, message: &[u8], signature: &str, prefix: &str) -> Result<bool, Error> {
        let prefix = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE).unwrap();
        let key_conf = self
            .kerl
            .get_state_for_prefix(&prefix)
            .unwrap()
            .unwrap()
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
        init(mut cx) {
            let root = Builder::new().prefix("test-db").tempdir().unwrap();
            let mut kerl = KERL::new(root.path()).unwrap();
            let km = CryptoBox::new().unwrap();
            kerl.incept(&km).unwrap();
            Ok(Controller {km, kerl})
        }

        method get_kerl(mut cx) {
            let this = cx.this();
            let kerl = {
                String::from_utf8(this.borrow(&cx.lock()).kerl.get_kerl().unwrap().unwrap()).unwrap()
            };
            Ok(cx.string(kerl).upcast())
        }

        method rotate(mut cx) {
            let mut this = cx.this();
            let m = this.borrow_mut(&cx.lock()).rotate();
            Ok(cx.string(m.to_string()).upcast())
        }

        method sign(mut cx) {
            let message: String = cx.argument::<JsString>(0)?.value();
            let this = cx.this();
            let signature = {
                // let guard = cx.lock();
                this.borrow(&cx.lock()).sign(&message.as_bytes().to_vec())
            };
            Ok(cx.string(signature).upcast())
        }

        method process_kerl(mut cx) {
            let kerl: String = cx.argument::<JsString>(0)?.value();
            let this = cx.this();

            this.borrow(&cx.lock()).process(&kerl.as_bytes());

            Ok(cx.string("ok").upcast())
        }

        method verify(mut cx) {
            let message: String = cx.argument::<JsString>(0)?.value();
            let signature: String = cx.argument::<JsString>(1)?.value();
            let identifier: String = cx.argument::<JsString>(2)?.value();
            let this = cx.this();

            let ver_result = {
                this.borrow(&cx.lock()).verify(&message.as_bytes(), &signature, &identifier).unwrap()
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

#[test]
pub fn test() {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let mut kerl = KERL::new(root.path()).unwrap();
    let km = CryptoBox::new().unwrap();
    kerl.incept(&km).unwrap();
    let cont = Controller { km, kerl };
    cont.process(br#"{"v":"KERI10JSON0000ed_","i":"DdqNMJ9KfcCjLR1wl97xsHMRm6S2UBZ11WBgdDuukFZw","s":"0","t":"icp","kt":"1","k":["DdqNMJ9KfcCjLR1wl97xsHMRm6S2UBZ11WBgdDuukFZw"],"n":"El6VP_btGBUNsa9xrslyv8u3c8VBwVoedaIjqtx7A85g","bt":"0","b":[],"c":[],"a":[]}-AABAA_NxZk2X7m_t-UsK2mcfykAl301n6vIykL7g0_3MDlo_DA-c_c7Q4usY7lZEShsbcFEpIL9m8W64gNIaGLw85Aw"#);
}
