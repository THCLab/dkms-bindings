use keri::{
    derivation::self_signing::SelfSigning,
    prefix::{AttachedSignaturePrefix, Prefix},
    signer::{CryptoBox, KeyManager},
};
use neon::prelude::*;
use tempfile::Builder;
pub mod kel;
use base64::{self, URL_SAFE};
use kel::{error::Error, KEL};

pub struct Controller {
    km: CryptoBox,
    kel: KEL,
}

impl Controller {
    pub fn get_prefix(&self) -> String {
        self.kel.get_prefix().to_str()
    }

    /// Returns own key event log of controller.
    pub fn get_kel(&self) -> Result<String, Error> {
        Ok(String::from_utf8(
            self.kel
                .get_kel()?
                .ok_or(Error::Generic("There is no kel".into()))?,
        )?)
    }

    /// Returns key event log of controller of given prefix.
    /// (Only if controller "knows" the identity of given prefix. It can be out of
    /// date kel if controller didn't get most recent events yet.)
    pub fn get_kel_for_prefix(&self, prefix: &str) -> Result<String, Error> {
        let prefix = prefix.parse()?;
        Ok(String::from_utf8(
            self.kel
                .get_kel_for_prefix(&prefix)?
                .ok_or(Error::Generic("There is no kel".into()))?,
        )?)
    }

    pub fn rotate(&mut self) -> Result<String, Error> {
        self.km.rotate()?;
        let rot = self.kel.rotate(&self.km);
        Ok(String::from_utf8(rot?.serialize()?)?)
    }

    /// Sign given message
    ///
    /// Returns signature encoded in base64
    /// # Arguments
    ///
    /// * `message` - Bytes of message that will be signed
    pub fn sign(&self, message: &Vec<u8>) -> Result<String, Error> {
        Ok(base64::encode_config(self.km.sign(message)?, URL_SAFE))
    }

    pub fn current_sn(&self) -> Result<u64, Error> {
        Ok(self.kel.get_state()?.unwrap().sn)
    }

    /// Process incoming events stream
    ///
    /// # Arguments
    ///
    /// * `stream` - Bytes of serialized events stream
    pub fn process(&self, stream: &[u8]) -> Result<(), Error> {
        self.kel.process_stream(stream)
    }

    /// Verify signature of given message
    ///
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signature` - A string slice that holds the signature in base64
    /// * `prefix` - A string slice that holds the prefix of signer
    pub fn verify(&self, message: &[u8], signature: &str, prefix: &str) -> Result<bool, Error> {
        let prefix = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kel
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

    /// Verify signature of given message using keys at `sn`
    ///
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signature` - A string slice that holds the signature in base64
    /// * `prefix` - A string slice that holds the prefix of signer
    /// * `sn` - A sequence number of event which established keys used to sign message.
    pub fn verify_at_sn(&self, message: &[u8], signature: &str, prefix: &str, sn: u64) -> Result<bool, Error> {
        let pref = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kel
            .get_keys_at_sn(&pref, sn)?.ok_or(Error::Generic(format!("There are no key config fo identifier {} at {}", prefix, sn)))?;
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
            let mut kel = KEL::new(root.path()).expect("Error while creating kel");
            let km = CryptoBox::new().expect("Error while generating keys");
            kel.incept(&km).expect("Error while creating inception event");
            Ok(Controller {km, kel})
        }

        method get_kel(mut cx) {
            let this = cx.this();
            let kel = {
                this.borrow(&cx.lock()).get_kel().expect("Can't get kel")
            };
            Ok(cx.string(kel).upcast())
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

        method process_kel(mut cx) {
            let kel: String = cx.argument::<JsString>(0)?.value();
            let this = cx.this();

            this.borrow(&cx.lock()).process(&kel.as_bytes()).expect("Error while processing events");

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

        method verify_at_sn(mut cx) {
            let message: String = cx.argument::<JsString>(0)?.value();
            let signature: String = cx.argument::<JsString>(1)?.value();
            let identifier: String = cx.argument::<JsString>(2)?.value();
            let sn : u64 = cx.argument::<JsNumber>(3)?.value() as u64;
            let this = cx.this();

            let ver_result = {
                this.borrow(&cx.lock()).verify_at_sn(&message.as_bytes(), &signature, &identifier, sn).expect("Error while verifing")
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

         method get_current_sn(mut cx) {
            let this = cx.this();
            let sn = {
                this.borrow(&cx.lock()).current_sn().expect("No current sn")
            };
            Ok(cx.number(sn as f64).upcast())
        }

        }

}

register_module!(mut m, {
    m.export_class::<JsController>("Controller")?;
    Ok(())
});
