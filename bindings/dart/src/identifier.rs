// use keri::{prefix::{IdentifierPrefix, BasicPrefix, SelfAddressingPrefix, SelfSigningPrefix}, derivation::{self_signing::SelfSigning, basic::Basic}};

// use crate::api::{Identifier, PublicKey, Signature, Digest};

// impl From<IdentifierPrefix> for Identifier {
//     fn from(id: IdentifierPrefix) -> Self {
//         match id {
//             IdentifierPrefix::Basic(bp) => Identifier::Basic(bp.into()),
//             IdentifierPrefix::SelfAddressing(sa) => Identifier::SelfAddressing(sa.into()),
//             IdentifierPrefix::SelfSigning(ss) => Identifier::SelfSigning(ss.into()),
//         }
//     }
// }

// impl Into<IdentifierPrefix> for Identifier {
//     fn into(self) -> IdentifierPrefix {
//         match self {
//             Identifier::Basic(bp) => IdentifierPrefix::Basic((&bp).into()),
//             Identifier::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(sa.into()),
//             Identifier::SelfSigning(ss) => IdentifierPrefix::SelfSigning(ss.into()),
//         }
//     }
// }

// impl Default for Signature {
//     fn default() -> Self {
//         Signature::new_from_b64(SelfSigning::Ed25519Sha512 , "".to_string())
//     }
// }

// impl From<Digest> for SelfAddressingPrefix {
//     fn from(bp: Digest) -> Self {
//         Self {
//         derivation: (*bp.derivation).into(),
//             digest: bp.digest,
//         }
//     }
// }

// // impl Into<SelfAddressingPrefix> for &Digest {
// //     fn into(self) -> SelfAddressingPrefix {
// // 		let der: SelfAddressing = (*self.derivation).into();
// //         der.derive(&self.digest)
// //     }
// // }
// impl From<SelfAddressingPrefix> for Digest {
//     fn from(sai: SelfAddressingPrefix) -> Self {
//         Digest { derivation: sai.derivation.into(), digest: sai.digest}
//     }
// }

// impl From<Box<Signature>> for SelfSigningPrefix {
//     fn from(bp: Box<Signature>) -> Self {
//         let der: SelfSigning = (*bp.derivation).into();
// 		der.derive(bp.signature)
//     }
// }

// impl From<SelfSigningPrefix> for Signature {
//     fn from(bp: SelfSigningPrefix) -> Self {
//         Signature { derivation: bp.derivation.into(), signature: bp.signature }
//     }
// }

// impl Into<SelfSigningPrefix> for &Signature {
//     fn into(self) -> SelfSigningPrefix {
// 		let der: SelfSigning = (*self.derivation).into();
//         der.derive(self.signature.clone())
//     }
// }

// impl Into<SelfSigningPrefix> for Signature {
//     fn into(self) -> SelfSigningPrefix {
// 		let der: SelfSigning = (*self.derivation).into();
//         der.derive(self.signature)
//     }
// }
