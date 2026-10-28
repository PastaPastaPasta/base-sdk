//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod byte_bags;
mod error;
mod ies_bytes;
mod public_hash;
mod scheme_ctx;
mod schemes;
mod share_id;
mod sig_id;

pub use byte_bags::{BlsDhBytes, BlsPkBytes, BlsSigBytes, BlsSkBytes, BLS_DH_LEN, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
pub use error::BlsError;
pub use ies_bytes::{BlsIesBlobBytes, BlsIesMultiBytes, IV_SEED_LEN, MAX_IES_RECIPIENTS};
pub use public_hash::{BlsPkHash, BLS_PK_HASH_LEN};
pub use scheme_ctx::{BlsCtx, BlsSchemeKind, BlsSchemeSource};
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
pub use share_id::{BlsShareId, BLS_ID_LEN};
pub use sig_id::BlsSigId;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    mod curve_consts;
    mod elem;
    mod ies_ops;
    mod macros;
    mod native;
    mod public_ops;
    mod scheme_chia;
    mod scheme_ietf;
    mod secret_ops;
    mod share_ops;
    mod sig_aggregate;
    mod sig_basic;
    mod sig_pop;
    mod sig_threshold;
    mod wrap_codec;
    mod wrap_eager;
    mod wrap_global;
    mod wrap_lazy;
    mod wrap_value;
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
    pub(crate) mod group;
    pub(crate) mod relic;
    pub(crate) mod scalar;
    pub(crate) mod scheme_ops;
    #[cfg(test)]
    pub(crate) mod tests;

    pub mod core;

    pub use ies_ops::{BlsIesBlob, BlsIesMulti};
    pub use public_ops::BlsPublicKey;
    pub use group::{BlsPointRepr, G1Affine, G2Affine, G1, G2};
    pub use scalar::Fr;
    pub use scheme_ops::BlsScheme;
    pub use secret_ops::BlsSecretKey;
    pub use share_ops::{BlsPkShare, BlsSigShare, BlsSkShare};
    pub use sig_basic::BlsSignature;
    pub use wrap_codec::{BlsPoint, BlsWire, BlsWirePoint};
    pub use wrap_eager::{BlsDecodeError, BlsEager, BlsEagerPk, BlsEagerSig, BlsEagerSk};
    pub use wrap_global::{BlsGlobal, BlsGlobalPk, BlsGlobalSig};
    pub use wrap_lazy::{BlsLazy, BlsLazyPk, BlsLazySig};
    pub use wrap_value::BlsValue;
  }
}
