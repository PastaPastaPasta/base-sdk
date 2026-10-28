//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special transaction payload decoders.
//!
//! Each payload type is decoded from the `extra_payload` field of a
//! `Transaction` whose `tx_type` is not `Spend`. A BLS field takes its scheme
//! from the payload's version or is always basic, and encodes under the
//! scheme its payload gives when encoded. A field under Core's process-wide
//! flag keeps its wire bytes ([`BlsGlobal`](dash_pkc::bls::BlsGlobal)), so
//! no payload needs the flag to decode.

mod assetlock;
mod assetunlock;
pub(crate) mod bls;
mod cbtx;
mod mnhftx;
mod quorum;
pub(crate) mod sighash;

pub use self::assetlock::{AssetLock, AssetLockInvalid};
pub use self::assetunlock::{AssetUnlock, AssetUnlockInvalid};
pub use self::bls::{commitment_bls_scheme, protx_bls_scheme};
pub use self::cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use self::mnhftx::{MnHardFork, MnHardForkInvalid, VERSIONBITS_NUM_BITS};
pub use self::quorum::{Commitment, CommitmentInvalid, FinalCommitment, QuorumVvecHash};
pub use self::sighash::llmq_sign_hash;
