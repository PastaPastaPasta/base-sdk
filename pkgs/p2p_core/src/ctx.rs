//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The peer and chain state a P2P payload decodes under.

use crate::version::ProtocolVersion;

use dash_pkc::bls::BlsCtx;
use dash_types::type_id::Unencodable;
use getset::CopyGetters;

/// The state Core consults while it reads a message from a peer.
///
/// Some payloads decode differently by the version negotiated with the peer
/// or by the BLS scheme in force when the message is processed.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, Unencodable)]
#[non_exhaustive]
pub struct ProtoCtx {
  /// The negotiated version, Core's `GetCommonVersion()`.
  #[getset(get_copy = "pub")]
  version: ProtocolVersion,
  /// The BLS scheme in force while the message is processed.
  #[getset(get_copy = "pub")]
  bls: BlsCtx,
}

impl ProtoCtx {
  /// Builds a context from the negotiated version and the BLS scheme.
  pub const fn new(version: ProtocolVersion, bls: BlsCtx) -> Self {
    Self { version, bls }
  }
}
