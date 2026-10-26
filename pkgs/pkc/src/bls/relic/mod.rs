//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! A transliteration of the relic code Core's dashbls runs at the v24 pin
//! (dashbls `depends/relic`, configured as Core builds it), for the
//! elements blst cannot represent: points off the curve or outside the
//! subgroup, and results that keep relic's coordinates (design §3.2).
//!
//! Only the functions `BlsElem` reaches are ported, each citing its relic
//! source. Group values never come here; blst computes them.

pub(crate) mod ep;
pub(crate) mod ep2;
mod field;
pub(crate) mod pp;
mod recode;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
pub(crate) use recode::Bn;

/// relic's `coord` tag, of which Core's configuration reaches two values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum Coord {
  /// `BASIC`: affine, z read as 1 where relic assumes it.
  Basic,
  /// `PROJC`: homogeneous projective in G1, Jacobian in G2.
  Projc,
}
