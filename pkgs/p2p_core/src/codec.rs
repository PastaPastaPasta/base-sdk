//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for P2P message types.

/// Largest P2P message payload, in bytes.
pub const MAX_P2P_PAYLOAD_SIZE: usize = 3_145_728;

/// Generates `Encode` + `Decode` with P2P payload size limit.
macro_rules! impl_p2p {
  ($ty:ty) => {
    $crate::__private::dash_types::impl_type!($ty, crate::codec::MAX_P2P_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_p2p;

/// Declares a flat struct with `new` and generates `BaseCodec`, `Encode`,
/// `Decode` and `Hashable` over its fields, under the P2P payload size limit.
macro_rules! codec_p2p {
  (
    $(#[$attr:meta])*
    $vis:vis struct $name:ident {
      $($(#[$fattr:meta])* $fvis:vis $field:ident: $fty:ty),+ $(,)?
    }
  ) => {
    $crate::__private::dash_types::impl_new! {
      $(#[$attr])*
      $vis struct $name {
        $($(#[$fattr])* $fvis $field: $fty),+
      }
    }

    $crate::__private::dash_primitives::codec_type!($name, crate::codec::MAX_P2P_PAYLOAD_SIZE, { $($field),+ });
  };
}
pub(crate) use codec_p2p;
