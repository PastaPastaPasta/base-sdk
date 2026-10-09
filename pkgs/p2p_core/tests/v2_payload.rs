//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! A V2 payload kept apart from its type decodes under V2 rules, not V1's.

#![cfg(feature = "serde")]
#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::Corpus;
use dash_p2p_core::limits::MAX_V2_CONTENTS_LEN;
use dash_p2p_core::{decode_v2_payload, split_v2, CommandString, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct V2Vector {
  form: String,
  payload_len: usize,
  core: String,
}

fn ctx() -> ProtoCtx {
  ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC)
}

/// A long-form type with 0x7f is valid in V2: Core processes it as an unknown
/// command, where V1 drops it.
#[rstest]
fn a_long_form_type_with_0x7f_is_unknown() {
  let mut contents = vec![0u8];
  contents.extend_from_slice(b"bs7\x7f\0\0\0\0\0\0\0\0");
  contents.extend_from_slice(&[1, 2, 3]);
  let m = split_v2(&contents).unwrap();
  let (cmd, payload) = (m.command(), m.payload().to_vec());
  assert!(decode_v2_payload(&cmd, &payload, &ctx()).unwrap().msg.is_unknown());
  assert_eq!(m.decode(&ctx()), decode_v2_payload(&cmd, &payload, &ctx()));
  assert!(matches!(
    P2pMsg::decode_with_policy(&cmd, &payload, &ctx()),
    Err(P2pDecodeError::InvalidCommand { .. })
  ));
}

/// A short-ID payload may run 12 bytes past the V1 limit.
#[rstest]
fn a_short_id_payload_may_exceed_the_v1_limit() {
  let mut contents = vec![21u8];
  contents.resize(1 + 3 * 1024 * 1024 + 5, 0);
  let m = split_v2(&contents).unwrap();
  let owned = m.payload().to_vec();
  let d = decode_v2_payload(&CommandString::TX, &owned, &ctx()).unwrap();
  assert!(matches!(d.msg, P2pMsg::Tx(_)));
  assert_eq!(Ok(d), m.decode(&ctx()));
  assert!(matches!(
    P2pMsg::decode_with_policy(&CommandString::TX, &owned, &ctx()),
    Err(P2pDecodeError::PayloadTooLarge { .. })
  ));
}

/// A type without a short ID arrives only in the long form, so its payload
/// is bound 12 bytes lower.
#[rstest]
fn a_long_form_payload_leaves_room_for_its_type() {
  let cmd = CommandString::from_bytes(*b"bs7\0\0\0\0\0\0\0\0\0");
  let mut contents = vec![0u8];
  contents.extend_from_slice(cmd.as_bytes());
  contents.resize(MAX_V2_CONTENTS_LEN, 0);
  let m = split_v2(&contents).unwrap();
  assert_eq!(decode_v2_payload(&cmd, m.payload(), &ctx()), m.decode(&ctx()));
  let mut payload = m.payload().to_vec();
  payload.push(0);
  assert_eq!(
    decode_v2_payload(&cmd, &payload, &ctx()),
    Err(P2pDecodeError::ContentsTooLarge {
      size: MAX_V2_CONTENTS_LEN + 1,
      max: MAX_V2_CONTENTS_LEN
    })
  );
}

/// BS4a's Core-judged V2 contents (probe_v2.py, both pins): an owned
/// hand-off of every short-ID ping decodes as `V2Message::decode` does, and
/// the payload Core disconnects on is refused.
#[rstest]
fn owned_payloads_follow_cores_v2_bounds() {
  let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "decode_domain");
  let mut checked = 0;
  for v in corpus
    .vectors::<V2Vector>("v2_contents")
    .iter()
    .filter(|v| v.form == "short")
  {
    let payload = vec![0u8; v.payload_len];
    let r = decode_v2_payload(&CommandString::PING, &payload, &ctx());
    match v.core.as_str() {
      "accept" => assert_eq!(r.unwrap().consumed, 8, "{}", v.payload_len),
      _ => assert!(
        matches!(r, Err(P2pDecodeError::ContentsTooLarge { .. })),
        "{}",
        v.payload_len
      ),
    }
    checked += 1;
  }
  assert_eq!(checked, 4);
}
