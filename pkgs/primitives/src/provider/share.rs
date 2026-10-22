//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Owner payouts and collateral shares of provider payloads.

use crate::codec_type;
use crate::sptx::ProTxInvalid;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use bitcoin_units::SignedAmount;
use dash_script::{PubKeyHash, Recipient};
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

use core::iter;

/// Fewest shares of a shared collateral.
const MIN_SHARES: usize = 2;

/// Most shares of a shared collateral, and most owner payouts.
pub(super) const MAX_SHARES: usize = 8;

/// Smallest part of the owner reward a payout may take, in basis points.
const MIN_REWARD: u16 = 100;

/// The whole owner reward in basis points.
pub(super) const MAX_REWARD: u16 = 10_000;

/// Smallest collateral share in duffs.
const MIN_SHARE_AMOUNT: i64 = SignedAmount::from_btc_i16(100).to_sat();

/// Longest early dissolution period in blocks.
const MAX_EARLY_PERIOD_BLOCKS: u32 = 420_480;

/// Collateral of a regular masternode in duffs.
pub(super) const REGULAR_COLLATERAL: i64 = SignedAmount::from_btc_i16(1000).to_sat();

/// Collateral of an Evo masternode in duffs.
pub(super) const EVO_COLLATERAL: i64 = SignedAmount::from_btc_i16(4000).to_sat();

codec_type! {
/// An owner payout, a script and its part of the owner reward.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PayoutShare {
  /// Payout script.
  #[getset(get = "pub")]
  script_payout: ScriptPubKeyBuf,
  /// Part of the owner reward in basis points.
  #[getset(get_copy = "pub")]
  reward: u16,
}
}

codec_type! {
/// One participant's part of a shared collateral.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CollateralShare {
  /// Amount in duffs.
  #[getset(get_copy = "pub")]
  amount: i64,
  /// Script the amount is refunded to.
  #[getset(get = "pub")]
  script_refund: ScriptPubKeyBuf,
  /// Script rewards are paid to, the refund script when empty.
  #[getset(get = "pub")]
  script_reward: ScriptPubKeyBuf,
  /// Owner key id of the participant (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_owner: PubKeyHash,
}
}

/// Reads a payout script, which must pay to a key hash or a script hash.
fn payee(script: &ScriptPubKeyBuf) -> Option<Recipient> {
  Recipient::from_script(script.as_bytes())
    .filter(|recipient| matches!(recipient, Recipient::PubKeyHash(_) | Recipient::ScriptHash(_)))
}

/// Checks owner payouts that must not pay the owner or voting key.
pub(super) fn check_payouts(
  payouts: &[PayoutShare],
  key_id_owner: Option<&PubKeyHash>,
  key_id_voting: &PubKeyHash,
) -> Option<ProTxInvalid> {
  if payouts.is_empty() || payouts.len() > MAX_SHARES {
    return Some(ProTxInvalid::BadPayoutCount { count: payouts.len() });
  }

  let mut total = 0u32;
  for (i, payout) in payouts.iter().enumerate() {
    if !(MIN_REWARD..=MAX_REWARD).contains(&payout.reward) {
      return Some(ProTxInvalid::BadPayoutReward { reward: payout.reward });
    }
    total += u32::from(payout.reward);

    let Some(recipient) = payee(&payout.script_payout) else {
      return Some(ProTxInvalid::BadPayoutScript);
    };
    if payouts[..i].iter().any(|p| p.script_payout == payout.script_payout) {
      return Some(ProTxInvalid::DuplicatePayout);
    }
    if let Recipient::PubKeyHash(hash) = recipient {
      if key_id_owner == Some(&hash) || hash == *key_id_voting {
        return Some(ProTxInvalid::PayoutKeyReuse);
      }
    }
  }

  if total != u32::from(MAX_REWARD) {
    return Some(ProTxInvalid::BadPayoutRewardSum { total });
  }
  None
}

/// Checks the shares of a `collateral` and the early dissolution terms. No
/// share may pay the voting key or any share's owner key.
pub(super) fn check_shares(
  shares: &[CollateralShare],
  collateral: i64,
  early_period_blocks: u32,
  early_penalty: i64,
  key_id_voting: &PubKeyHash,
) -> Option<ProTxInvalid> {
  if !(MIN_SHARES..=MAX_SHARES).contains(&shares.len()) {
    return Some(ProTxInvalid::BadShareCount { count: shares.len() });
  }
  if early_period_blocks > MAX_EARLY_PERIOD_BLOCKS {
    return Some(ProTxInvalid::BadEarlyPeriod {
      blocks: early_period_blocks,
    });
  }

  let mut total = 0i64;
  let mut min_amount = i64::MAX;
  for (i, share) in shares.iter().enumerate() {
    // Each amount is at most the collateral, so the total cannot overflow.
    if !(MIN_SHARE_AMOUNT..=collateral).contains(&share.amount) {
      return Some(ProTxInvalid::BadShareAmount { amount: share.amount });
    }
    total += share.amount;
    min_amount = min_amount.min(share.amount);

    if share.key_id_owner.is_null() {
      return Some(ProTxInvalid::NullShareKey);
    }
    let earlier = &shares[..i];
    if earlier.iter().any(|s| s.key_id_owner == share.key_id_owner) {
      return Some(ProTxInvalid::DuplicateShareKey);
    }
    if earlier.iter().any(|s| s.script_refund == share.script_refund) {
      return Some(ProTxInvalid::DuplicateShareRefund);
    }

    // An empty reward script leaves rewards to the refund script.
    let reward = Some(&share.script_reward).filter(|script| !script.is_empty());
    for script in iter::once(&share.script_refund).chain(reward) {
      let Some(recipient) = payee(script) else {
        return Some(ProTxInvalid::BadShareScript);
      };
      if let Recipient::PubKeyHash(hash) = recipient {
        if hash == *key_id_voting || shares.iter().any(|s| s.key_id_owner == hash) {
          return Some(ProTxInvalid::ShareKeyReuse);
        }
      }
    }
  }

  if total != collateral {
    return Some(ProTxInvalid::BadShareAmountSum { total });
  }
  if !(0..min_amount).contains(&early_penalty) || (early_period_blocks == 0 && early_penalty != 0) {
    return Some(ProTxInvalid::BadEarlyPenalty { penalty: early_penalty });
  }
  None
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_script::ScriptHash;
  use rstest::rstest;

  const OWNER: u8 = 0x11;
  const VOTING: u8 = 0x22;
  const DASH: i64 = SignedAmount::ONE_BTC.to_sat();

  fn key(id: u8) -> PubKeyHash {
    PubKeyHash::from([id; 20])
  }

  pub(crate) fn script(recipient: Recipient) -> ScriptPubKeyBuf {
    let mut buf = Vec::new();
    recipient.to_script(&mut buf);
    ScriptPubKeyBuf::from_bytes(buf)
  }

  fn p2pkh(id: u8) -> ScriptPubKeyBuf {
    script(Recipient::PubKeyHash(key(id)))
  }

  fn p2sh(id: u8) -> ScriptPubKeyBuf {
    script(Recipient::ScriptHash(ScriptHash::from([id; 20])))
  }

  fn op_true() -> ScriptPubKeyBuf {
    ScriptPubKeyBuf::from_bytes(vec![0x51])
  }

  fn payouts(list: &[(ScriptPubKeyBuf, u16)]) -> Vec<PayoutShare> {
    list
      .iter()
      .map(|(script, reward)| PayoutShare::new(script.clone(), *reward))
      .collect()
  }

  /// `count` payouts to distinct key hashes, each of `reward`.
  fn spread(count: u8, reward: u16) -> Vec<PayoutShare> {
    (1..=count).map(|id| PayoutShare::new(p2pkh(id), reward)).collect()
  }

  #[rstest]
  #[case::whole_reward(payouts(&[(p2pkh(1), 10_000)]), None)]
  #[case::none(vec![], Some(ProTxInvalid::BadPayoutCount { count: 0 }))]
  #[case::nine(spread(9, 1_000), Some(ProTxInvalid::BadPayoutCount { count: 9 }))]
  #[case::eight(spread(8, 1_250), None)]
  #[case::below_smallest_reward(
    payouts(&[(p2pkh(1), 99), (p2pkh(2), 9_901)]),
    Some(ProTxInvalid::BadPayoutReward { reward: 99 })
  )]
  #[case::above_whole_reward(payouts(&[(p2pkh(1), 10_001)]), Some(ProTxInvalid::BadPayoutReward { reward: 10_001 }))]
  #[case::smallest_reward(payouts(&[(p2pkh(1), 100), (p2pkh(2), 9_900)]), None)]
  #[case::sum_below(
    payouts(&[(p2pkh(1), 5_000), (p2pkh(2), 4_999)]),
    Some(ProTxInvalid::BadPayoutRewardSum { total: 9_999 })
  )]
  #[case::sum_above(
    payouts(&[(p2pkh(1), 5_000), (p2pkh(2), 5_001)]),
    Some(ProTxInvalid::BadPayoutRewardSum { total: 10_001 })
  )]
  #[case::p2sh(payouts(&[(p2sh(1), 10_000)]), None)]
  #[case::other_script(payouts(&[(op_true(), 10_000)]), Some(ProTxInvalid::BadPayoutScript))]
  #[case::same_script(payouts(&[(p2pkh(1), 5_000), (p2pkh(1), 5_000)]), Some(ProTxInvalid::DuplicatePayout))]
  #[case::owner_key(payouts(&[(p2pkh(OWNER), 10_000)]), Some(ProTxInvalid::PayoutKeyReuse))]
  #[case::voting_key(payouts(&[(p2pkh(VOTING), 10_000)]), Some(ProTxInvalid::PayoutKeyReuse))]
  #[case::p2sh_of_key_ids(payouts(&[(p2sh(OWNER), 5_000), (p2sh(VOTING), 5_000)]), None)]
  fn check_payouts_follows_the_reference(#[case] payouts: Vec<PayoutShare>, #[case] expected: Option<ProTxInvalid>) {
    assert_eq!(check_payouts(&payouts, Some(&key(OWNER)), &key(VOTING)), expected);
  }

  /// Without an owner key, as in ProUpRegTx, a payout to any key hash but the
  /// voting key passes.
  #[rstest]
  #[case::null_key(0, None)]
  #[case::voting_key(VOTING, Some(ProTxInvalid::PayoutKeyReuse))]
  fn check_payouts_without_owner_key(#[case] id: u8, #[case] expected: Option<ProTxInvalid>) {
    let payouts = payouts(&[(p2pkh(id), 10_000)]);
    assert_eq!(check_payouts(&payouts, None, &key(VOTING)), expected);
  }

  /// Shares of a collateral and the early dissolution terms.
  struct Terms {
    shares: Vec<CollateralShare>,
    collateral: i64,
    period: u32,
    penalty: i64,
  }

  fn share(dash: i64, refund: ScriptPubKeyBuf, owner: u8) -> CollateralShare {
    CollateralShare::new(dash * DASH, refund, ScriptPubKeyBuf::new(), key(owner))
  }

  /// Two shares of 600 and 400 DASH of a regular collateral, with early
  /// dissolution terms.
  fn two_shares() -> Terms {
    Terms {
      shares: vec![share(600, p2pkh(0x40), 0x50), share(400, p2pkh(0x41), 0x51)],
      collateral: REGULAR_COLLATERAL,
      period: 1_000,
      penalty: 50 * DASH,
    }
  }

  #[rstest]
  #[case::two_shares(|_: &mut Terms| {}, None)]
  #[case::single(
    |t: &mut Terms| t.shares = vec![share(1_000, p2pkh(0x40), 0x50)],
    Some(ProTxInvalid::BadShareCount { count: 1 })
  )]
  #[case::nine(
    |t: &mut Terms| t.shares = (0..9).map(|i| share(111, p2pkh(0x40 + i), 0x50 + i)).collect(),
    Some(ProTxInvalid::BadShareCount { count: 9 })
  )]
  #[case::eight(|t: &mut Terms| t.shares = (0..8).map(|i| share(125, p2pkh(0x40 + i), 0x50 + i)).collect(), None)]
  #[case::longest_period(|t: &mut Terms| t.period = 420_480, None)]
  #[case::period_too_long(|t: &mut Terms| t.period = 420_481, Some(ProTxInvalid::BadEarlyPeriod { blocks: 420_481 }))]
  #[case::below_100_dash(
    |t: &mut Terms| t.shares[1].amount = 100 * DASH - 1,
    Some(ProTxInvalid::BadShareAmount { amount: 100 * DASH - 1 })
  )]
  #[case::exactly_100_dash(
    |t: &mut Terms| t.shares = vec![share(900, p2pkh(0x40), 0x50), share(100, p2pkh(0x41), 0x51)],
    None
  )]
  #[case::above_collateral(
    |t: &mut Terms| t.shares[0].amount = REGULAR_COLLATERAL + 1,
    Some(ProTxInvalid::BadShareAmount { amount: REGULAR_COLLATERAL + 1 })
  )]
  #[case::whole_collateral(
    |t: &mut Terms| t.shares[0].amount = REGULAR_COLLATERAL,
    Some(ProTxInvalid::BadShareAmountSum { total: 1_400 * DASH })
  )]
  #[case::null_owner_key(|t: &mut Terms| t.shares[1].key_id_owner = key(0), Some(ProTxInvalid::NullShareKey))]
  #[case::same_owner_key(|t: &mut Terms| t.shares[1].key_id_owner = key(0x50), Some(ProTxInvalid::DuplicateShareKey))]
  #[case::same_refund(
    |t: &mut Terms| t.shares[1].script_refund = p2pkh(0x40),
    Some(ProTxInvalid::DuplicateShareRefund)
  )]
  #[case::refund_other_script(
    |t: &mut Terms| t.shares[0].script_refund = op_true(),
    Some(ProTxInvalid::BadShareScript)
  )]
  #[case::reward_other_script(
    |t: &mut Terms| t.shares[0].script_reward = op_true(),
    Some(ProTxInvalid::BadShareScript)
  )]
  #[case::p2sh_scripts(
    |t: &mut Terms| {
      t.shares[0].script_refund = p2sh(0x40);
      t.shares[0].script_reward = p2sh(0x42);
    },
    None
  )]
  #[case::same_reward(
    |t: &mut Terms| {
      t.shares[0].script_reward = p2pkh(0x42);
      t.shares[1].script_reward = p2pkh(0x42);
    },
    None
  )]
  #[case::reward_other_owner(
    |t: &mut Terms| t.shares[0].script_reward = p2pkh(0x51),
    Some(ProTxInvalid::ShareKeyReuse)
  )]
  #[case::reward_own_owner(|t: &mut Terms| t.shares[0].script_reward = p2pkh(0x50), Some(ProTxInvalid::ShareKeyReuse))]
  #[case::reward_voting_key(
    |t: &mut Terms| t.shares[0].script_reward = p2pkh(VOTING),
    Some(ProTxInvalid::ShareKeyReuse)
  )]
  #[case::refund_other_owner(
    |t: &mut Terms| t.shares[0].script_refund = p2pkh(0x51),
    Some(ProTxInvalid::ShareKeyReuse)
  )]
  #[case::refund_voting_key(
    |t: &mut Terms| t.shares[0].script_refund = p2pkh(VOTING),
    Some(ProTxInvalid::ShareKeyReuse)
  )]
  #[case::p2sh_of_key_ids(
    |t: &mut Terms| {
      t.shares[0].script_refund = p2sh(0x51);
      t.shares[0].script_reward = p2sh(VOTING);
    },
    None
  )]
  #[case::sum_below(
    |t: &mut Terms| t.shares[1].amount -= 1,
    Some(ProTxInvalid::BadShareAmountSum { total: REGULAR_COLLATERAL - 1 })
  )]
  #[case::negative_penalty(|t: &mut Terms| t.penalty = -1, Some(ProTxInvalid::BadEarlyPenalty { penalty: -1 }))]
  #[case::penalty_of_smallest_share(
    |t: &mut Terms| t.penalty = 400 * DASH,
    Some(ProTxInvalid::BadEarlyPenalty { penalty: 400 * DASH })
  )]
  #[case::penalty_below_smallest_share(|t: &mut Terms| t.penalty = 400 * DASH - 1, None)]
  #[case::penalty_without_period(
    |t: &mut Terms| t.period = 0,
    Some(ProTxInvalid::BadEarlyPenalty { penalty: 50 * DASH })
  )]
  #[case::no_early_terms(
    |t: &mut Terms| {
      t.period = 0;
      t.penalty = 0;
    },
    None
  )]
  #[case::evo(
    |t: &mut Terms| {
      t.collateral = EVO_COLLATERAL;
      t.shares = vec![share(2_400, p2pkh(0x40), 0x50), share(1_600, p2pkh(0x41), 0x51)];
    },
    None
  )]
  #[case::evo_of_regular_sum(
    |t: &mut Terms| t.collateral = EVO_COLLATERAL,
    Some(ProTxInvalid::BadShareAmountSum { total: REGULAR_COLLATERAL })
  )]
  fn check_shares_follows_the_reference(#[case] edit: fn(&mut Terms), #[case] expected: Option<ProTxInvalid>) {
    let mut t = two_shares();
    edit(&mut t);
    assert_eq!(
      check_shares(&t.shares, t.collateral, t.period, t.penalty, &key(VOTING)),
      expected
    );
  }
}
