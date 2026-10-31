//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProDisTx shared masternode dissolution payload (type 10).

use super::share::MAX_SHARES;
use super::DissolveSig;
use crate::codec::{decode_list, encode_list, impl_payload};
use crate::prelude::*;
use crate::sptx::ProTxInvalid;
use crate::{hash_impl, TxHash};

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, Checkable};
use getset::{CopyGetters, Getters};

use core::fmt;

impl_new! {
/// ProDisTx: dissolve a shared masternode (type 10).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProDisTx {
  /// Payload version, read at any value.
  #[getset(get_copy = "pub")]
  version: u16,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Index of the acting share.
  #[getset(get_copy = "pub")]
  actor_index: u16,
  /// One signature by the acting share's owner, or one per share in share
  /// order.
  #[getset(get = "pub")]
  sigs: Vec<DissolveSig>,
}
}

impl_payload!(ProDisTx);

impl BaseCodec for ProDisTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      actor_index: u16::decode(data)?,
      sigs: decode_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.actor_index.encode(buf);
    encode_list(&self.sigs, buf);
  }
}

impl Checkable for ProDisTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version != Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadDissolveVersion { version: self.version });
    }
    if self.sigs.is_empty() || self.sigs.len() > MAX_SHARES {
      return Some(ProTxInvalid::BadDissolveSigCount { count: self.sigs.len() });
    }
    None
  }
}

hash_impl!(ProDisTx);

impl ProDisTx {
  /// The payload version `check` accepts.
  const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for ProDisTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProDisTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_json_rt, check_sptx_raw, vec_from_hex};
  use rstest::rstest;

  /// Regtest transactions as txid and raw bytes, from functional tests of the
  /// reference implementation at v24.0.0-rc.4.
  /// `dash-cli -regtest decoderawtransaction <raw>` decodes each one.
  const REGTEST: [(&str, &str); 4] = [
    // feature_masternode_shares.py line 1072
    ("dd6370e67f7f35225d921c35b6adfccc5debd58a6954a55f275d16c65c4e9c14", "03000a00019c5ba0130c6200a5c7c357ebf13f7c008f75e718fdfd3a7a0a51f47347cc0bbe0100000000ffffffff02004a4d220f0000001976a914add27799695434616eb5e3082da1369de92a0c7588ac60172826080000001976a9144ff00c1437dfe8d85b6f90a67abe3fbf1de8742588ac000000006601009c5ba0130c6200a5c7c357ebf13f7c008f75e718fdfd3a7a0a51f47347cc0bbe0100011fd26ab9307834c21d66da1219a59732d674c41c51253e3ffd3b43456c2a500d410001044be39e9ccc9a80f85430b913acba980e26194c481df88fc5e1a00a0810"),
    // feature_masternode_shares.py line 1168
    ("7d45a115f98d71f24b39cc02614a2e292729693b0ffbe238aedae8a6a4aecb1e", "03000a0001d37d74e7c2b2ce65b308de2d9863d9a6e6177b3944fc5a284c81977381d3e28c0100000000ffffffff0200743ba40b0000001976a914d9a234523db23a2b0a40cebd83bbdc361fcc696988ac60ed39a40b0000001976a914c032f79c2de30457684745b0ce1d83c71ab97de388ac00000000a70100d37d74e7c2b2ce65b308de2d9863d9a6e6177b3944fc5a284c81977381d3e28c00000220105609b7b82755380ef83033007f5eaa539df21f56934d80ac99d2491f04d6fd48d22a931b50ae1d1639a10fa5a71b34fd82425739caf4eae85bcf057eb01d9b20a253ee269664ccb3255194ac377eaff1f3c341e27be66dc490cc7d13f614d0f3733452504fb4dc72f53919dd76ebe4096821958e5c976276e6d16e5b00920498"),
    // feature_masternode_shares.py line 601
    ("0dd2aacf250c57a5be60a2e75f1d696ac711cd8d63e37546a45908acb006aa95", "03000a0001d4e1cad32528a9a72f491e7a757b8c5104d1b9fe1a6565880d7a6204533e81bf0800000000ffffffff0800e40b54020000001976a9146e6c55150a2a7a03298b0f15cee13bf62067c4fe88ac00e40b54020000001976a914836fc8a301096552ec69a94e2b76e39f75d48deb88ac00e40b54020000001976a914ea1f0a66a9ca78aee3fd9eb6721ba60fee114ba688ac00e40b54020000001976a91440f1b5b19fbb0966c86d923344af3046457a6ca188ac00e40b54020000001976a91438ae4e6283fd8a4e7066d43bb21dc782889d9c9988ac00e40b54020000001976a9145e040300c831d56611a3c10ab6a66d49862326b188ac00e40b54020000001976a9149d3a6b20a07d182519e2c55e445d040c56b1a08d88ac602522fc0600000017a914d015a362e5cf69693545428baa6d7e78d423afcd8700000000fd2d020100d4e1cad32528a9a72f491e7a757b8c5104d1b9fe1a6565880d7a6204533e81bf0700081f193392934363415f463f09bff72f1fc6b1fbb37ff7fb6e5010641bf60561bd90528ca684f6138a5ae40dd21b70a281e1104ed283ceb0bd740b82b8eb96ad79e21f3e90fc61bace822b6b40fd2bbb3a70b495fe0497997461cf64ec27adc64e644b1c5524605f4e232efe5fa0e86b0e991cb61a8622bda33ab9b213e284ca9035f11fc34d3f2ecbc129eb289aa8cab306ef5e6cc142ab9915cf733ea7369e046636f124744cc85675ccbb4cd7680914cc8fa02b30a0bf5eea8243b04cbfab5628fcc61f477674d3fff62f346e88a4e433af51859edecaf6045833cac047e8e660202ac00880185156400bb6e3f1c8c27b444d85e4e10d124aca8b46afd6b5d67b1e327520fd3b7233eea5d60ccb20dabcbf7641c106d0fbe41640151eaef9d18364023c116c198e2ed98166ee3f2c824363bcf26eb43516d0d6e5d76f3c0daa56518b44021fe2d76e5c9289961276d224802d8fce34d652c33a6e7b58483f71563fbb0d4f845589648baf7a594cd6924f650c255f0de741b307feb42553043caa9a8fc0a4101f6743bde2e1b9e3f791b21ba78b62cb27f61477500c335221e77b89258e93c78a6f87b1544a733129570b397b8697eaae33529c8a88710695ace141f74622a3aa2062e71317344e1f0c6e88119fc813a388fdccd25936f22c57e86a9cab08ea23a85ae47ffd74d52af64471785d3ddef2989a661a1a74af42392faf6c85db69d0d2"),
    // feature_masternode_shares.py line 1400
    ("3fabf05b318d7c4e157899c40f682f9ac23521c6500a7826af5faf37ff0483fd", "03000a0001e70ae76b24fafead188cec43dea4722c62a06653364c9bf33e5fc024fa3bf77c0100000000ffffffff0200b864d9450000001976a914e4bfda1f1ea786645110e10bea91fde266e84ee388ac60617548170000001976a9143bed3c650fcba45a7a9eeab4873eebca7646e14888ac00000000a70100e70ae76b24fafead188cec43dea4722c62a06653364c9bf33e5fc024fa3bf77c0100022026ec2cd04905d716679de33eff8d06f2400e519d6bbbc88e578dc7fff372480c723f2c1646b300f7167dca2e94a6f6f51a652a76c9b1f82549b7bd27931d22db203f04364bcd134ec13e10e536f63d967a5d1da86fd05f978ef9467e7884e761cb658895fc8b710bcebcfbad072c44f3d028039cb3c85645610b5f6fcfa3dfaae2"),
  ];

  /// The payload of regtest transaction `txid`.
  fn regtest(txid: &str) -> ProDisTx {
    let (txid, raw) = REGTEST.into_iter().find(|(t, _)| *t == txid).unwrap();
    check_sptx_raw(&vec_from_hex(raw), txid)
  }

  #[rstest]
  #[case::masternode_shares_1072(REGTEST[0])]
  #[case::masternode_shares_1168(REGTEST[1])]
  #[case::masternode_shares_601(REGTEST[2])]
  #[case::masternode_shares_1400(REGTEST[3])]
  fn regtest_vectors(#[case] vector: (&str, &str)) {
    let (txid, raw) = vector;
    let raw = vec_from_hex(raw);
    assert_json_rt(&check_sptx_raw::<ProDisTx>(&raw, txid));
    assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{txid}");
  }

  #[rstest]
  #[case::wide_actor_index(|ptx: &mut ProDisTx| ptx.actor_index = 256, None)]
  #[case::no_sigs(|ptx: &mut ProDisTx| ptx.sigs.clear(), Some(ProTxInvalid::BadDissolveSigCount { count: 0 }))]
  #[case::nine_sigs(
    |ptx: &mut ProDisTx| ptx.sigs.push(ptx.sigs[0]),
    Some(ProTxInvalid::BadDissolveSigCount { count: 9 })
  )]
  #[case::version_0(|ptx: &mut ProDisTx| ptx.version = 0, Some(ProTxInvalid::BadDissolveVersion { version: 0 }))]
  #[case::version_2(|ptx: &mut ProDisTx| ptx.version = 2, Some(ProTxInvalid::BadDissolveVersion { version: 2 }))]
  #[case::version_before_sig_count(
    |ptx: &mut ProDisTx| {
      ptx.version = 2;
      ptx.sigs.clear();
    },
    Some(ProTxInvalid::BadDissolveVersion { version: 2 })
  )]
  fn check(#[case] edit: fn(&mut ProDisTx), #[case] expected: Option<ProTxInvalid>) {
    let mut ptx = regtest("0dd2aacf250c57a5be60a2e75f1d696ac711cd8d63e37546a45908acb006aa95");
    assert_eq!(ptx.sigs.len(), MAX_SHARES);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
