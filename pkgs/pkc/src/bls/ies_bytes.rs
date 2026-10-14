//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Byte bags for BLS-IES encrypted blobs.

#[cfg(feature = "codec")]
use crate::bls::BlsError;
use crate::bls::BlsPkBytes;
use crate::prelude::*;

#[cfg(feature = "codec")]
use bitcoin_hashes::sha256d::Hash as Sha256d;
use cfg_if::cfg_if;
#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::{read_bytes, BaseCodec, DecodeError, EncodeBuf};
#[cfg(feature = "codec")]
use dash_types::type_id::TypeId;
#[cfg(feature = "codec")]
use dash_types::{impl_type, CompactSize, Numeric};
#[cfg(feature = "codec")]
use dash_types::{Checkable, Hashable};
use hex_conservative::DisplayHex;

use core::fmt;

/// Byte length of the seed a BLS-IES message derives its IVs from.
pub const IV_SEED_LEN: usize = 32;

/// Largest recipient count (and index), an IV is derived for.
pub const MAX_IES_RECIPIENTS: usize = 2048;

/// A BLS-IES encrypted blob under an ephemeral key.
#[derive(Clone, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsIesBlobBytes {
  ephemeral_pk: BlsPkBytes,
  iv_seed: [u8; IV_SEED_LEN],
  data: Vec<u8>,
}

#[cfg(feature = "codec")]
impl BaseCodec for BlsIesBlobBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let ephemeral_pk = BlsPkBytes::decode(data)?;
    let iv_seed = <[u8; IV_SEED_LEN]>::decode(data)?;
    let len = CompactSize::decode_len(data)?;
    Ok(Self {
      ephemeral_pk,
      iv_seed,
      data: read_bytes(data, len)?.to_vec(),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.ephemeral_pk.encode(buf);
    self.iv_seed.encode(buf);
    CompactSize::from(self.data.len()).encode(buf);
    buf.extend_from_slice(&self.data); // nosemgrep: codec-no-raw-extend
  }
}

#[cfg(feature = "codec")]
impl_type!(BlsIesBlobBytes);

#[cfg(feature = "codec")]
impl Checkable for BlsIesBlobBytes {
  type Error = BlsError;

  fn check(&self) -> Option<BlsError> {
    if self.ephemeral_pk.is_null() {
      return Some(BlsError::InvalidPublicKey);
    }
    if self.data.is_empty() {
      return Some(BlsError::InvalidCiphertextLength);
    }
    if self.iv_seed.iter().all(|&b| b == 0) {
      return Some(BlsError::InvalidIvSeed);
    }
    None
  }
}

#[cfg(feature = "codec")]
impl Hashable for BlsIesBlobBytes {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(Sha256d::hash(&self.to_bytes()).to_byte_array())
  }
}

impl BlsIesBlobBytes {
  /// Constructs from raw components.
  pub fn new(ephemeral_pk: BlsPkBytes, iv_seed: [u8; IV_SEED_LEN], data: Vec<u8>) -> Self {
    Self {
      ephemeral_pk,
      iv_seed,
      data,
    }
  }

  /// Borrows the ciphertext.
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  /// The ephemeral public key the sender encrypted under.
  pub fn ephemeral_pk(&self) -> &BlsPkBytes {
    &self.ephemeral_pk
  }

  /// The seed the recipient's IV is derived from.
  pub fn iv_seed(&self) -> &[u8; IV_SEED_LEN] {
    &self.iv_seed
  }
}

#[cfg(feature = "codec")]
impl BlsIesBlobBytes {
  /// The full wire image.
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    buf
  }
}

impl fmt::Debug for BlsIesBlobBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsIesBlobBytes")
      .field("ephemeral_pk", &self.ephemeral_pk)
      .field("iv_seed", &self.iv_seed.as_hex())
      .field("data_len", &self.data.len())
      .finish()
  }
}

/// One ciphertext per recipient under an ephemeral key.
#[derive(Clone, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsIesMultiBytes {
  ephemeral_pk: BlsPkBytes,
  iv_seed: [u8; IV_SEED_LEN],
  blobs: Vec<Vec<u8>>,
}

#[cfg(feature = "codec")]
impl BaseCodec for BlsIesMultiBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let ephemeral_pk = BlsPkBytes::decode(data)?;
    let iv_seed = <[u8; IV_SEED_LEN]>::decode(data)?;

    // Each element is a `Vec` far wider than the length prefix that admitted it
    // so capacity is grown against content, not reserved.
    let count = CompactSize::decode_len(data)?;
    let mut blobs = Vec::new();
    for _ in 0..count {
      let len = CompactSize::decode_len(data)?;
      blobs.push(read_bytes(data, len)?.to_vec());
    }

    Ok(Self {
      ephemeral_pk,
      iv_seed,
      blobs,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.ephemeral_pk.encode(buf);
    self.iv_seed.encode(buf);
    CompactSize::from(self.blobs.len()).encode(buf);
    for blob in &self.blobs {
      CompactSize::from(blob.len()).encode(buf);
      buf.extend_from_slice(blob); // nosemgrep: codec-no-raw-extend
    }
  }
}

#[cfg(feature = "codec")]
impl_type!(BlsIesMultiBytes);

#[cfg(feature = "codec")]
impl Hashable for BlsIesMultiBytes {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(Sha256d::hash(&self.to_bytes()).to_byte_array())
  }
}

impl BlsIesMultiBytes {
  /// Constructs from raw components.
  pub fn new(ephemeral_pk: BlsPkBytes, iv_seed: [u8; IV_SEED_LEN], blobs: Vec<Vec<u8>>) -> Self {
    Self {
      ephemeral_pk,
      iv_seed,
      blobs,
    }
  }

  /// Borrows the per-recipient ciphertexts.
  pub fn blobs(&self) -> &[Vec<u8>] {
    &self.blobs
  }

  /// The ephemeral public key the sender encrypted under.
  pub fn ephemeral_pk(&self) -> &BlsPkBytes {
    &self.ephemeral_pk
  }

  /// The seed every recipient's IV is derived from.
  pub fn iv_seed(&self) -> &[u8; IV_SEED_LEN] {
    &self.iv_seed
  }
}

#[cfg(feature = "codec")]
impl BlsIesMultiBytes {
  /// The full wire image.
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    buf
  }
}

impl fmt::Debug for BlsIesMultiBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsIesMultiBytes")
      .field("ephemeral_pk", &self.ephemeral_pk)
      .field("iv_seed", &self.iv_seed.as_hex())
      .field("blob_count", &self.blobs.len())
      .finish()
  }
}

cfg_if! {
  if #[cfg(feature = "codec")] {
    cfg_if! {
      if #[cfg(feature = "serde")] {
        use dash_types::serialize::hex as serde_hex;
        use serde::de::Error as DeError;
        use serde::{Deserializer, Serializer};

        /// Decodes a whole hex image, rejecting any unconsumed tail.
        fn from_image<'de, T: BaseCodec, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
          let bytes: Vec<u8> = serde_hex::deserialize(deserializer)?;
          let mut cursor = bytes.as_slice();
          let value = T::decode(&mut cursor).map_err(DeError::custom)?;

          if !cursor.is_empty() {
            return Err(DeError::custom("trailing bytes after encoded value"));
          }

          Ok(value)
        }

        impl ::serde::Serialize for BlsIesBlobBytes {
          fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
            serde_hex::serialize(&self.to_bytes(), serializer)
          }
        }

        impl<'de> ::serde::Deserialize<'de> for BlsIesBlobBytes {
          fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            from_image(deserializer)
          }
        }

        impl ::serde::Serialize for BlsIesMultiBytes {
          fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
            serde_hex::serialize(&self.to_bytes(), serializer)
          }
        }

        impl<'de> ::serde::Deserialize<'de> for BlsIesMultiBytes {
          fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            from_image(deserializer)
          }
        }
      }
    }
  }
}

#[cfg(all(test, feature = "codec"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use rstest::rstest;

  fn blob(data: Vec<u8>) -> BlsIesBlobBytes {
    BlsIesBlobBytes::new(BlsPkBytes::from_bytes([0xab; 48]), [0xcd; IV_SEED_LEN], data)
  }

  fn multi(blobs: Vec<Vec<u8>>) -> BlsIesMultiBytes {
    BlsIesMultiBytes::new(BlsPkBytes::from_bytes([0xab; 48]), [0xcd; IV_SEED_LEN], blobs)
  }

  #[rstest]
  fn layout_matches_reference() {
    let encoded = blob(vec![0x11; 3]).to_bytes();

    assert_eq!(encoded[..48], [0xab; 48]);
    assert_eq!(encoded[48..80], [0xcd; 32]);
    assert_eq!(encoded[80], 3);
    assert_eq!(encoded.len(), 84);

    let encoded = multi(vec![vec![0x11; 2], vec![0x22; 1]]).to_bytes();
    assert_eq!(encoded[80], 2, "blob count precedes the blobs");
    assert_eq!(encoded[81], 2);
    assert_eq!(encoded[84], 1);
    assert_eq!(encoded.len(), 86);
  }

  #[rstest]
  #[case::empty(vec![])]
  #[case::one_block(vec![0x11; 16])]
  fn blob_codec_roundtrips(#[case] data: Vec<u8>) {
    let bag = blob(data);
    let encoded = bag.to_bytes();
    assert_eq!(BlsIesBlobBytes::decode(&mut encoded.as_slice()).unwrap(), bag);
  }

  #[rstest]
  #[case::none(vec![])]
  #[case::mixed_lengths(vec![vec![0x11; 16], vec![], vec![0x22; 32]])]
  fn multi_codec_roundtrips(#[case] blobs: Vec<Vec<u8>>) {
    let bag = multi(blobs);
    let encoded = bag.to_bytes();
    assert_eq!(BlsIesMultiBytes::decode(&mut encoded.as_slice()).unwrap(), bag);
  }

  #[rstest]
  fn decode_leaves_trailing_input_for_the_next_reader() {
    let bag = blob(vec![0x11; 16]);
    let image: Vec<u8> = bag.to_bytes().into_iter().chain([0xff; 4]).collect();

    let mut cursor = image.as_slice();
    assert_eq!(BlsIesBlobBytes::decode(&mut cursor).unwrap(), bag);
    assert_eq!(cursor, [0xff; 4], "the suffix is the caller's to read");
  }

  /// A length claiming more than the input holds must fail rather than
  /// allocate for it.
  #[rstest]
  fn decode_rejects_overlong_lengths() {
    let mut encoded = blob(vec![0x11; 3]).to_bytes();
    encoded[80] = 0xfe;
    assert!(BlsIesBlobBytes::decode(&mut encoded.as_slice()).is_err());

    let mut encoded = multi(vec![vec![0x11; 3]]).to_bytes();
    encoded[80] = 0xfe;
    assert!(BlsIesMultiBytes::decode(&mut encoded.as_slice()).is_err());
  }

  /// Null key, empty ciphertext, null seed, and nothing besides.
  ///
  /// A fault the reference does not name is not ours to add, which is also
  /// why the multi-recipient bag has no `Checkable` at all. A misaligned
  /// blob clears the gate and is left to fail at the cipher.
  #[rstest]
  #[case::whole_block([0xab; 48], [0xcd; IV_SEED_LEN], vec![0x11; 16], None)]
  #[case::misaligned([0xab; 48], [0xcd; IV_SEED_LEN], vec![0x11; 17], None)]
  #[case::empty_data([0xab; 48], [0xcd; IV_SEED_LEN], vec![], Some(BlsError::InvalidCiphertextLength))]
  #[case::null_seed([0xab; 48], [0; IV_SEED_LEN], vec![0x11; 16], Some(BlsError::InvalidIvSeed))]
  #[case::null_key([0; 48], [0xcd; IV_SEED_LEN], vec![0x11; 16], Some(BlsError::InvalidPublicKey))]
  fn check_validates_each_field(
    #[case] ephemeral_pk: [u8; 48],
    #[case] iv_seed: [u8; IV_SEED_LEN],
    #[case] data: Vec<u8>,
    #[case] fault: Option<BlsError>,
  ) {
    let bag = BlsIesBlobBytes::new(BlsPkBytes::from_bytes(ephemeral_pk), iv_seed, data);
    assert_eq!(bag.check(), fault);
  }

  cfg_if! {
    if #[cfg(feature = "bls")] {
      use crate::bls::tests::RSEED;
      use crate::bls::{BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey};

      use dash_dev::{vec_from_hex, Corpus};
      use serde::Deserialize;

      #[derive(Deserialize)]
      struct BlobVec {
        data_len: usize,
        image: String,
      }

      #[derive(Deserialize)]
      struct MultiVec {
        blob_lens: Vec<usize>,
        image: String,
      }

      fn assert_codec_vectors<S: BlsScheme>(scheme: &str) {
        let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ies").scope(scheme);
        let eph_pk = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap().public_key().to_bytes();

        for v in corpus.vectors::<BlobVec>("blob") {
          let image = vec_from_hex(&v.image);
          let bag = BlsIesBlobBytes::decode(&mut image.as_slice()).unwrap();

          assert_eq!(bag.ephemeral_pk().as_bytes(), &eph_pk);
          assert_eq!(bag.iv_seed(), &RSEED[1]);
          assert_eq!(bag.data().len(), v.data_len);
          assert_eq!(bag.to_bytes(), image);
        }

        for v in corpus.vectors::<MultiVec>("multi") {
          let image = vec_from_hex(&v.image);
          let bag = BlsIesMultiBytes::decode(&mut image.as_slice()).unwrap();

          assert_eq!(bag.ephemeral_pk().as_bytes(), &eph_pk);
          assert_eq!(bag.iv_seed(), &RSEED[1]);
          assert_eq!(bag.blobs().iter().map(Vec::len).collect::<Vec<_>>(), v.blob_lens);
          assert_eq!(bag.to_bytes(), image);
        }
      }

      #[rstest]
      #[case::chia(assert_codec_vectors::<BlsScChia>, "chia")]
      #[case::ietf(assert_codec_vectors::<BlsScIetf>, "ietf")]
      fn codec_matches_the_reference(#[case] assertion: fn(&str), #[case] scheme: &str) {
        assertion(scheme);
      }
    }
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::assert_json_rt;

      #[rstest]
      fn serde_roundtrips() {
        assert_json_rt(&blob(vec![0x11; 16]));
        assert_json_rt(&multi(vec![vec![0x11; 16], vec![0x22; 16]]));
      }

      /// A suffix the decoder never reaches would re-serialize shortened, so
      /// the image has to be consumed whole.
      #[rstest]
      fn serde_rejects_trailing_bytes() {
        use dash_dev::json_rejects;

        fn quoted(bytes: &[u8]) -> String {
          alloc::format!("\"{}\"", bytes.as_hex())
        }

        fn with_suffix(bytes: &[u8]) -> Vec<u8> {
          let mut padded = bytes.to_vec();
          padded.push(0xff);
          padded
        }

        let image = blob(vec![0x11; 16]).to_bytes();
        assert!(!json_rejects::<BlsIesBlobBytes>(&quoted(&image)));
        assert!(json_rejects::<BlsIesBlobBytes>(&quoted(&with_suffix(&image))));

        let image = multi(vec![vec![0x11; 16]]).to_bytes();
        assert!(!json_rejects::<BlsIesMultiBytes>(&quoted(&image)));
        assert!(json_rejects::<BlsIesMultiBytes>(&quoted(&with_suffix(&image))));
      }
    }
  }
}
