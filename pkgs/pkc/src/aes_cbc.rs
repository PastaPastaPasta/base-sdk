//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unpadded AES-256-CBC.

use crate::prelude::*;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes256;
use zeroize::{Zeroize, Zeroizing};

/// AES block length in bytes.
pub(crate) const AES_BLOCK_LEN: usize = 16;

/// AES-256 key length in bytes.
pub(crate) const AES_KEY_LEN: usize = 32;

/// Encrypts under unpadded AES-256-CBC, or `None` when the input is not a
/// whole number of blocks.
pub(crate) fn encrypt(key: &[u8; AES_KEY_LEN], iv: &[u8; AES_BLOCK_LEN], plaintext: &[u8]) -> Option<Vec<u8>> {
  if !plaintext.len().is_multiple_of(AES_BLOCK_LEN) {
    return None;
  }

  let cipher = Aes256::new(key.into());
  let mut output = Vec::with_capacity(plaintext.len());
  let mut chain = *iv;

  for plain in plaintext.chunks_exact(AES_BLOCK_LEN) {
    let mut block = aes::Block::default();
    for (out, (p, c)) in block.iter_mut().zip(plain.iter().zip(&chain)) {
      *out = p ^ c;
    }
    cipher.encrypt_block(&mut block);
    chain.copy_from_slice(&block);
    output.extend_from_slice(&block); // nosemgrep: codec-no-raw-extend
  }

  Some(output)
}

/// Decrypts under unpadded AES-256-CBC, or `None` when the input is not a
/// whole number of blocks.
pub(crate) fn decrypt(
  key: &[u8; AES_KEY_LEN],
  iv: &[u8; AES_BLOCK_LEN],
  ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
  if !ciphertext.len().is_multiple_of(AES_BLOCK_LEN) {
    return None;
  }

  let cipher = Aes256::new(key.into());
  let mut output = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
  let mut chain = *iv;

  for cipher_text in ciphertext.chunks_exact(AES_BLOCK_LEN) {
    let mut block = aes::Block::default();
    block.copy_from_slice(cipher_text);
    cipher.decrypt_block(&mut block);
    for (out, c) in block.iter().zip(&chain) {
      output.push(out ^ c);
    }
    chain.copy_from_slice(cipher_text);
    block[..].zeroize();
  }

  Some(output)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use rstest::rstest;

  fn key_and_iv() -> ([u8; AES_KEY_LEN], [u8; AES_BLOCK_LEN]) {
    let mut key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; AES_BLOCK_LEN];
    getrandom::fill(&mut key).unwrap();
    getrandom::fill(&mut iv).unwrap();
    (key, iv)
  }

  #[rstest]
  #[case::empty(vec![])]
  #[case::one_block(vec![0x11; 16])]
  #[case::many_blocks(vec![0x22; 64])]
  fn cbc_roundtrips(#[case] plaintext: Vec<u8>) {
    let (key, iv) = key_and_iv();
    let ciphertext = encrypt(&key, &iv, &plaintext).unwrap();
    assert_eq!(*decrypt(&key, &iv, &ciphertext).unwrap(), plaintext);
  }

  /// Identical plaintext blocks must not encrypt alike.
  #[rstest]
  fn cbc_chains_ciphertext_blocks() {
    let (key, iv) = key_and_iv();
    let ciphertext = encrypt(&key, &iv, &[0x11u8; 32]).unwrap();
    assert_ne!(ciphertext[..AES_BLOCK_LEN], ciphertext[AES_BLOCK_LEN..]);
  }

  /// Neither direction may silently truncate a partial trailing block.
  #[rstest]
  #[case::one_over(17)]
  #[case::under_a_block(15)]
  fn cbc_rejects_a_partial_trailing_block(#[case] len: usize) {
    let (key, iv) = key_and_iv();
    let input = vec![0x11u8; len];
    assert!(encrypt(&key, &iv, &input).is_none());
    assert!(decrypt(&key, &iv, &input).is_none());
  }
}
