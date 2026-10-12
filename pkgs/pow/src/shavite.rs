//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 hash function.

use crate::aes::{block_from_words, round_nk, words_from_block, Block};
use crate::consts::shavite::{BLOCK, IV};
use crate::util::memops::{digest_from_u32_le, load_u32_le, zero_extend};

use wide::u32x4;

const SCHEDULE_BUNDLES: usize = 112;
type Bundle = [u32; 4];
type State = [u32; 16];
type BlockWords = [u32; 32];

/// Selects which counter word is injected at one schedule checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CounterWord {
  Counter(usize),
  InvertedCounter(usize),
}

/// Schedule bundle that receives one HAIFA counter injection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CounterInjection {
  bundle: usize,
  words: [CounterWord; 4],
}

const COUNTER_INJECTIONS: [CounterInjection; 4] = [
  CounterInjection {
    bundle: 8,
    words: [
      CounterWord::Counter(0),
      CounterWord::Counter(1),
      CounterWord::Counter(2),
      CounterWord::InvertedCounter(3),
    ],
  },
  CounterInjection {
    bundle: 41,
    words: [
      CounterWord::Counter(3),
      CounterWord::Counter(2),
      CounterWord::Counter(1),
      CounterWord::InvertedCounter(0),
    ],
  },
  CounterInjection {
    bundle: 79,
    words: [
      CounterWord::Counter(2),
      CounterWord::Counter(3),
      CounterWord::Counter(0),
      CounterWord::InvertedCounter(1),
    ],
  },
  CounterInjection {
    bundle: 110,
    words: [
      CounterWord::Counter(1),
      CounterWord::Counter(0),
      CounterWord::Counter(3),
      CounterWord::InvertedCounter(2),
    ],
  },
];

/// Rotates each 4-word column one step toward the front.
const COLUMN_ROTATION: [usize; 16] = [12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

#[inline(always)]
const fn rotate_bundle_words(bundle: Bundle) -> Bundle {
  [bundle[1], bundle[2], bundle[3], bundle[0]]
}

/// Reads one counter word according to the schedule descriptor.
#[inline(always)]
fn counter_word(counter: u128, word: CounterWord) -> u32 {
  match word {
    CounterWord::Counter(index) => (counter >> (32 * index)) as u32,
    CounterWord::InvertedCounter(index) => !(counter >> (32 * index)) as u32,
  }
}

/// Expands one 128-byte block into 112 four-word schedule bundles.
#[inline(always)]
fn expand_round_keys_words(msg: &BlockWords, counter: u128) -> [Bundle; SCHEDULE_BUNDLES] {
  let mut schedule = [[0u32; 4]; SCHEDULE_BUNDLES];
  let mut bundle = 0;
  while bundle < 8 {
    schedule[bundle][0] = msg[bundle * 4];
    schedule[bundle][1] = msg[bundle * 4 + 1];
    schedule[bundle][2] = msg[bundle * 4 + 2];
    schedule[bundle][3] = msg[bundle * 4 + 3];
    bundle += 1;
  }

  let mut next_injection = 0;
  bundle = 8;
  loop {
    let mut pair = 0;
    while pair < 8 {
      // One half of the schedule uses the AES-based recurrence from the
      // design, with counter words injected at fixed checkpoints.
      schedule[bundle] = expand_aes_step(&schedule, bundle);
      if next_injection < COUNTER_INJECTIONS.len() && COUNTER_INJECTIONS[next_injection].bundle == bundle {
        inject_counter_words(&mut schedule[bundle], counter, COUNTER_INJECTIONS[next_injection]);
        next_injection += 1;
      }
      bundle += 1;
      pair += 1;
    }

    if bundle == SCHEDULE_BUNDLES {
      break;
    }

    let mut pair = 0;
    while pair < 8 {
      // The next half only xors earlier bundles. Grouping the two recurrences
      // separately keeps the schedule shape visible in the code.
      schedule[bundle] = expand_linear_step(&schedule, bundle);
      bundle += 1;
      pair += 1;
    }
  }

  schedule
}

#[inline(always)]
fn expand_round_keys(msg: &[u8; BLOCK], counter: u128) -> [Bundle; SCHEDULE_BUNDLES] {
  let words = core::array::from_fn(|word| load_u32_le(msg, word));
  expand_round_keys_words(&words, counter)
}

/// Applies the AES-based bundle step used by the key schedule.
#[inline(always)]
fn expand_aes_step(schedule: &[Bundle; SCHEDULE_BUNDLES], bundle: usize) -> Bundle {
  let expanded = words_from_block(round_nk(lane(rotate_bundle_words(schedule[bundle - 8])))).to_array();
  [
    expanded[0] ^ schedule[bundle - 1][0],
    expanded[1] ^ schedule[bundle - 1][1],
    expanded[2] ^ schedule[bundle - 1][2],
    expanded[3] ^ schedule[bundle - 1][3],
  ]
}

/// Applies the xor-only bundle step used between AES expansion groups.
#[inline(always)]
fn expand_linear_step(schedule: &[Bundle; SCHEDULE_BUNDLES], bundle: usize) -> Bundle {
  [
    schedule[bundle - 8][0] ^ schedule[bundle - 2][1],
    schedule[bundle - 8][1] ^ schedule[bundle - 2][2],
    schedule[bundle - 8][2] ^ schedule[bundle - 2][3],
    schedule[bundle - 8][3] ^ schedule[bundle - 1][0],
  ]
}

/// Injects the HAIFA counter words at one schedule checkpoint.
#[inline(always)]
fn inject_counter_words(bundle_words: &mut Bundle, counter: u128, injection: CounterInjection) {
  let mut word = 0;
  while word < 4 {
    bundle_words[word] ^= counter_word(counter, injection.words[word]);
    word += 1;
  }
}

/// Lays four state words out as one AES block.
#[inline(always)]
fn lane(words: Bundle) -> Block {
  block_from_words(u32x4::new(words))
}

/// Runs the 4-round AES bundle that updates one 4-word half.
#[inline(always)]
fn apply_round_bundle(state: &mut State, left: [usize; 4], right: [usize; 4], keys: &[Bundle]) {
  // Each bundle reads one 4-word half, runs four keyed AES rounds, then xors
  // the result into the opposite half in Feistel order.
  let mut block = lane([state[right[0]], state[right[1]], state[right[2]], state[right[3]]]);
  let mut round = 0;
  while round < 4 {
    block = round_nk(block ^ lane(keys[round]));
    round += 1;
  }

  let mixed = words_from_block(block).to_array();
  state[left[0]] ^= mixed[0];
  state[left[1]] ^= mixed[1];
  state[left[2]] ^= mixed[2];
  state[left[3]] ^= mixed[3];
}

/// Rotates the four columns after one round pair.
#[inline(always)]
fn rotate_columns(state: &mut State) {
  let saved = *state;
  let mut word = 0;
  while word < 16 {
    state[word] = saved[COLUMN_ROTATION[word]];
    word += 1;
  }
}

/// Runs the SHAvite-3-512 compression function.
#[inline(always)]
fn compress_block(chaining_value: &mut State, msg: &[u8; BLOCK], counter: u128) {
  let schedule = expand_round_keys(msg, counter);
  compress_schedule(chaining_value, &schedule);
}

#[inline(always)]
fn compress_schedule(chaining_value: &mut State, schedule: &[Bundle; SCHEDULE_BUNDLES]) {
  let mut state = *chaining_value;
  let mut bundle = 0;
  let mut round = 0;
  while round < 14 {
    apply_round_bundle(
      &mut state,
      [0, 1, 2, 3],
      [4, 5, 6, 7],
      &schedule[bundle * 4..bundle * 4 + 4],
    );
    bundle += 1;
    apply_round_bundle(
      &mut state,
      [8, 9, 10, 11],
      [12, 13, 14, 15],
      &schedule[bundle * 4..bundle * 4 + 4],
    );
    bundle += 1;
    rotate_columns(&mut state);
    round += 1;
  }

  let mut word = 0;
  while word < 16 {
    chaining_value[word] ^= state[word];
    word += 1;
  }
}

fn hash_to_words(data: &[u8]) -> State {
  let mut chaining_value = IV;
  let mut counter = 0u128;

  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    counter = counter.wrapping_add(1024);
    compress_block(&mut chaining_value, block, counter);
  }

  let used = tail.len();
  counter = counter.wrapping_add(used as u128 * 8);
  let saved_counter = counter;

  let mut block: [u8; BLOCK] = zero_extend(tail);
  block[used] = 0x80;
  if used == 0 {
    counter = 0;
  } else if used >= 110 {
    compress_block(&mut chaining_value, &block, counter);
    block = [0u8; BLOCK];
    counter = 0;
  }

  block[110..126].copy_from_slice(&saved_counter.to_le_bytes());
  block[126..].copy_from_slice(&512u16.to_le_bytes());
  compress_block(&mut chaining_value, &block, counter);

  chaining_value
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  digest_from_u32_le(&hash_to_words(data))
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("shavite", hash512);
  }
}
