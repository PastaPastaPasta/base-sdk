//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's P2P protocol limits, equal at v23.1.8 and v24.0.0-rc.3.

/// `MAX_PROTOCOL_MESSAGE_LENGTH`, the V1 payload limit (`net.h`).
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 3 * 1024 * 1024;

/// `MAX_SIZE`, the largest size `ReadCompactSize` accepts (`serialize.h`).
pub const MAX_SIZE: u64 = 0x0200_0000;

/// `MAX_SUBVERSION_LENGTH`, the `version` user agent limit (`net.h`).
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// `MAX_INV_SZ`, the `inv`, `getdata` and v24 `notfound` limit (`net.h`).
pub const MAX_INV_SZ: usize = 50_000;

/// `MAX_GETDATA_SZ`, the most entries Core puts in one `getdata` it sends.
pub const MAX_GETDATA_SZ: usize = 1_000;

/// `MAX_LOCATOR_SZ`; a longer `getheaders` or `getblocks` locator disconnects.
pub const MAX_LOCATOR_SZ: usize = 101;

/// `MAX_HEADERS_UNCOMPRESSED_RESULT`, the `headers` limit.
pub const MAX_HEADERS_UNCOMPRESSED_RESULT: usize = 2_000;

/// `MAX_HEADERS_COMPRESSED_RESULT`, the `headers2` limit from
/// [`crate::ProtocolVersion::INCREASE_MAX_HEADERS2`].
pub const MAX_HEADERS_COMPRESSED_RESULT: usize = 8_000;

/// `MAX_ADDR_TO_SEND`, the `addr` and `addrv2` limit.
pub const MAX_ADDR_TO_SEND: usize = 1_000;

/// `MAX_BLOOM_FILTER_SIZE`, the `filterload` data limit in bytes.
pub const MAX_BLOOM_FILTER_SIZE: usize = 36_000;

/// `MAX_HASH_FUNCS`; a `filterload` with more is penalised.
pub const MAX_HASH_FUNCS: u32 = 50;

/// `MAX_SCRIPT_ELEMENT_SIZE`, the `filteradd` data limit in bytes.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// `CMPCTBLOCKS_VERSION`; `sendcmpct` with another version is ignored.
pub const CMPCTBLOCKS_VERSION: u64 = 1;

/// `MAX_CMPCTBLOCK_DEPTH`, how deep below the tip Core serves `cmpctblock`.
pub const MAX_CMPCTBLOCK_DEPTH: u32 = 5;

/// `MAX_BLOCKTXN_DEPTH`, how deep below the tip Core serves `blocktxn`.
pub const MAX_BLOCKTXN_DEPTH: u32 = 10;

/// `MAX_GETCFILTERS_SIZE`, the most filters one `getcfilters` may request.
pub const MAX_GETCFILTERS_SIZE: u32 = 1_000;

/// `MAX_GETCFHEADERS_SIZE`, the most headers one `getcfheaders` may request.
pub const MAX_GETCFHEADERS_SIZE: u32 = 2_000;

/// `CFCHECKPT_INTERVAL`, the spacing of `cfcheckpt` entries
/// (`blockfilterindex.h`).
pub const CFCHECKPT_INTERVAL: u32 = 1_000;

/// `MAX_CONTENTS_LEN`, the V2 contents limit: a long-form type, 13 bytes,
/// and a V1-sized payload. Core checks it before reading the type.
pub const MAX_V2_CONTENTS_LEN: usize = 1 + 12 + MAX_PROTOCOL_MESSAGE_LENGTH;
