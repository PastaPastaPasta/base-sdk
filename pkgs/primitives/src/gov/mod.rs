//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types.

mod object;
mod vote;

pub use object::{GovData, GovObject, GovObjectType, Proposal, ProposalInvalid, Trigger};
pub use vote::{GovVote, GovVoteBls, GovVoteEcdsa, GovVoteEcdsaSer, VoteOutcome, VoteSignal};
