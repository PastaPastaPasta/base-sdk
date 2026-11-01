//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Prints the chain parameters of a reference implementation release as JSON,
// using the release's own code. build.sh links it against the release's
// libraries and compiles in the tag, its commit and this file's sha256.
//
//   chainparams_dump info
//     the tag, commit, source sha256 and version string.
//   chainparams_dump params <chain> [args...]
//     the parameters of <chain> after the release parses [args...] and selects
//     the chain, as "params" and "ext", and the spork signers its startup then
//     resolves ("spork"). A refused argument list gives the release's error
//     text instead, "parse_error" while parsing, "error" while selecting the
//     chain, or "spork.error" while resolving the spork signers.
//   chainparams_dump payment <height> <block value>
//     the mainnet masternode payment at <height> in the classic reward era.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <deploymentinfo.h>
#include <key_io.h>
#include <llmq/params.h>
#include <script/standard.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <version.h>

#if CLIENT_VERSION_MAJOR >= 24
#include <masternode/payments.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <set>
#include <string>
#include <vector>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

#if !defined(DUMP_TAG) || !defined(DUMP_COMMIT) || !defined(DUMP_SOURCE_SHA256)
#error "build.sh defines DUMP_TAG, DUMP_COMMIT and DUMP_SOURCE_SHA256"
#endif

namespace {

UniValue HashHex(const uint256& hash) { return UniValue{hash.GetHex()}; }

UniValue LlmqJson(const Consensus::LLMQParams& q)
{
    UniValue llmq{UniValue::VOBJ};
    llmq.pushKV("type", static_cast<int>(q.type));
    llmq.pushKV("name", std::string{q.name});
    llmq.pushKV("useRotation", q.useRotation);
    llmq.pushKV("size", q.size);
    llmq.pushKV("minSize", q.minSize);
    llmq.pushKV("threshold", q.threshold);
    llmq.pushKV("dkgInterval", q.dkgInterval);
    llmq.pushKV("dkgPhaseBlocks", q.dkgPhaseBlocks);
    llmq.pushKV("dkgMiningWindowStart", q.dkgMiningWindowStart);
    llmq.pushKV("dkgMiningWindowEnd", q.dkgMiningWindowEnd);
    llmq.pushKV("dkgBadVotesThreshold", q.dkgBadVotesThreshold);
    llmq.pushKV("signingActiveQuorumCount", q.signingActiveQuorumCount);
    llmq.pushKV("keepOldConnections", q.keepOldConnections);
    llmq.pushKV("keepOldKeys", q.keepOldKeys);
    llmq.pushKV("recoveryMembers", q.recoveryMembers);
    return llmq;
}

// An LLMQ with the values the release derives from it.
UniValue LlmqExtJson(const Consensus::LLMQParams& q)
{
    UniValue llmq{LlmqJson(q)};
    llmq.pushKV("max_store_depth", q.max_store_depth());
    llmq.pushKV("is_single_member", q.is_single_member());
    return llmq;
}

UniValue ParamsJson(const CChainParams& chain)
{
    const Consensus::Params& c = chain.GetConsensus();
    UniValue consensus{UniValue::VOBJ};
    consensus.pushKV("hashGenesisBlock", HashHex(c.hashGenesisBlock));
    consensus.pushKV("hashDevnetGenesisBlock", HashHex(c.hashDevnetGenesisBlock));
    consensus.pushKV("nSubsidyHalvingInterval", c.nSubsidyHalvingInterval);
    consensus.pushKV("nMasternodePaymentsStartBlock", c.nMasternodePaymentsStartBlock);
    consensus.pushKV("nMasternodePaymentsIncreaseBlock", c.nMasternodePaymentsIncreaseBlock);
    consensus.pushKV("nMasternodePaymentsIncreasePeriod", c.nMasternodePaymentsIncreasePeriod);
    consensus.pushKV("nInstantSendConfirmationsRequired", c.nInstantSendConfirmationsRequired);
    consensus.pushKV("nInstantSendKeepLock", c.nInstantSendKeepLock);
    consensus.pushKV("nBudgetPaymentsStartBlock", c.nBudgetPaymentsStartBlock);
    consensus.pushKV("nBudgetPaymentsCycleBlocks", c.nBudgetPaymentsCycleBlocks);
    consensus.pushKV("nBudgetPaymentsWindowBlocks", c.nBudgetPaymentsWindowBlocks);
    consensus.pushKV("nSuperblockStartBlock", c.nSuperblockStartBlock);
    consensus.pushKV("nSuperblockStartHash", HashHex(c.nSuperblockStartHash));
    consensus.pushKV("nSuperblockCycle", c.nSuperblockCycle);
    consensus.pushKV("nSuperblockMaturityWindow", c.nSuperblockMaturityWindow);
    consensus.pushKV("nGovernanceMinQuorum", c.nGovernanceMinQuorum);
    consensus.pushKV("nGovernanceFilterElements", c.nGovernanceFilterElements);
    consensus.pushKV("nMasternodeMinimumConfirmations", c.nMasternodeMinimumConfirmations);
    consensus.pushKV("BIP34Height", c.BIP34Height);
    consensus.pushKV("BIP34Hash", HashHex(c.BIP34Hash));
    consensus.pushKV("BIP65Height", c.BIP65Height);
    consensus.pushKV("BIP66Height", c.BIP66Height);
    consensus.pushKV("BIP147Height", c.BIP147Height);
    consensus.pushKV("CSVHeight", c.CSVHeight);
    consensus.pushKV("DIP0001Height", c.DIP0001Height);
    consensus.pushKV("DIP0003Height", c.DIP0003Height);
    consensus.pushKV("DIP0003EnforcementHeight", c.DIP0003EnforcementHeight);
    consensus.pushKV("DIP0003EnforcementHash", HashHex(c.DIP0003EnforcementHash));
    consensus.pushKV("DIP0008Height", c.DIP0008Height);
    consensus.pushKV("BRRHeight", c.BRRHeight);
    consensus.pushKV("DIP0020Height", c.DIP0020Height);
    consensus.pushKV("DIP0024Height", c.DIP0024Height);
    consensus.pushKV("DIP0024QuorumsHeight", c.DIP0024QuorumsHeight);
    consensus.pushKV("V19Height", c.V19Height);
    consensus.pushKV("V20Height", c.V20Height);
    consensus.pushKV("MN_RRHeight", c.MN_RRHeight);
    consensus.pushKV("WithdrawalsHeight", c.WithdrawalsHeight);
    consensus.pushKV("MinBIP9WarningHeight", c.MinBIP9WarningHeight);
    consensus.pushKV("nRuleChangeActivationThreshold", uint64_t{c.nRuleChangeActivationThreshold});
    consensus.pushKV("nMinerConfirmationWindow", uint64_t{c.nMinerConfirmationWindow});
    UniValue deployments{UniValue::VARR};
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const Consensus::BIP9Deployment& d = c.vDeployments[i];
        UniValue dep{UniValue::VOBJ};
        dep.pushKV("name", VersionBitsDeploymentInfo[i].name);
        dep.pushKV("bit", d.bit);
        dep.pushKV("nStartTime", d.nStartTime);
        dep.pushKV("nTimeout", d.nTimeout);
        dep.pushKV("min_activation_height", d.min_activation_height);
        dep.pushKV("nWindowSize", d.nWindowSize);
        dep.pushKV("nThresholdStart", d.nThresholdStart);
        dep.pushKV("nThresholdMin", d.nThresholdMin);
        dep.pushKV("nFalloffCoeff", d.nFalloffCoeff);
        dep.pushKV("useEHF", d.useEHF);
        deployments.push_back(dep);
    }
    consensus.pushKV("vDeployments", deployments);
    consensus.pushKV("powLimit", HashHex(c.powLimit));
    consensus.pushKV("fPowAllowMinDifficultyBlocks", c.fPowAllowMinDifficultyBlocks);
    consensus.pushKV("fPowNoRetargeting", c.fPowNoRetargeting);
    consensus.pushKV("nPowTargetSpacing", c.nPowTargetSpacing);
    consensus.pushKV("nPowTargetTimespan", c.nPowTargetTimespan);
    consensus.pushKV("nPowKGWHeight", c.nPowKGWHeight);
    consensus.pushKV("nPowDGWHeight", c.nPowDGWHeight);
    consensus.pushKV("nMinimumChainWork", HashHex(c.nMinimumChainWork));
    consensus.pushKV("defaultAssumeValid", HashHex(c.defaultAssumeValid));
    consensus.pushKV("nMinimumDifficultyBlocks", c.nMinimumDifficultyBlocks);
    consensus.pushKV("nHighSubsidyBlocks", c.nHighSubsidyBlocks);
    consensus.pushKV("nHighSubsidyFactor", c.nHighSubsidyFactor);
    UniValue llmqs{UniValue::VARR};
    for (const auto& q : c.llmqs) llmqs.push_back(LlmqJson(q));
    consensus.pushKV("llmqs", llmqs);
    consensus.pushKV("llmqTypeChainLocks", static_cast<int>(c.llmqTypeChainLocks));
    consensus.pushKV("llmqTypeDIP0024InstantSend", static_cast<int>(c.llmqTypeDIP0024InstantSend));
    consensus.pushKV("llmqTypePlatform", static_cast<int>(c.llmqTypePlatform));
    consensus.pushKV("llmqTypeMnhf", static_cast<int>(c.llmqTypeMnhf));

    UniValue base58{UniValue::VOBJ};
    base58.pushKV("PUBKEY_ADDRESS", HexStr(chain.Base58Prefix(CChainParams::PUBKEY_ADDRESS)));
    base58.pushKV("SCRIPT_ADDRESS", HexStr(chain.Base58Prefix(CChainParams::SCRIPT_ADDRESS)));
    base58.pushKV("SECRET_KEY", HexStr(chain.Base58Prefix(CChainParams::SECRET_KEY)));
    base58.pushKV("EXT_PUBLIC_KEY", HexStr(chain.Base58Prefix(CChainParams::EXT_PUBLIC_KEY)));
    base58.pushKV("EXT_SECRET_KEY", HexStr(chain.Base58Prefix(CChainParams::EXT_SECRET_KEY)));

    UniValue checkpoints{UniValue::VOBJ};
    for (const auto& [height, hash] : chain.Checkpoints().mapCheckpoints) {
        checkpoints.pushKV(strprintf("%d", height), hash.GetHex());
    }

    UniValue ret{UniValue::VOBJ};
    ret.pushKV("networkID", chain.NetworkIDString());
    ret.pushKV("messageStart", HexStr(chain.MessageStart()));
    CDataStream genesis{SER_NETWORK, PROTOCOL_VERSION};
    genesis << chain.GenesisBlock();
    ret.pushKV("defaultPort", int{chain.GetDefaultPort()});
    ret.pushKV("pruneAfterHeight", chain.PruneAfterHeight());
    ret.pushKV("genesisHash", chain.GenesisBlock().GetHash().GetHex());
    ret.pushKV("genesisBlock", HexStr(MakeUCharSpan(genesis)));
    ret.pushKV("devnetGenesisHash", chain.DevNetGenesisBlock().GetHash().GetHex());
    ret.pushKV("extCoinType", chain.ExtCoinType());
    ret.pushKV("base58Prefixes", base58);
    ret.pushKV("checkpoints", checkpoints);
    ret.pushKV("consensus", consensus);
    return ret;
}

UniValue ExtJson(const CChainParams& chain)
{
    UniValue ext{UniValue::VOBJ};
    const CBaseChainParams& base = BaseParams();
    ext.pushKV("dataDir", base.DataDir());
    ext.pushKV("rpcPort", int{base.RPCPort()});
    ext.pushKV("onionServiceTargetPort", int{base.OnionServiceTargetPort()});
    ext.pushKV("defaultPlatformP2PPort", int{chain.GetDefaultPlatformP2PPort()});
    ext.pushKV("defaultPlatformHTTPPort", int{chain.GetDefaultPlatformHTTPPort()});
#if CLIENT_VERSION_MAJOR >= 24
    ext.pushKV("minBlocksToKeep", chain.MinBlocksToKeep());
#else
    ext.pushKV("minBlocksToKeep", uint64_t{MIN_BLOCKS_TO_KEEP});
#endif
    ext.pushKV("assumedBlockchainSize", chain.AssumedBlockchainSize());
    ext.pushKV("assumedChainStateSize", chain.AssumedChainStateSize());
    UniValue seeds{UniValue::VARR};
    for (const auto& s : chain.DNSSeeds()) seeds.push_back(s);
    ext.pushKV("dnsSeeds", seeds);
    ext.pushKV("fixedSeeds", HexStr(chain.FixedSeeds()));
    UniValue spork{UniValue::VARR};
#if CLIENT_VERSION_MAJOR >= 24
    ext.pushKV("bech32PlatformHRP", chain.Bech32PlatformHRP());
    spork.push_back(chain.SporkAddress());
#else
    ext.pushKV("requireStandard", chain.RequireStandard());
    for (const auto& a : chain.SporkAddresses()) spork.push_back(a);
    ext.pushKV("minSporkKeys", chain.MinSporkKeys());
#endif
    ext.pushKV("sporkAddresses", spork);
    ext.pushKV("defaultConsistencyChecks", chain.DefaultConsistencyChecks());
    ext.pushKV("requireRoutableExternalIP", chain.RequireRoutableExternalIP());
    ext.pushKV("isTestChain", chain.IsTestChain());
    ext.pushKV("isMockableChain", chain.IsMockableChain());
    ext.pushKV("mineBlocksOnDemand", chain.MineBlocksOnDemand());
    ext.pushKV("allowMultipleAddressesFromGroup", chain.AllowMultipleAddressesFromGroup());
    ext.pushKV("llmqConnectionRetryTimeout", chain.LLMQConnectionRetryTimeout());
    ext.pushKV("poolMinParticipants", chain.PoolMinParticipants());
    ext.pushKV("poolMaxParticipants", chain.PoolMaxParticipants());
    ext.pushKV("fulfilledRequestExpireTime", chain.FulfilledRequestExpireTime());
    ext.pushKV("creditPoolPeriodBlocks", chain.CreditPoolPeriodBlocks());

    // The rate goes out as its IEEE 754 bits, which JSON numbers can round.
    const ChainTxData& tx = chain.TxData();
    UniValue txdata{UniValue::VOBJ};
    txdata.pushKV("nTime", tx.nTime);
    txdata.pushKV("nTxCount", tx.nTxCount);
    uint64_t rate_bits;
    static_assert(sizeof(rate_bits) == sizeof(tx.dTxRate));
    std::memcpy(&rate_bits, &tx.dTxRate, sizeof(rate_bits));
    txdata.pushKV("dTxRateBits", strprintf("%016x", rate_bits));
    ext.pushKV("chainTxData", txdata);

    CDataStream devnet_genesis{SER_NETWORK, PROTOCOL_VERSION};
    devnet_genesis << chain.DevNetGenesisBlock();
    ext.pushKV("devnetGenesisBlock", HexStr(MakeUCharSpan(devnet_genesis)));

    UniValue assumeutxo{UniValue::VARR};
    for (const auto& [height, data] : chain.Assumeutxo()) {
        UniValue au{UniValue::VOBJ};
        au.pushKV("height", height);
        au.pushKV("hash_serialized", data.hash_serialized.ToString());
#if CLIENT_VERSION_MAJOR >= 24
        au.pushKV("evo_hash", data.evo_hash.ToString());
#endif
        au.pushKV("nChainTx", uint64_t{data.nChainTx});
        assumeutxo.push_back(au);
    }
    ext.pushKV("assumeutxo", assumeutxo);

    UniValue info{UniValue::VARR};
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        UniValue d{UniValue::VOBJ};
        d.pushKV("name", VersionBitsDeploymentInfo[i].name);
        d.pushKV("gbt_force", VersionBitsDeploymentInfo[i].gbt_force);
        info.push_back(d);
    }
    ext.pushKV("deploymentInfo", info);

    UniValue buried{UniValue::VOBJ};
    for (int i = Consensus::DEPLOYMENT_HEIGHTINCB; i <= Consensus::DEPLOYMENT_WITHDRAWALS; ++i) {
        const auto dep = static_cast<Consensus::BuriedDeployment>(i);
        buried.pushKV(DeploymentName(dep), chain.GetConsensus().DeploymentHeight(dep));
    }
    ext.pushKV("buriedDeployments", buried);

    UniValue llmqs{UniValue::VARR};
    for (const auto& q : chain.GetConsensus().llmqs) llmqs.push_back(LlmqExtJson(q));
    ext.pushKV("llmqs", llmqs);
    UniValue available{UniValue::VARR};
    for (const auto& q : Consensus::available_llmqs) available.push_back(LlmqExtJson(q));
    ext.pushKV("availableLlmqs", available);
#if CLIENT_VERSION_MAJOR >= 24
    ext.pushKV("MAX_LLMQ_SIZE", Consensus::MAX_LLMQ_SIZE);
#endif
    return ext;
}

// The spork signer state the release's spork manager keeps, with its two
// setters as the release has them, without the lock and the log lines.
struct SporkSigners {
#if CLIENT_VERSION_MAJOR >= 24
    CKeyID sporkPubKeyID;
#else
    std::set<CKeyID> setSporkPubKeyIDs;
    int nMinSporkKeys{0};
#endif

    bool SetSporkAddress(const std::string& strAddress)
    {
        CTxDestination dest = DecodeDestination(strAddress);
        const PKHash* pkhash = std::get_if<PKHash>(&dest);
        if (!pkhash) {
            return false;
        }
#if CLIENT_VERSION_MAJOR >= 24
        sporkPubKeyID = ToKeyID(*pkhash);
#else
        setSporkPubKeyIDs.insert(ToKeyID(*pkhash));
#endif
        return true;
    }

#if CLIENT_VERSION_MAJOR < 24
    bool SetMinSporkKeys(int minSporkKeys)
    {
        if (int maxKeysNumber = setSporkPubKeyIDs.size(); (minSporkKeys <= maxKeysNumber / 2) || (minSporkKeys > maxKeysNumber)) {
            return false;
        }
        nMinSporkKeys = minSporkKeys;
        return true;
    }
#endif
};

// The spork signers as the release's startup resolves them from the options,
// with its error or warning recorded instead of raised.
UniValue SporkJson(const ArgsManager& args, const CChainParams& chainparams)
{
    SporkSigners sporkman;
    UniValue out{UniValue::VOBJ};
    const auto InitError = [&](const bilingual_str& str) {
        out.pushKV("error", str.original);
        return out;
    };
#if CLIENT_VERSION_MAJOR >= 24
    const std::string spork_address{args.GetArg("-sporkaddr", chainparams.SporkAddress())};
    if (args.GetArgs("-sporkaddr").size() > 1) {
        out.pushKV("warning", strprintf(_("More than one spork address is provided. Using %s."), spork_address).original);
    }
    if (!sporkman.SetSporkAddress(spork_address)) {
        return InitError(_("Invalid spork address specified with -sporkaddr"));
    }
    UniValue keys{UniValue::VARR};
    keys.push_back(HexStr(sporkman.sporkPubKeyID));
#else
    std::vector<std::string> vSporkAddresses;
    if (args.IsArgSet("-sporkaddr")) {
        vSporkAddresses = args.GetArgs("-sporkaddr");
    } else {
        vSporkAddresses = chainparams.SporkAddresses();
    }
    for (const auto& address : vSporkAddresses) {
        if (!sporkman.SetSporkAddress(address)) {
            return InitError(_("Invalid spork address specified with -sporkaddr"));
        }
    }
    int minsporkkeys = args.GetIntArg("-minsporkkeys", chainparams.MinSporkKeys());
    if (!sporkman.SetMinSporkKeys(minsporkkeys)) {
        return InitError(_("Invalid minimum number of spork signers specified with -minsporkkeys"));
    }
    UniValue keys{UniValue::VARR};
    for (const auto& id : sporkman.setSporkPubKeyIDs) keys.push_back(HexStr(id));
    out.pushKV("minSporkKeys", sporkman.nMinSporkKeys);
#endif
    out.pushKV("keyIDs", keys);
    return out;
}

int DumpInfo()
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("tag", DUMP_TAG);
    out.pushKV("commit", DUMP_COMMIT);
    out.pushKV("source_sha256", DUMP_SOURCE_SHA256);
    out.pushKV("version", FormatFullVersion());
    std::printf("%s\n", out.write().c_str());
    return 0;
}

int DumpParams(int argc, char* argv[])
{
    std::vector<const char*> args{"chainparams_dump"};
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    UniValue out{UniValue::VOBJ};
    gArgs.ClearArgs();
    SetupChainParamsOptions(gArgs);
    // The node's other options that its chain parameters or spork signers
    // read, added as the node adds them.
    gArgs.AddArg("-fastprune", "", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
#if CLIENT_VERSION_MAJOR < 24
    gArgs.AddArg("-minsporkkeys=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
#endif
    gArgs.AddArg("-sporkaddr=<dashaddress>", "", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    std::string error;
    if (!gArgs.ParseParameters(args.size(), args.data(), error)) {
        out.pushKV("parse_error", error);
    } else {
        try {
            SelectParams(argv[0]);
            out.pushKV("params", ParamsJson(Params()));
            out.pushKV("ext", ExtJson(Params()));
            out.pushKV("spork", SporkJson(gArgs, Params()));
        } catch (const std::exception& e) {
            out.pushKV("error", std::string{e.what()});
        }
    }
    std::printf("%s\n", out.write().c_str());
    return 0;
}

int DumpPayment(const char* height_arg, const char* value_arg)
{
    int height;
    int64_t value;
    if (!ParseInt32(height_arg, &height) || !ParseInt64(value_arg, &value)) {
        std::fprintf(stderr, "payment: bad height or block value\n");
        return 2;
    }
    SelectParams(CBaseChainParams::MAIN);
#if CLIENT_VERSION_MAJOR >= 24
    const CAmount payment{GetMasternodePayment(height, value, Params().GetConsensus(), MnRewardEra::Classic)};
#else
    const CAmount payment{GetMasternodePayment(height, value, /*fV20Active=*/false)};
#endif
    UniValue out{UniValue::VOBJ};
    out.pushKV("height", height);
    out.pushKV("block_value", value);
    out.pushKV("payment", payment);
    std::printf("%s\n", out.write().c_str());
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    const std::string mode{argc > 1 ? argv[1] : ""};
    if (mode == "info" && argc == 2) return DumpInfo();
    if (mode == "params" && argc > 2) return DumpParams(argc - 2, argv + 2);
    if (mode == "payment" && argc == 4) return DumpPayment(argv[2], argv[3]);
    std::fprintf(stderr,
                 "usage: %s info\n"
                 "       %s params <chain> [args...]\n"
                 "       %s payment <height> <block value>\n",
                 argv[0], argv[0], argv[0]);
    return 2;
}
