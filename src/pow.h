// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Tcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TCOIN_POW_H
#define TCOIN_POW_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class CBlock;
class CKey;
class CHelperBlock;
class CKeyID;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

std::vector<unsigned char> GetHelperSignature(const CHelperBlock* phblock, CKey key);

bool VerifyHelperSignature(const CHelperBlock* phblock, const CKeyID winningAddress);

CKeyID GetWinningAddress(const CBlockIndex* pindex, int nHeight, const Consensus::Params&);

int GetNBlocksWithoutHelper(const CBlockIndex* pindex, const Consensus::Params& params);

int GetPosPhase (const CBlockIndex* pindex, const Consensus::Params& params);

/** Check whether a block hash satisfies the proof-of-stake-work requirement specified by nBits and stake signed */
bool CheckProofOfStakeWork(CBlockIndex* pindex, const Consensus::Params&);

#endif // TCOIN_POW_H
