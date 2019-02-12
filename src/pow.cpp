// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Tcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

#include "util.h"
#include "validation.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
  LogPrintf("getnextworkrequired: %d\n",pindexLast->nHeight);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    if (pindexLast->nHeight <= params.nHeightCP) {
      return UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).GetCompact();
    }


    if (pindexLast->nHeight >= 602927) { //tmp
      return UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).GetCompact();
    }
    
    // Only change once per difficulty adjustment interval
    bool fork = EnforceProofOfStake(pindexLast,params);
    bool forkPrev = EnforceProofOfStake(pindexLast->pprev,params);
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval(fork) != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks && pindexLast->nHeight >= params.nHeightMinDiff)
        {
	  LogPrintf("allowmindiff\n");
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
	  if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2) {
	    LogPrintf("min diff block time and height met\n");
	    return UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).GetCompact();
	  }
	  else
            {
	      // Return the last non-special-min-difficulty-rules-block
	      const CBlockIndex* pindex = pindexLast;
	      while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval(fork) != 0 && pindex->nBits == nProofOfWorkLimit)
		pindex = pindex->pprev;
	      return pindex->nBits;
            }
        }
	if (!fork || forkPrev)
	  return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval(fork)-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    int64_t nFirstBlockTime =  pindexFirst->GetBlockTime();
    if (fork)
      nFirstBlockTime =  pindexFirst->GetMedianTimePast();
    return CalculateNextWorkRequired(pindexLast, nFirstBlockTime, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    bool fork = EnforceProofOfStake(pindexLast,params);
    bool forkPrev = EnforceProofOfStake(pindexLast->pprev,params);
    if (fork)
      nActualTimespan = pindexLast->GetMedianTimePast() - nFirstBlockTime;
    int64_t targetTimespan = params.nPowTargetTimespan;
    if (fork)
	targetTimespan /= 14;
    if (nActualTimespan < params.nPowTargetTimespan/4 && (!fork || forkPrev))
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4 && (!fork || forkPrev))
        nActualTimespan = params.nPowTargetTimespan*4;
    if (nActualTimespan <= 0)
      nActualTimespan = params.nPowTargetTimespan/4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow) {
      LogPrintf("checkproofofwork: bad range\n");
      return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
      //LogPrintf("work doesn't match claimed amount\n");
      return false;
    }

    return true;
}

std::vector<unsigned char> GetHelperSignature (const CHelperBlock* phblock, CKey key) {
  CHashWriter ss(SER_GETHASH, 0);
  ss << phblock->hashPrevBlock.ToString();
  ss << phblock->hashMerkleRoot.ToString();
  ss << phblock->paymentAddress.ToString();
  std::vector<unsigned char> vchSig;
  if (!key.SignCompact(ss.GetHash(), vchSig)) {
    LogPrintf("GetHelperSignature: signing failed\n");
  }
  return vchSig;
}

bool VerifyHelperSignature (const CHelperBlock* phblock, const CKeyID winningAddress) {
  CHashWriter ss(SER_GETHASH, 0);
  ss << phblock->hashPrevBlock.ToString();
  ss << phblock->hashMerkleRoot.ToString();
  ss << phblock->paymentAddress.GetHex();
  CPubKey pubkey;
  if (!pubkey.RecoverCompact(ss.GetHash(), phblock->signature))
    return false;
  return (pubkey.GetID() == winningAddress);
}

CKeyID GetWinningAddress (const CBlockIndex* pindex, int nHeight, const Consensus::Params& params) {
  int startBlock = 1;
  if (nHeight > params.nPosLookback)
    startBlock += nHeight-params.nPosLookback;
  const CBlockIndex* pindexCur = pindex->GetAncestor(nHeight);

  uint64_t moneySupplyUsed = pindex->nMatureSat.at(nHeight) - pindex->nMatureSat.at(startBlock-1);
  arith_uint256 hashBlock = UintToArith256(pindexCur->GetBlockHash());
  arith_uint256 quotient = hashBlock / moneySupplyUsed;
  arith_uint256 subtractor = moneySupplyUsed*quotient;
  uint64_t winningSat = (hashBlock-subtractor).GetLow64();
  
  uint64_t winningBlockNumber = 0; // number representing the amount of supply created up to that block
  int winningBlockHeight = -1; // the block number / height
  const CBlockIndex * pindexWin = 0;
  for (int i=startBlock; i<=nHeight; i++) {
    //const CBlockIndex * pindexCur = 0;
    /*if (i==nHeight) {
      pindexCur = pindex;
    }
    else if (chainActive.Height() > startBlock-2) {
      pindexCur = chainActive[i];
    }
    else {
      pindexCur = pindex->GetAncestor(i);
      }*/
    if (pindex->nMatureSat.at(i) - pindex->nMatureSat.at(startBlock-1) > winningSat) {
      //LogPrintf("have pindexWin\n");
      pindexWin = pindex->GetAncestor(i-1);
      winningBlockNumber = pindex->nMatureSat.at(i-1) - pindex->nMatureSat.at(startBlock-1);
      winningBlockHeight = i-1;
      break;
    }
  }
  if (!pindexWin) {
    LogPrintf("can't find winning block\n");
    return CKeyID();
  }
  //LogPrintf("nHeight %d moneySupplyUsed %llu winningSat %llu winningBlockNumber %llu winningBlock %u\n",nHeight,moneySupplyUsed,winningSat,winningBlockNumber,winningBlockHeight);

  // iterate transactions in the winning block to find the winning UTXO
  CScript winningUTXO;
  bool haveWinner = false;
  CBlock winningBlock;
  if (ReadBlockFromDisk(winningBlock, pindexWin, params)) {
    unsigned int nTxs = winningBlock.vtx.size();
    uint64_t satoshiCounter = winningBlockNumber;
    for (unsigned int i=0; i<nTxs; i++) {
      CTransactionRef tx = winningBlock.vtx[i];
      unsigned int nOut = tx->vout.size();
      //LogPrintf("tx %u nOut %u\n",i,nOut);
      for (unsigned int j=0; j<nOut; j++) {
	CTxOut out = tx->vout[j];
	satoshiCounter += out.nValue;
	if (satoshiCounter >= winningSat) {
	  winningUTXO = out.scriptPubKey;
	  haveWinner = true;
	  break;
	}
	//LogPrintf("satoshiCounter = %llu\n",satoshiCounter);
      }
      if (haveWinner)
	break;
    }
  }
  if (!haveWinner)
    return CKeyID();
  CTxDestination dest;
  if (!ExtractDestination(winningUTXO,dest)) {
    LogPrintf("can't extract destination\n");
    return CKeyID();
  }
  CKeyID keyID;
  if (!CTcoinAddress(dest).GetKeyID(keyID)) {
    LogPrintf("can't get key id\n");
    return CKeyID();
  }
  return keyID;
}

bool HasHelperBlock(const CBlockIndex* pindex, int nHeight, const Consensus::Params& params) {
  const CBlockIndex* pindexCur = pindex->GetAncestor(nHeight);
  if (!pindexCur)
    return true;
  if (!EnforceProofOfStake(pindexCur->pprev,params))
    return true;
  //int nHeight = pindex->nHeight;
  if (nHeight <= 1)
    return true;
  //LogPrintf("check hasHelperBlock with nMatureSat %llu\n",pindex->nMatureSat.at(nHeight));
  if (pindex->nMatureSat.at(nHeight-1) <= 0)
    return true;

  //LogPrintf("chainActive height = %d\n",chainActive.Height());
  CKeyID winningAddress;
  if (!pindexCur->pprev->winningAddress.IsNull()) {
    winningAddress = pindex->pprev->winningAddress;
  }
  else {
    winningAddress = GetWinningAddress(pindex,pindexCur->pprev->nHeight,params);
  }
  if (winningAddress.IsNull()) {
    LogPrintf("no winning address\n");
    return false;
  }
  CBlock block;
  //LogPrintf("HasHelperBlock: may read block from disk...\n");
  if (pindexCur->pblock) {
    //LogPrintf("have pindex->pblock\n");
    block = *pindexCur->pblock;
  }
  else if (!ReadBlockFromDisk(block,pindexCur,params)) {
    LogPrintf("Can't read block from disk\n");
  }
  //LogPrintf("HasHelperBlock: readblockfrom disk finished\n");
  if (!block.HasHelper()) {
    LogPrintf("block has no helper\n");
    return false;
  }
  const CHelperBlock* phblock = block.GetHelper();
  /*if (phblock->paymentAddress != winningAddress) {
    LogPrintf("Helper block has wrong payment address\n");
    }*/
  CBlock blockPrev;
  if (!ReadBlockFromDisk(blockPrev, pindexCur->pprev, params)) {
    LogPrintf("can't read prev block from disk\n");
    return false;
  }
  uint256 fullHashPrev = blockPrev.GetFullHash();
  if (phblock->hashPrevBlock != fullHashPrev) {
    LogPrintf("hash prev doesn't match\n");
    return false;
  }
  if (!MatchBlockMerkleTree(block,phblock->hashMerkleRoot)) {
    LogPrintf("doesn't match merkle tree\n");
    return false;
  }
  if (!VerifyHelperSignature(phblock,winningAddress)) {
    LogPrintf("bad sig for helper\n");
  }
  LogPrintf("good helper block\n");
  return true;
}

int GetNBlocksWithoutHelper(const CBlockIndex* pindex, const Consensus::Params& params) {
  int n = 0;
  int nHeight = pindex->nHeight;
  while (!HasHelperBlock(pindex,nHeight,params)) {
    n++;
    nHeight--;
  }
  return n;
}

int GetPosPhase (const CBlockIndex* pindex, const Consensus::Params& params) { // Number from 0 to 3 to slowly "phase in" the helper block req
  unsigned int phase = 0;
  CBlockIndex * pindexCur = pindex->pprev;
  int nBlocks = 1;
  while (EnforceProofOfStake(pindexCur,params)) {
    if (nBlocks >= 6048) {
      phase = 3;
      break;
    }
    else if (nBlocks >= 4032) {
      phase = 2;
    }
    else if (nBlocks >= 2016) {
      phase = 1;
    }
    pindexCur = pindexCur->pprev;
    nBlocks++;
  }
  return phase;
}

bool CheckProofOfStakeWork(CBlockIndex* pindex, const Consensus::Params& params) {
  unsigned int nBits = pindex->nBits;
  int nBlocksDiv = 8/mathPow(2,GetPosPhase(pindex,params));
  int nBlocksWithoutHelper = GetNBlocksWithoutHelper(pindex,params)/nBlocksDiv;
  LogPrintf("nBlocksWithoutHelper = %d\n",nBlocksWithoutHelper);
  if (nBlocksWithoutHelper > 0) {
    unsigned int scalingFactor = mathPow(2,nBlocksWithoutHelper);
    // tmp
    scalingFactor = 1;
    arith_uint256 bnBits;
    bnBits.SetCompact(nBits);
    bnBits /= scalingFactor;
    nBits = bnBits.GetCompact();
  }
  pindex->nBlocksWithoutHelper = nBlocksWithoutHelper;
  if (!CheckProofOfWork(pindex->pblock->GetPoWHash(),nBits,params))
    return false;
  return true;
}
