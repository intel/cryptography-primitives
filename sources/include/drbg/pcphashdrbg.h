/*************************************************************************
* Copyright (C) 2026 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

/*
//  Purpose:
//     Hash DRBG state, internal definitions and function declarations
*/

#if !defined(_CP_HASHDRBG_H)
#define _CP_HASHDRBG_H

#define HASH_DRBG_MIN_SEED_BITS_LEN 440
#define HASH_DRBG_MAX_SEED_BITS_LEN 888

#define HASH_DRBG_MIN_SEED_BYTES_LEN (HASH_DRBG_MIN_SEED_BITS_LEN / 8)
#define HASH_DRBG_MAX_SEED_BYTES_LEN (HASH_DRBG_MAX_SEED_BITS_LEN / 8)

#define HASH_DRBG_MIN_SEC_STRENGTH      128
#define HASH_DRBG_SEC_STRENGTH_192      192
#define HASH_DRBG_MAX_BITS_SEC_STRENGTH 256

/* Constants of maximum values according to the NIST.SP.800-90Ar1
   Table 2: "Definitions for Hash-Based DRBG Mechanisms". */
/* MAX_INPUT_LEN for personalization_string, additional_input and
   entropy_input equals to 2^35 bits. To avoid overflowing, use maximum integer
   value (2^31 - 1) since the lengths of the input arrays are passed as int */
#define MAX_INPUT_LEN (~(1 << 31)) // (2^31 - 1) bits
/* MAX_RESEED_INTERVAL equals to 2^48,
   MAX_BITS_NUMBER_PER_REQUEST equals to 2^19 bits.
   Lower these two values to the minimum allowed values since
   the limits set in 90A are unreasonably big */
#define MAX_RESEED_INTERVAL         (Ipp64u)(1ul << 24) // 2^24
#define MAX_BITS_NUMBER_PER_REQUEST (1 << 16)           // 2^16 bits

struct _cpHashDRBG {
    Ipp32u idCtx;                                       /* DRBG identifier */
    int seedBitsLen;                                    /* Secret values length */
    Ipp32u securityStrength;      /* Security strength of the DRBG instantiation */
    int predictionResistanceFlag; /* Indicates whether or not prediction resistance may be required by
                                      the consuming application during requests for pseudorandom bits */
    int hashStateSize_rmf;        /* The size of hashState */
    Ipp64u reseedCounter;         /* Indicates the number of requests for pseudorandom bits
                                      since new entropy_input was obtained during
                                      instantiation or reseeding */
    IppsHashMethod* pHashMethod;  /* Hash method used by the DRBG mechanism; ippsHashMethod_SHA256()
                                      is set by default if no hash method was passed */
    Ipp8u* V;                     /* Secret values (stores one extra byte at the very beginning) */
    Ipp8u* C;                     /* Secret values */
    Ipp8u* tempBuf;               /* Temporary buffer to store the values of V
                                      (also like V, stores one extra byte) */
    IppsHashState_rmf* hashState; /* Pointer to IppsHashState_rmf context */
    Ipp8u* hashOutputBuf;         /* Buffer to store hash output digest */
};

#define HASH_DRBG_SET_ID(ctx)       ((ctx)->idCtx = (Ipp32u)idCtxHashDRBG ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define HASH_DRBG_SEEDBITS_LEN(ctx) ((ctx)->seedBitsLen)
/* Extended size for V and tempBuf */
#define HASH_DRBG_SEEDBITS_LEN_EXT(ctx)     ((ctx)->seedBitsLen + 8)
#define HASH_DRBG_RESEED_COUNTER(ctx)       ((ctx)->reseedCounter)
#define HASH_DRBG_SECURITY_STRENGTH(ctx)    ((ctx)->securityStrength)
#define HASH_DRBG_PRED_RESISTANCE_FLAG(ctx) ((ctx)->predictionResistanceFlag)
#define HASH_DRBG_HASH_STATE_SIZE(ctx)      ((ctx)->hashStateSize_rmf)

#define HASH_DRBG_VALID_ID(ctx) \
    ((((ctx)->idCtx) ^ (Ipp32u)IPP_UINT_PTR((ctx))) == (Ipp32u)idCtxHashDRBG)

#define cpHashDRBG_GetEntropyInput OWNAPI(cpHashDRBG_GetEntropyInput)
IPP_OWN_DECL(IppStatus,
             cpHashDRBG_GetEntropyInput,
             (const int minEntropy,
              const int predictionResistanceRequest,
              int* pEntrInputBitsLen,
              IppsHashDRBG_EntropyInputCtx* pEntrInputCtx))
#define cpHashDRBG_df OWNAPI(cpHashDRBG_df)
IPP_OWN_DECL(IppStatus,
             cpHashDRBG_df,
             (const Ipp8u* inputParam1,
              const cpSize inputParam1Len,
              const Ipp8u* inputParam2,
              const cpSize inputParam2Len,
              const Ipp8u* inputParam3,
              const cpSize inputParam3Len,
              Ipp8u* requestedBits,
              const cpSize nBitsToReturn,
              IppsHashDRBGState* drbgCtx))
#define cpHashDRBG_Gen OWNAPI(cpHashDRBG_Gen)
IPP_OWN_DECL(IppStatus,
             cpHashDRBG_Gen,
             (Ipp32u * pRand,
              int randBytesLen,
              const int predictionResistanceRequest,
              const Ipp8u* additionalInput,
              const int additionalInputLen,
              IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
              IppsHashDRBGState* pDrbg))

#endif /* _CP_HASHDRBG_H */
