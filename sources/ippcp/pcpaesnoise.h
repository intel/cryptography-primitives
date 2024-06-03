/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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

#if !defined(_PCP_AES_NOISE_H)
#define _PCP_AES_NOISE_H

/*
 * The parameters below are empirical and chosen in advance to guarantee
 * the high level of security protection against Mistletoe3 attack.
 */
#define MISTLETOE3_MAX_CHUNK_SIZE   (16000)     /* maximum chunks size allowed to be processed without noise injection (in bytes) \
                                                   16000 bytes = 16*1000 bytes = 1000 AES blocks */
#define MISTLETOE3_TARGET_SIZE      (800000000) /* expected sampling interval of the attacker. During the attack \
                                                   the adversary measures how long it takes to encrypt MISTLETOE3_TARGET_SIZE of bytes. \
                                                   MISTLETOE3_TARGET_SIZE is much greater than MISTLETOE3_MAX_CHUNK_SIZE \
                                                   800000000 bytes = 16*50000000 bytes = 50000000 AES blocks */
#define MISTLETOE3_BASE_NOISE_LEVEL (28)        /* noiseLevel adjusts the random number of what bitsize will be generated, this number will be \
                                                   used as a parameter for _ippcpDelay function. Level of noise needed depends on many factors, such \
                                                   as processor, code implementation, power limit setting by the attacker, etc. \
                                                   For base noise level was selected a relatively safe value of 28, for user this parameter was \
                                                   introduced as abstract with tunable range [0,4] */

#define MISTLETOE3_NOISE_RATE     ((double)MISTLETOE3_MAX_CHUNK_SIZE / \
                                   (double)MISTLETOE3_TARGET_SIZE)

/* Structure containing noise parameters required for Mistletoe3 mitigation */
typedef struct _cpAESNoiseParams {
  Ipp32u rnd;         /* Random number value from previous noise injection */
  Ipp32u noiseLevel;  /* Number of bits that should be taken from generated \
                         32-bit random value. noiseLevel == 0 -> mitigation is off */
} cpAESNoiseParams;

#define AES_NOISE_RAND(ctx)           ((ctx)->rnd)
#define AES_NOISE_LEVEL(ctx)          ((ctx)->noiseLevel)

/* size of _cpAESNoiseParams structure */
__IPPCP_INLINE int cpSizeofNoise_Params(void)
{
   return sizeof(cpAESNoiseParams);
}

#define _ippcpDelay  OWNAPI(_ippcpDelay)
   IPP_OWN_DECL(void, _ippcpDelay, (Ipp32u value))

#define cpAESRandomNoise  OWNAPI(cpAESRandomNoise)
   IPP_OWN_DECL(IppStatus, cpAESRandomNoise, (IppBitSupplier rndFunc, Ipp32u nBits, Ipp64f noiseRate, Ipp32u *pRndValue))

#endif /* _PCP_AES_NOISE_H */
