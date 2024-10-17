/*************************************************************************
* Copyright (C) 2016 Intel Corporation
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
//     Cryptography Primitive.
//     RSAES-OAEP Encryption/Decryption Functions
//
//  Contents:
//        ippsRSADecrypt_OAEP_rmf()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcptool.h"
#include "pcpngrsa.h"
#include "hash/pcphash_rmf.h"

// ICX compiler optimizations lead to incorrect execution on windows
#if(_IPP32E>=_IPP32E_K0) && defined (__INTEL_LLVM_COMPILER) && defined( _WIN64 )
#pragma optimize( "", off )
#endif

/*F*
// Name: ippsRSADecrypt_OAEP_rmf
//
// Purpose: Performs RSAES-OAEP decryprion scheme
//
// Returns:                   Reason:
//    ippStsNotSupportedModeErr  unknown hashAlg
//
//    ippStsNullPtrErr           NULL == pKey
//                               NULL == pSrc
//                               NULL == pLab
//                               NULL == pDst
//                               NULL == pDstLen
//                               NULL == pMethod
//                               NULL == pBuffer
//
//    ippStsLengthErr            labLen <0
//                               RSAsize < 2*hashLen +2
//
//    ippStsIncompleteContextErr private key is not set up
//
//    ippStsContextMatchErr      !RSA_PRV_KEY_VALID_ID()
//
//    ippStsOutOfRangeErr        ciphertext > RSA(N)
//
//    ippStsUnderRunErr          decoding error
//
//    ippStsNoErr                no error
//
// Parameters:
//    pSrc        pointer to the ciphertext
//                assumed that length of the ciphertext is equal to k - sizeof RSA modulus in bytes
//    pLab        (optional) pointer to the label associated with plaintext
//    labLen      label length (bytes)
//    pDst        pointer to the encoded plaintext
//                assumed that length of the recovered message is at least k-hashLen*2-2 bytes;
//                maximum message length is (k-hashLen*2-2) bytes and is for chosen RSA and Hash-function
//    pDstLen     pointer to the plaintext length
//    pKey        pointer to the RSA private key context
//    pMethod     hash methods
//    pBuffer     pointer to scratch buffer
*F*/
IPPFUN(IppStatus, ippsRSADecrypt_OAEP_rmf, (const Ipp8u* pSrc,
                                            const Ipp8u* pLab, int labLen,
                                                  Ipp8u* pDst, int* pDstLen,
                                            const IppsRSAPrivateKeyState* pKey,
                                            const IppsHashMethod* pMethod,
                                                  Ipp8u* pScratchBuffer))
{
   int hashLen;

   /* test data pointer */
   IPP_BAD_PTR4_RET(pSrc, pDst, pDstLen, pMethod);

   IPP_BADARG_RET(!pLab && labLen, ippStsNullPtrErr);

   IPP_BAD_PTR2_RET(pKey, pScratchBuffer);
   IPP_BADARG_RET(!RSA_PRV_KEY_VALID_ID(pKey), ippStsContextMatchErr);
   IPP_BADARG_RET(!RSA_PRV_KEY_IS_SET(pKey), ippStsIncompleteContextErr);

   /* test hash length */
   IPP_BADARG_RET(labLen < 0, ippStsLengthErr);

   hashLen = pMethod->hashLen;
   /* test compatibility of RSA and hash length */
   IPP_BADARG_RET(BITS2WORD8_SIZE(RSA_PRV_KEY_BITSIZE_N(pKey)) < (2 * hashLen + 2), ippStsLengthErr);

   {
      /* size of RSA modulus in bytes and chunks */
      int k = BITS2WORD8_SIZE(RSA_PRV_KEY_BITSIZE_N(pKey));
      cpSize nsN = BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_N(pKey));

      /* align resource */
      BNU_CHUNK_T* pResource = (BNU_CHUNK_T*)(IPP_ALIGNED_PTR(pScratchBuffer, (int)sizeof(BNU_CHUNK_T)));

      /* temporary BN */
      __ALIGN8 IppsBigNumState tmpBN;
      BN_Make(pResource, pResource+nsN+1, nsN, &tmpBN);
      pResource += (nsN + 1) * 2;              /* update buffer pointer */
      ippsSetOctString_BN(pSrc, k, &tmpBN);  /* convert ciphertext to BigNum */
      /* make sure ciphertext < RSA modulus N */
      IPP_BADARG_RET(0 <= cpCmp_BNU(BN_NUMBER(&tmpBN), BN_SIZE(&tmpBN),
         MOD_MODULUS(RSA_PRV_KEY_NMONT(pKey)), MOD_LEN(RSA_PRV_KEY_NMONT(pKey))), ippStsOutOfRangeErr);

      /* RSA decryption */
      if (RSA_PRV_KEY1_VALID_ID(pKey))
         gsRSAprv_cipher(&tmpBN, &tmpBN, pKey, pResource);
      else
         gsRSAprv_cipher_crt(&tmpBN, &tmpBN, pKey, pResource);

      /*
      // EME-OAEP decoding
      */
      {
         Ipp8u* pEM = (Ipp8u*)(BN_BUFFER(&tmpBN));
         Ipp8u* pBuffer = (Ipp8u*)BN_NUMBER(&tmpBN);

         int i;
         /* convert RSA encoded into EM */
         for (i = 0; i < k; i++) {
            pEM[i] = pBuffer[k-1-i];
         }

         /*
         // OAEP EM decoding, EM = Y || maskedSeed || maskedDB
         */
         {
            /* check that Y == 0 */
            BNU_CHUNK_T res = cpIsZero_ct(pEM[0]);

            Ipp8u* pSeed = pEM + 1;
            Ipp8u* pDB   = pEM + 1 + hashLen; /* DB = lHash || PS || Msg */
            int dbLen = k - 1 - hashLen;
            int maxMsgLen = dbLen - hashLen - 1;

            /* seed = maskedSeed ^ seedMask, seedMask = MGF(maskedDB, hashLen) */
            ippsMGF1_rmf(pDB, dbLen, pBuffer, hashLen, pMethod);
            XorBlock(pSeed, pBuffer, pSeed, hashLen);

            /* DB = maskedDB ^ dbMask, dbMask = MGF (seed, dbLen) */
            ippsMGF1_rmf(pSeed, hashLen, pBuffer, dbLen, pMethod);
            XorBlock(pDB, pBuffer, pDB, dbLen);

            /* re-compute Hash(Label) and compare with lHash */
            ippsHashMessage_rmf(pLab, labLen, pBuffer, pMethod);
            res &= cpIsEquBlock_ct(pDB, pBuffer, hashLen);

            /* detect the padding consists of a number of 0x00-bytes, followed by a 0x01 */
            BNU_CHUNK_T byte_01_found = 0;
            BNU_CHUNK_T byte_01_idx = 0;
            for (i = hashLen; i < dbLen; i++) {
               BNU_CHUNK_T byte_00 = cpIsZero_ct(pDB[i]);        /* mask if byte is 0x00 */
               BNU_CHUNK_T byte_01 = cpIsZero_ct(pDB[i] ^ 0x01);   /* mask if byte is 0x01 */
               /* set index of byte 01_idx if byte 01 found */
               byte_01_idx = cpSelect_ct(~byte_01_found & byte_01, (BNU_CHUNK_T)i, byte_01_idx);
               /* set flag byte_01_found */
               byte_01_found |= byte_01;
               /* update EM encoding result */
               res &= (byte_01_found | byte_00);
            }
            /* update EM encoding result if byte_01_found */
            res &= byte_01_found;

            /* copy decoded message to pDst */
            {
               /* move decoded message by (maxMsgLen-msgLen) left
               */
               int msgIdx = (int)byte_01_idx + 1; /* decoded message index inside DB */
               int msgLen = dbLen - msgIdx;  /* length of decoded message */

               BNU_CHUNK_T mask;
               for(msgIdx = 1; msgIdx < maxMsgLen; msgIdx <<= 1) {
                  mask = cpIsEqu_ct((BNU_CHUNK_T)(msgIdx & (maxMsgLen - msgLen)), (BNU_CHUNK_T)msgIdx);
                  for(i = hashLen+1; i < (dbLen-msgIdx); i++)
                     pDB[i] = cpSelect_ct_8u(mask, pDB[i + msgIdx], pDB[i]);
               }

               /* copy decoded message */
               for(i = 0; i < maxMsgLen; i++) {
                  mask = res & cpIsLt_ct((BNU_CHUNK_T)i, (BNU_CHUNK_T)msgLen);
                  pDst[i] = cpSelect_ct_8u(mask, pDB[i + hashLen + 1], pDst[i]);
               }

               /* decoded message length */
               *pDstLen = cpSelect_ct_int(res, msgLen, -1);
            }

            /* clean */
            PurgeBlock(pEM, k);
            PurgeBlock(pBuffer, k);

            /* return error status if is */
            return (IppStatus)cpSelect_ct_int(res, ippStsNoErr, ippStsUnderRunErr);
         }
      }
   }
}

#if(_IPP32E>=_IPP32E_K0) && defined (__INTEL_LLVM_COMPILER) && defined( _WIN64 )
#pragma optimize( "", on )
#endif
