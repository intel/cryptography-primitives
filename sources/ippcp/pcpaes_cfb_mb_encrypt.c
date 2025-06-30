/*************************************************************************
* Copyright (C) 2020 Intel Corporation
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
//
//  Purpose:
//     Cryptography Primitive.
//     AES Multi Buffer Encryption (CFB mode)
//
//  Contents:
//        ippsAES_EncryptCFB16_MB()
//
*/

#include "owncp.h"
#include "pcpaesm.h"
#include "aes_cfb_vaes_mb.h"
#include "aes_cfb_aesni_mb.h"


/*!
 *  \brief ippsAES_EncryptCFB16_MB
 *
 *  Name:         ippsAES_EncryptCFB16_MB
 *
 *  Purpose:      AES-CFB16 Multi Buffer Encryption
 *
 *  Parameters:
 *    \param[in]   pSrc                 Pointer to the array of source data
 *    \param[out]  pDst                 Pointer to the array of target data
 *    \param[in]   len                  Pointer to the array of input buffer lengths (in bytes)
 *    \param[in]   pCtx                 Pointer to the array of AES contexts
 *    \param[in]   pIV                  Pointer to the array of initialization vectors (IV)
 *    \param[out]  status               Pointer to the IppStatus array that contains status
 *                                      for each processed buffer in encryption operation
 *    \param[in]   numBuffers           Number of buffers to be processed
 *
 *  Returns:                          Reason:
 *    \return ippStsNullPtrErr            Indicates an error condition if any of the specified pointers is NULL:
 *                                        NULL == pSrc
 *                                        NULL == pDst
 *                                        NULL == len
 *                                        NULL == pCtx
 *                                        NULL == pIV
 *                                        NULL == status
 *    \return ippStsContextMatchErr       Indicates an error condition if input buffers have different key sizes
 *    \return ippStsLengthErr             Indicates an error condition if numBuffers < 1
 *    \return ippStsErr                   One or more of performed operation executed with error
 *                                        Check status array for details
 *    \return ippStsNoErr                 No error
 */

/* Work Load Size from Buffers */
#define WORKLOAD_LINES_16 (AES_MB_MAX_KERNEL_SIZE)     /* size 16 */
#define WORKLOAD_LINES_8  (AES_MB_MAX_KERNEL_SIZE / 2) /* size  8 */
#define WORKLOAD_LINES_4  (AES_MB_MAX_KERNEL_SIZE / 4) /* size  4 */


/* clang-format off */
IPPFUN(IppStatus, ippsAES_EncryptCFB16_MB, (const Ipp8u* pSrc[],
                                            Ipp8u* pDst[],
                                            int len[],
                                            const IppsAESSpec* pCtx[],
                                            const Ipp8u* pIV[],
                                            IppStatus status[],
                                            int numBuffers))
/* clang-format on */
{
    int i;

    // Check input pointers
    IPP_BAD_PTR2_RET(pCtx, pIV);
    IPP_BAD_PTR4_RET(pSrc, pDst, len, status);

    // Check number of buffers to be processed
    IPP_BADARG_RET((numBuffers < 1), ippStsLengthErr);

    // Sequential check of all input buffers
    int isAllBuffersValid = 1;
    for (i = 0; i < numBuffers; i++) {
        // Test source, target buffers and initialization pointers
        if (pSrc[i] == NULL || pDst[i] == NULL || pIV[i] == NULL || pCtx[i] == NULL) {
            status[i]         = ippStsNullPtrErr;
            isAllBuffersValid = 0;
            continue;
        }

        // Test the context ID
        if (!VALID_AES_ID(pCtx[i])) {
            status[i]         = ippStsContextMatchErr;
            isAllBuffersValid = 0;
            continue;
        }

        // Test stream length
        if (len[i] < 1) {
            status[i]         = ippStsLengthErr;
            isAllBuffersValid = 0;
            continue;
        }

        // Test stream integrity
        if ((len[i] % CFB16_BLOCK_SIZE)) {
            status[i]         = ippStsUnderRunErr;
            isAllBuffersValid = 0;
            continue;
        }

        status[i] = ippStsNoErr;
    }

    // If any of the input buffer is not valid stop the processing
    IPP_BADARG_RET(!isAllBuffersValid, ippStsErr)

    // Check compatibility of the keys
    int referenceKeySize = RIJ_NK(pCtx[0]);
    for (i = 0; i < numBuffers; i++) {
        IPP_BADARG_RET((RIJ_NK(pCtx[i]) != referenceKeySize), ippStsContextMatchErr);
    }

#if (_IPP32E >= _IPP32E_Y8)
    Ipp32u const* loc_enc_keys[AES_MB_MAX_KERNEL_SIZE];
    Ipp8u const* loc_src[AES_MB_MAX_KERNEL_SIZE];
    Ipp8u* loc_dst[AES_MB_MAX_KERNEL_SIZE];
    Ipp8u const* loc_iv[AES_MB_MAX_KERNEL_SIZE];
    int loc_len[AES_MB_MAX_KERNEL_SIZE];
    int buffersProcessed = 0;
    int numRounds        = 0;
#endif

#if (_IPP32E >= _IPP32E_K1)
    if (IsFeatureEnabled(ippCPUID_AVX512VAES)) {
        int workLoadSize = 0;
        while (numBuffers > 0) {
            /* init work load size */
            if (numBuffers > WORKLOAD_LINES_8) {                           /* size 16 */
                workLoadSize = WORKLOAD_LINES_16;
            } else if (numBuffers > WORKLOAD_LINES_4 &&
                       numBuffers <= WORKLOAD_LINES_8) {                   /* size  8 */
                workLoadSize = WORKLOAD_LINES_8;
            } else if (numBuffers > 0 && numBuffers <= WORKLOAD_LINES_4) { /* size  4 */
                workLoadSize = WORKLOAD_LINES_4;
            } else {
                break;
            }

            /* fill buffers */
            for (i = 0; i < workLoadSize; i++) {
                if (i >= numBuffers) {
                    loc_len[i] = 0;
                    continue;
                }

                loc_src[i]      = pSrc[i + buffersProcessed];
                loc_dst[i]      = pDst[i + buffersProcessed];
                loc_iv[i]       = pIV[i + buffersProcessed];
                loc_enc_keys[i] = (Ipp32u*)RIJ_EKEYS(pCtx[i + buffersProcessed]);
                loc_len[i]      = len[i + buffersProcessed];
                /* As numRounds is the same for all buffers, get it from the last one */
                numRounds = RIJ_NR(pCtx[i + buffersProcessed]);
            }

            /* choosing a core for filled buffers */
            switch (workLoadSize) {
            case WORKLOAD_LINES_16: {
                aes_cfb16_enc_vaes_mb16(loc_src, loc_dst, loc_len, numRounds, loc_enc_keys, loc_iv);
                break;
            }
            case WORKLOAD_LINES_8: {
                aes_cfb16_enc_vaes_mb8(loc_src, loc_dst, loc_len, numRounds, loc_enc_keys, loc_iv);
                break;
            }
            case WORKLOAD_LINES_4: {
                aes_cfb16_enc_vaes_mb4(loc_src, loc_dst, loc_len, numRounds, loc_enc_keys, loc_iv);
                break;
            }
            default:
                break;
            }

            /* changing the remaining buffers for processing */
            numBuffers -= workLoadSize;
            buffersProcessed += workLoadSize;
        }
    }
#endif // if(_IPP32E>=_IPP32E_K1)

#if (_IPP32E >= _IPP32E_Y8)
    if (IsFeatureEnabled(ippCPUID_AES)) {
        while (numBuffers > 0) {
            for (i = 0; i < WORKLOAD_LINES_4; i++) {
                if (i >= numBuffers) {
                    loc_len[i] = 0;
                    continue;
                }

                loc_src[i]      = pSrc[i + buffersProcessed];
                loc_dst[i]      = pDst[i + buffersProcessed];
                loc_iv[i]       = pIV[i + buffersProcessed];
                loc_enc_keys[i] = (Ipp32u*)RIJ_EKEYS(pCtx[i + buffersProcessed]);
                loc_len[i]      = len[i + buffersProcessed];
                /* As numRounds is the same for all buffers, get it from the last one */
                numRounds = RIJ_NR(pCtx[i + buffersProcessed]);
            }

            aes_cfb16_enc_aesni_mb4(loc_src, loc_dst, loc_len, numRounds, loc_enc_keys, loc_iv);
            numBuffers -= WORKLOAD_LINES_4;
            buffersProcessed += WORKLOAD_LINES_4;
        }
    }
#endif // (_IPP32E>=_IPP32E_Y8)

    for (i = 0; i < numBuffers; i++) {
        status[i] = ippsAESEncryptCFB(pSrc[i], pDst[i], len[i], CFB16_BLOCK_SIZE, pCtx[i], pIV[i]);
    }

    for (i = 0; i < numBuffers; i++) {
        if (status[i] != ippStsNoErr) {
            return ippStsErr;
        }
    }

    return ippStsNoErr;
}

#undef WORKLOAD_LINES_16
#undef WORKLOAD_LINES_8
#undef WORKLOAD_LINES_4
