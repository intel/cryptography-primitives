/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#include "owndefs.h"
#include "xmss_internal/xmss.h"

/*F*
//    Name: ippsXMSSVerify
//
// Purpose: XMSS signature verification.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pSign == NULL
//                            pIsSignValid == NULL
//                            pKey == NULL
//                            pBuffer == NULL
//    ippStsLengthErr         msgLen < 1
//    ippStsLengthErr         msgLen > IPP_MAX_32S - (numTempBufs + len) * n
//    ippStsNoErr             no errors
//
// Parameters:
//    pMsg           pointer to the message data buffer
//    msgLen         message buffer length
//    pSign          pointer to the XMSS signature
//    pIsSignValid   1 if signature is valid, 0 - vice versa
//    pKey           pointer to the XMSS public key
//    pBuffer        pointer to the temporary memory
//
*F*/
IPPFUN(IppStatus, ippsXMSSVerify,( const Ipp8u* pMsg,
                                   const Ipp32s msgLen,
                                   const IppsXMSSSignatureState* pSign,
                                   int* pIsSignValid,
                                   const IppsXMSSPublicKeyState* pKey,
                                   Ipp8u* pBuffer))
{
    IppStatus retCode = ippStsNoErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR4_RET(pMsg, pSign, pIsSignValid, pKey)
    /* Check if temporary buffer is NULL */
    IPP_BAD_PTR1_RET(pBuffer)
    /* Check msg length */
    IPP_BADARG_RET(msgLen < 1, ippStsLengthErr)
    *pIsSignValid = 0;

    /* Parameters of the current XMSS */
    Ipp32s h = 0;
    cpWOTSParams params;
    retCode = cp_xmss_set_params(pKey->OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    Ipp32s len = params.len;
    Ipp32s n = params.n;
    const Ipp32s numTempBufs = 10;
    IPP_BADARG_RET(msgLen > (Ipp32s)(IPP_MAX_32S) - (numTempBufs + len) * n, ippStsLengthErr);

// description of internals for OTS Hash / L-tree / Hash tree address is following
// +-----------------------------------------------------+
// | layer address                              (32 bits)|
// +-----------------------------------------------------+
// | tree address                               (64 bits)|
// +-----------------------------------------------------+
// | type = 0 / 1 / 2                           (32 bits)|
// +-----------------------------------------------------+
// | OTS address / L-tree address / Padding = 0 (32 bits)|
// +-----------------------------------------------------+
// | chain address / tree height                (32 bits)|
// +-----------------------------------------------------+
// | hash address / tree index                  (32 bits)|
// +-----------------------------------------------------+
// | keyAndMask                                 (32 bits)|
// +-----------------------------------------------------+
    Ipp8u adrs[ADRS_SIZE] = { 0, 0, 0, 0,             //  0; 4
                              0, 0, 0, 0, 0, 0, 0, 0, //  4; 12
                              0, 0, 0, 0,             // 12; 16
                              0, 0, 0, 0,             // 16; 20
                              0, 0, 0, 0,             // 20; 24
                              0, 0, 0, 0,             // 24; 28
                              0, 0, 0, 0              // 28; 32
    };

    Ipp32u idx = pSign->idx;

    Ipp8u* pMsg_ = pBuffer;
    Ipp8u* temp_key = pBuffer + n;
    Ipp8u* temp_buf = pBuffer + n + (len * n);

    // byte[n] M_ = H_msg(r || getRoot(PK) || (toByte(idx_sig, n)), M);
    cp_to_byte(temp_buf, n, /*h_msg padding id*/ 2);
    CopyBlock(pSign->r, temp_buf + n, n);
    CopyBlock(pKey->pRoot, temp_buf + 2 * n, n);
    cp_to_byte(temp_buf + 3 * n, n, idx);
    CopyBlock(pMsg, temp_buf + 4 * n, msgLen);

    retCode = ippsHashMessage_rmf(temp_buf, 4 * n + msgLen, pMsg_,
        params.hash_method);

    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    cp_xmss_set_ots_address(adrs, idx);

    // 1. get ots public key working with msg and ots signature
    retCode = cp_xmss_WOTS_pkFromSig(pMsg_, pSign->pOTSSign, pKey->pSeed, adrs, temp_key, temp_buf, &params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    cp_xmss_set_tree_type(adrs, /*L-tree*/ 1);
    retCode = cp_xmss_ltree(temp_key, pKey->pSeed, adrs, temp_buf, &params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    // 2. do hashing using authorization path
    cp_xmss_set_tree_type(adrs, /*hash tree*/ 2);

    cp_xmss_set_ots_address(adrs, 0);

    for(Ipp32s i = 0; i < h; ++i){
        cp_xmss_set_tree_height(adrs, (Ipp8u) i);
        // if we are the left child
        if (((pSign->idx / (1 << i)) & 1) == 0) {
            // leaf || auth_path
            CopyBlock(temp_key, temp_buf, n);
            CopyBlock(pSign->pAuthPath + (i * n), temp_buf + n, n);
        }
        else {
            // auth_path || leaf
            CopyBlock(pSign->pAuthPath + (i * n), temp_buf, n);
            CopyBlock(temp_key, temp_buf + n, n);
        }

        idx /= 2;
        cp_xmss_set_tree_index_32(adrs, idx);

        retCode = cp_xmss_rand_hash(temp_buf, temp_buf + n, pKey->pSeed, adrs, temp_key, temp_buf + 2 * n, &params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    }

    // 3. verify with public key
    BNU_CHUNK_T is_equal = cpIsEquBlock_ct(pKey->pRoot, temp_key, n);
    if(is_equal) {
        *pIsSignValid = 1;
    }
    return retCode;
}
