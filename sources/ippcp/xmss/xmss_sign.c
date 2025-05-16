/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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
//    Name: ippsXMSSSign
//
// Purpose: XMSS signature generation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pPrvKey == NULL
//                            pSign == NULL
//                            pBuffer == NULL
//    ippStsLengthErr         msgLen < 1
//    ippStsLengthErr         msgLen > IPP_MAX_32S - (n + 5 * n + len + key_gen_size)
//    ippStsOutOfRangeErr     index of current secret key is greater then number of keys
//    ippStsNoErr             no errors
//
// Parameters:
//    pMsg           pointer to the message data buffer
//    msgLen         message buffer length
//    pPrvKey        pointer to the XMSS private key
//    pSign          pointer to the XMSS signature
//    pBuffer        pointer to the temporary memory
//
*F*/
IPPFUN(IppStatus, ippsXMSSSign,( const Ipp8u* pMsg,
                                 const Ipp32s msgLen,
                                 IppsXMSSPrivateKeyState* pPrvKey,
                                 IppsXMSSSignatureState* pSign,
                                 Ipp8u* pBuffer))
{
    IppStatus retCode = ippStsNoErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR3_RET(pMsg, pPrvKey, pSign)
    /* Check if temporary buffer is NULL */
    IPP_BAD_PTR1_RET(pBuffer)
    /* Check msg length */
    IPP_BADARG_RET(msgLen < 1, ippStsLengthErr)

    /* Parameters of the current XMSS */
    Ipp32s h = 0;
    cpWOTSParams params;
    retCode = cp_xmss_set_params(pPrvKey->OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    Ipp32s len = params.len;
    Ipp32s n = params.n;

    Ipp32s key_gen_size;
    retCode = ippsXMSSKeyGenBufferGetSize(&key_gen_size, pPrvKey->OIDAlgo);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    IPP_BADARG_RET(msgLen > (Ipp32s)(IPP_MAX_32S) - (n + 5 * n + len + key_gen_size), ippStsLengthErr);

    Ipp32s pBufferSize;
    retCode = ippsXMSSSignBufferGetSize(&pBufferSize, msgLen, pPrvKey->OIDAlgo);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

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
    // idx
    pSign->idx = pPrvKey->idx;

    // fill r
    Ipp8u* idx_buf = pBuffer;
    cp_to_byte(idx_buf, n, pPrvKey->idx);
    retCode = cp_xmss_prf(pPrvKey->pSK_PRF, idx_buf, pSign->r, idx_buf + n, &params);
    if(ippStsNoErr != retCode) {
        PurgeBlock(pBuffer, pBufferSize);
        return retCode;
    }

    // byte[n] M_ = H_msg(r || getRoot(PK) || (toByte(idx_sig, n)), M);
    Ipp8u* pMsg_ = pBuffer;
    Ipp8u* temp_buf = pMsg_ + n;

    cp_to_byte(temp_buf, n, /*h_msg padding id*/ 2);
    CopyBlock(pSign->r, temp_buf + n, n);
    CopyBlock(pPrvKey->pRoot, temp_buf + 2 * n, n);
    cp_to_byte(temp_buf + 3 * n, n, pPrvKey->idx);
    CopyBlock(pMsg, temp_buf + 4 * n, msgLen);

    retCode = ippsHashMessage_rmf(temp_buf, 4 * n + msgLen, pMsg_, params.hash_method);
    if(ippStsNoErr != retCode) {
        PurgeBlock(pBuffer, pBufferSize);
        return retCode;
    }

    // pAuthPath
    retCode = cp_xmss_tree_hash(/*isKeyGen*/ 0, pPrvKey, adrs, pSign->pAuthPath, pPrvKey->idx, temp_buf, h, &params);
    if(ippStsNoErr != retCode) {
        PurgeBlock(pBuffer, pBufferSize);
        return retCode;
    }

    // pOTSSign
    cp_to_byte(adrs, ADRS_SIZE, 0);
    cp_xmss_set_tree_type(adrs, /*OTS hash*/ 0);
    cp_xmss_set_ots_address(adrs, /*setOTSAddress*/ pPrvKey->idx);
    retCode = cp_xmss_WOTS_sign(pMsg_, pPrvKey->pSecretSeed, pSign->pOTSSign, pPrvKey->pPublicSeed, adrs, temp_buf, &params);

    // zeroize the temporary memory if everything else was successful
    PurgeBlock(pBuffer, pBufferSize);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    // during the next call another private key should be used to sign
    pPrvKey->idx++;

    // pass the error if we are out of secret keys
    // Note: there is no overflow since the maximum value for h is 20 according to the Spec
    if(pPrvKey->idx == (Ipp32u)(1 << h)) {
        return ippStsOutOfRangeErr;
    }

    return retCode;
}
