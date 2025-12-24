/*************************************************************************
* Copyright (C) 2013 Intel Corporation
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

/*F*
//    Name: ippsRSAVerify_PKCS1v15_rmf
//
// Purpose: RSASSA-PKCS-v1_5 signature verification with hash method
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMsg == NULL
//                               pSign == NULL
//                               pIsValid == NULL
//                               pKey == NULL
//                               pMethod == NULL
//                               pScratchBuffer == NULL
//    ippStsLengthErr            msgLen < IPPCP_RSA_PKCS1V15_PREHASHED
//    ippStsSizeErr              encoded message length is too long
//    ippStsContextMatchErr      pKey context is invalid
//    ippStsIncompleteContextErr pKey context is not completely initialized
//    ippStsNotSupportedModeErr  hash method is not supported for PKCS#1 v1.5
//    ippStsNoErr                no errors
//
// Parameters:
//    pMsg            pointer to the input message or pre-hashed message digest
//    msgLen          length of the input message in bytes, or IPPCP_RSA_PKCS1V15_PREHASHED 
//                    if pMsg contains a pre-hashed message digest
//    pSign           pointer to the RSA signature to verify
//    pIsValid        pointer to the verification result
//    pKey            pointer to the RSA public key context
//    pMethod         pointer to the hash method context
//    pScratchBuffer  pointer to the scratch buffer for internal computations
//
// Notes:
//    When msgLen == IPPCP_RSA_PKCS1V15_PREHASHED, pMsg must point to a pre-computed
//    hash digest of exactly pMethod->hashLen bytes. Internal hashing is bypassed.
//    When msgLen >= 0, pMsg points to the raw message data and internal hashing is performed.
//
*F*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpngrsa.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"

#include "pcprsa_pkcs1c15_data.h"
#include "pcprsa_verifysign_pkcs1v15.h"
#include "pcprsa_pkcs1v15_preproc.h"

/* clang-format off */
IPPFUN(IppStatus, ippsRSAVerify_PKCS1v15_rmf, (const Ipp8u* pMsg,
                                               int msgLen,
                                               const Ipp8u* pSign,
                                               int* pIsValid,
                                               const IppsRSAPublicKeyState* pKey,
                                               const IppsHashMethod* pMethod,
                                               Ipp8u* pScratchBuffer))
/* clang-format on */
{
    // badargs, pointer alignments, set valid = 0
    const IppStatus preprocResult = SingleVerifyPkcs1v15RmfPreproc(pMsg,
                                                                   msgLen,
                                                                   pSign,
                                                                   pIsValid,
                                                                   &pKey,
                                                                   pMethod,
                                                                   pScratchBuffer);

    if (ippStsNoErr != preprocResult) {
        return preprocResult;
    }

    // Check if message is pre-hashed
    if (msgLen == IPPCP_RSA_PKCS1V15_PREHASHED) {
        return VerifySign(
                   pMsg,
                   pMethod->hashLen,
                   pksc15_salt[pMethod->hashAlgId].pSalt,
                   pksc15_salt[pMethod->hashAlgId].saltLen,
                   pSign,
                   pIsValid,
                   pKey,
                   (BNU_CHUNK_T*)(IPP_ALIGNED_PTR((pScratchBuffer), (int)sizeof(BNU_CHUNK_T))))
                   ? ippStsNoErr
                   : ippStsSizeErr;
    } else {
        Ipp8u md[IPP_SHA512_DIGEST_BITSIZE / BYTESIZE];
        ippsHashMessage_rmf(pMsg, msgLen, md, pMethod);

        return VerifySign(
                   md,
                   pMethod->hashLen,
                   pksc15_salt[pMethod->hashAlgId].pSalt,
                   pksc15_salt[pMethod->hashAlgId].saltLen,
                   pSign,
                   pIsValid,
                   pKey,
                   (BNU_CHUNK_T*)(IPP_ALIGNED_PTR((pScratchBuffer), (int)sizeof(BNU_CHUNK_T))))
                   ? ippStsNoErr
                   : ippStsSizeErr;
    }
}
