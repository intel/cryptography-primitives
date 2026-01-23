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
//
//  Purpose:
//     Cryptography Primitive.
//     RSA Functions
//
//  Contents:
//        ippsRSA_SetPublicKeyPart()
//
*/

#include "owncp.h"
#include "pcpbn.h"
#include "pcpngrsa.h"

/*F*
// Name: ippsRSA_SetPublicKeyPart
//
// Purpose: Set up a specific part of the RSA public key
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pKey
//                               NULL == pValue
//
//    ippStsContextMatchErr     !BN_VALID_ID(pValue)
//                              !RSA_PUB_KEY_VALID_ID(pKey)
//
//    ippStsBadArgErr            invalid keyTag parameter for public key
//
//    ippStsOutOfRangeErr        0 >= pValue
//
//    ippStsSizeErr              bitsize(pValue) exceeds requested value for the part
//
//    ippStsNoErr                no error
//
// Parameters:
//    keyTag         which part of the key to set (ippRSAkeyN or ippRSAkeyE)
//    pValue         pointer to the big number value for this part
//    pKey           pointer to the key context
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsRSA_SetPublicKeyPart, (IppRSAKeyTag keyTag,
                                             const IppsBigNumState* pValue,
                                             IppsRSAPublicKeyState* pKey))
/* clang-format on */
{
    /* test public key context */
    IPP_BAD_PTR1_RET(pKey);
    IPP_BADARG_RET(!RSA_PUB_KEY_VALID_ID(pKey), ippStsContextMatchErr);

    /* test input value */
    IPP_BAD_PTR1_RET(pValue);
    IPP_BADARG_RET(!BN_VALID_ID(pValue), ippStsContextMatchErr);
    IPP_BADARG_RET(!(0 < cpBN_tst(pValue)), ippStsOutOfRangeErr);

    {
        switch (keyTag) {
        case ippRSAkeyN:
            /* validate modulus size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PUB_KEY_MAXSIZE_N(pKey),
                           ippStsSizeErr);

            /* setup montgomery engine with the modulus */
            gsModEngineInit(RSA_PUB_KEY_NMONT(pKey),
                            (Ipp32u*)BN_NUMBER(pValue),
                            cpBN_bitsize(pValue),
                            MOD_ENGINE_RSA_POOL_SIZE,
                            gsModArithRSA());

            /* store modulus bit size */
            RSA_PUB_KEY_BITSIZE_N(pKey) = cpBN_bitsize(pValue);
            break;

        case ippRSAkeyE:
            /* validate exponent size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PUB_KEY_MAXSIZE_E(pKey),
                           ippStsSizeErr);

            /* store E */
            ZEXPAND_COPY_BNU(RSA_PUB_KEY_E(pKey),
                             BITS_BNU_CHUNK(RSA_PUB_KEY_MAXSIZE_E(pKey)),
                             BN_NUMBER(pValue),
                             BN_SIZE(pValue));

            /* store exponent bit size */
            RSA_PUB_KEY_BITSIZE_E(pKey) = cpBN_bitsize(pValue);
            break;

        default:
            return ippStsBadArgErr;
        }

        return ippStsNoErr;
    }
}
