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
//        ippsRSA_SetPrivateKeyType2Part()
//
*/

#include "owncp.h"
#include "pcpbn.h"
#include "pcpngrsa.h"

/*F*
// Name: ippsRSA_SetPrivateKeyType2Part
//
// Purpose: Set up a specific part of the RSA private key type 2
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pKey
//                               NULL == pValue
//
//    ippStsContextMatchErr     !BN_VALID_ID(pValue)
//                              !RSA_PRV_KEY2_VALID_ID(pKey)
//
//    ippStsBadArgErr            invalid keyTag parameter for private key type 2
//
//    ippStsOutOfRangeErr        0 >= pValue
//
//    ippStsSizeErr              bitsize(pValue) exceeds requested value for the part
//
//    ippStsNoErr                no error
//
// Parameters:
//    keyTag         which part of the key to set (ippRSAkeyP, ippRSAkeyQ, ippRSAkeyDp, ippRSAkeyDq, ippRSAkeyQinv)
//    pValue         pointer to the big number value for this part
//    pKey           pointer to the key context
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsRSA_SetPrivateKeyType2Part, (IppRSAKeyTag keyTag,
                                                   const IppsBigNumState* pValue,
                                                   IppsRSAPrivateKeyState* pKey))
/* clang-format on */
{
    /* test private key context */
    IPP_BAD_PTR1_RET(pKey);
    IPP_BADARG_RET(!RSA_PRV_KEY2_VALID_ID(pKey), ippStsContextMatchErr);

    /* test input value */
    IPP_BAD_PTR1_RET(pValue);
    IPP_BADARG_RET(!BN_VALID_ID(pValue), ippStsContextMatchErr);
    IPP_BADARG_RET(!(0 < cpBN_tst(pValue)), ippStsOutOfRangeErr);

    {
        switch (keyTag) {
        case ippRSAkeyP:
            /* validate P size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PRV_KEY_BITSIZE_P(pKey),
                           ippStsSizeErr);

            /* setup montgomery engine P */
            gsModEngineInit(RSA_PRV_KEY_PMONT(pKey),
                            (Ipp32u*)BN_NUMBER(pValue),
                            cpBN_bitsize(pValue),
                            MOD_ENGINE_RSA_POOL_SIZE,
                            gsModArithRSA());

            /* store P bit size */
            RSA_PRV_KEY_BITSIZE_P(pKey) = cpBN_bitsize(pValue);
            break;

        case ippRSAkeyQ:
            /* validate Q size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PRV_KEY_BITSIZE_Q(pKey),
                           ippStsSizeErr);

            /* setup montgomery engine Q */
            gsModEngineInit(RSA_PRV_KEY_QMONT(pKey),
                            (Ipp32u*)BN_NUMBER(pValue),
                            cpBN_bitsize(pValue),
                            MOD_ENGINE_RSA_POOL_SIZE,
                            gsModArithRSA());

            /* store Q bit size */
            RSA_PRV_KEY_BITSIZE_Q(pKey) = cpBN_bitsize(pValue);
            break;

        case ippRSAkeyDp:
            /* validate Dp size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PRV_KEY_BITSIZE_P(pKey),
                           ippStsSizeErr);

            /* store CTR's exp dp */
            ZEXPAND_COPY_BNU(RSA_PRV_KEY_DP(pKey),
                             BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_P(pKey)),
                             BN_NUMBER(pValue),
                             BN_SIZE(pValue));
            break;

        case ippRSAkeyDq:
            /* validate Dq size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PRV_KEY_BITSIZE_Q(pKey),
                           ippStsSizeErr);

            /* store CTR's exp dq */
            ZEXPAND_COPY_BNU(RSA_PRV_KEY_DQ(pKey),
                             BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_Q(pKey)),
                             BN_NUMBER(pValue),
                             BN_SIZE(pValue));
            break;

        case ippRSAkeyQinv:
            /* validate Qinv size */
            IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pValue), BN_SIZE(pValue)) >
                               RSA_PRV_KEY_BITSIZE_P(pKey),
                           ippStsSizeErr);

            /* store CTR's invQ */
            ZEXPAND_COPY_BNU(RSA_PRV_KEY_INVQ(pKey),
                             BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_P(pKey)),
                             BN_NUMBER(pValue),
                             BN_SIZE(pValue));
            break;

        default:
            return ippStsBadArgErr;
        }

        /* check if all components are set and compute N = P*Q if so */
        if (RSA_PRV_KEY2_READY(pKey)) {
            BNU_CHUNK_T* pN = MOD_MODULUS(RSA_PRV_KEY_NMONT(pKey));
            cpSize nsN = BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_P(pKey) + RSA_PRV_KEY_BITSIZE_Q(pKey));

            /* compute N = P*Q using the values from Montgomery engines */
            cpMul_BNU_school(pN,
                             MOD_MODULUS(RSA_PRV_KEY_PMONT(pKey)),
                             BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_P(pKey)),
                             MOD_MODULUS(RSA_PRV_KEY_QMONT(pKey)),
                             BITS_BNU_CHUNK(RSA_PRV_KEY_BITSIZE_Q(pKey)));

            /* setup montgomery engine N */
            gsModEngineInit(RSA_PRV_KEY_NMONT(pKey),
                            (Ipp32u*)MOD_MODULUS(RSA_PRV_KEY_NMONT(pKey)),
                            RSA_PRV_KEY_BITSIZE_P(pKey) + RSA_PRV_KEY_BITSIZE_Q(pKey),
                            MOD_ENGINE_RSA_POOL_SIZE,
                            gsModArithRSA());

            FIX_BNU(pN, nsN);
            RSA_PRV_KEY_BITSIZE_N(pKey) = BITSIZE_BNU(pN, nsN);
        }

        return ippStsNoErr;
    }
}
