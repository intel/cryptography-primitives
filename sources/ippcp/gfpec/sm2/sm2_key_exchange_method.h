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
#ifndef _SM2_KEY_EXCHANGE_METHOD_H_
#define _SM2_KEY_EXCHANGE_METHOD_H_

#include "owncp.h"
#include "pcpbnuimpl.h"
#include "gfpec/pcpgfpecstuff.h"

/*
// EC over GF(p) Key Exchange SM2 context
*/
typedef struct _GFpECKeyExchangeSM2 {
   Ipp32u idCtx;                    /* context identifier */
   IppsKeyExchangeRoleSM2 role;     /* role User A(request) or B(response) */
   IppsGFpECState *pEC;             /* Elliptic Curve data context */
   IppsGFpECPoint *pPubKeyReqA;     /* Pa[User A] - Public Key */
   IppsGFpECPoint *pPubKeyRespB;    /* Pb[User B] - Public Key */
   IppsGFpECPoint *pEphPubKeyReqA;  /* Ra[User A] - Ephemeral Public Key */
   IppsGFpECPoint *pEphPubKeyRespB; /* Rb[User B] - Ephemeral Public Key */
   Ipp8u *pZReqA;                   /* Za[User A] - User ID Hash */
   Ipp8u *pZRespB;                  /* Zb[User B] - User ID Hash */
   Ipp8u *pPrecHash;                /* Precompute Hash - SM3( x(u/v) || Za || Zb || xa || ya || xb || yb ) */
   BNU_CHUNK_T *pPointXYBigEndian;  /* U/V */
} GFpECKeyExchangeSM2;


/*
// Context Access Macros
*/
/* clang-format off */
#define EC_SM2_KEY_EXCH_ID(ctx)                  ((ctx)->idCtx)
#define EC_SM2_KEY_EXCH_SET_ID(ctx)              (EC_SM2_KEY_EXCH_ID(ctx) = (Ipp32u)idCtxGFPECKE ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define EC_SM2_KEY_EXCH_VALID_ID(ctx)            ((EC_SM2_KEY_EXCH_ID(ctx) ^ (Ipp32u)IPP_UINT_PTR(ctx)) == (Ipp32u)idCtxGFPECKE)
#define EC_SM2_KEY_EXCH_ROLE(ctx)                ((ctx)->role)
#define EC_SM2_KEY_EXCH_EC(ctx)                  ((ctx)->pEC)
#define EC_SM2_KEY_EXCH_PUB_KEY_USER_A(ctx)      ((ctx)->pPubKeyReqA)
#define EC_SM2_KEY_EXCH_PUB_KEY_USER_B(ctx)      ((ctx)->pPubKeyRespB)
#define EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(ctx)  ((ctx)->pEphPubKeyReqA)
#define EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(ctx)  ((ctx)->pEphPubKeyRespB)
#define EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(ctx) ((ctx)->pZReqA)
#define EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(ctx) ((ctx)->pZRespB)
#define EC_SM2_KEY_EXCH_PRECOM_HASH(ctx)         ((ctx)->pPrecHash)
#define EC_SM2_KEY_EXCH_POINT_PTR(ctx)           ((ctx)->pPointXYBigEndian)
#define EC_SM2_KEY_EXCH_POINT_X(ctx)             ((ctx)->pPointXYBigEndian)
#define EC_SM2_KEY_EXCH_POINT_Y(ctx)             ((ctx)->pPointXYBigEndian + GFP_FELEN(GFP_PMA(ECP_GFP(EC_SM2_KEY_EXCH_EC(ctx)))) )
/* clang-format on */

#endif // _SM2_KEY_EXCHANGE_METHOD_H_
