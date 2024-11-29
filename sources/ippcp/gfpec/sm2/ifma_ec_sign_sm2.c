/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/pcpgfpstuff.h"

#include "gfpec/sm2/ifma_defs_sm2.h"
#include "gfpec/sm2/ifma_ecpoint_sm2.h"
#include "gfpec/sm2/ifma_arith_method_sm2.h"


IPP_OWN_DEFN(IppStatus, gfec_Sign_sm2_avx512,
             (const IppsBigNumState* pMsgDigest,
              const IppsBigNumState* pRegPrivate,
              IppsBigNumState* pEphPrivate,
              IppsBigNumState* pSignR, IppsBigNumState* pSignS,
              IppsGFpECState* pEC,
              Ipp8u* pScratchBuffer)) {
    IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

    IppStatus sts = ippStsNoErr;

    gsModEngine* pME = GFP_PMA(ECP_GFP(pEC));
    gsModEngine* nME = ECP_MONT_R(pEC);

    const int orderBits = ECP_ORDBITSIZE(pEC);
    const int orderLen  = BITS_BNU_CHUNK(orderBits);

    ifmaArithMethod* pmeth = (ifmaArithMethod*)GFP_METHOD_ALT(pME);
    ifmaArithMethod* nmeth = (ifmaArithMethod*)GFP_METHOD_ALT(nME);

    ifma_import to_radix52   = pmeth->import_to52;
    ifma_export from_radix52 = pmeth->export_to64;

    /* Mod engine (mod p) */
    ifma_decode p_from_mont = pmeth->decode;

    /* Mod engine (mod n - subgroup order) */
    ifma_encode n_to_mont   = nmeth->encode;
    ifma_decode n_from_mont = nmeth->decode;
    ifma_mul n_mul          = nmeth->mul;
    ifma_add n_add          = nmeth->add;
    ifma_add n_sub          = nmeth->sub;
    ifma_inv n_inv          = nmeth->inv;
    ifma_red n_red          = nmeth->red;

    fesm2 sign_r, sign_s;
    sign_r = sign_s = setzero_i64();

    /* compute r-component
     * 1) (x1,y1) = [s]G
     * 2) r = (e + x1) mod n
     */
    /* 1) (x1,y1) = [s]G */
    /* copy scalar */
    BNU_CHUNK_T* pExtendedScalar = cpGFpGetPool(2, pME);
    cpGFpElementCopyPad(pExtendedScalar, orderLen + 1, BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate));

    __ALIGN64 PSM2_POINT_IFMA P;

    if (ECP_PREMULBP(pEC)) {
        gesm2_mul_base(&P, (Ipp8u*)pExtendedScalar);
    } else {
        BNU_CHUNK_T* pPool = cpGFpGetPool(3, pME);

        /* Convert base point to a new Montgomery domain */
        __ALIGN64 PSM2_POINT_IFMA G52;
        recode_point_to_mont52(&G52, ECP_G(pEC), pPool, pmeth, pME);

        gesm2_mul(&P, &G52, (Ipp8u*)pExtendedScalar, orderBits);

        cpGFpReleasePool(3, pME);
    }

    /* extract affine P.x */
    gesm2_to_affine(/* x = */ &(P.x), /* y = */ NULL, /* a = */ &P);
    P.x = p_from_mont(P.x);
    P.x = n_red(P.x);

    /* 2) r = (e + x1) mod n */
    BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pME);
    fesm2 msg         = setzero_i64();
    ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pMsgDigest), BN_SIZE(pMsgDigest));
    msg = to_radix52((Ipp64u*)pTmp);
    msg = n_red(msg); /* reduce just in case */

    msg = n_to_mont(msg);
    P.x = n_to_mont(P.x);

    sign_r = n_add(msg, P.x);
    /* check r == 0 or r + k == n(0) */
    /* r == 0 */
    const mask8 sign_r_err_zeros = FESM2_IS_ZERO(sign_r);
    /* r + k == 0 */
    /* extract k */
    fesm2 eph_key = setzero_i64();
    ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate));
    eph_key = to_radix52((Ipp64u*)pTmp);
    eph_key = n_to_mont(eph_key);

    fesm2 t;
    t = n_add(eph_key, sign_r);

    const mask8 rpk_err_zeros = FESM2_IS_ZERO(t);

    if (((mask8)0xFF == sign_r_err_zeros) || ((mask8)0xFF == rpk_err_zeros))
        sts = ippStsEphemeralKeyErr;

    fesm2 reg_key = setzero_i64();
    ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pRegPrivate), BN_SIZE(pRegPrivate));
    reg_key = to_radix52((Ipp64u*)pTmp);

    const fesm2 one = FESM2_LOADU(PSM2_ONE52);

    t       = n_to_mont(one);
    reg_key = n_to_mont(reg_key);

    sign_s  = n_mul(sign_r, reg_key);  /* sign_s  = r * d                      (result not normalized) */
    reg_key = n_add(reg_key, t);       /* reg_key = 1 + d                          (result normalized) */
    reg_key = n_inv(reg_key);          /* reg_key = (1 + d)^(-1)               (result not normalized) */
    sign_s  = n_sub(eph_key, sign_s);  /* sign_s  = (k - r * d)                    (result normalized) */
    sign_s  = n_mul(sign_s, reg_key);  /* sign_s  = (1 + d)^(-1) * (k - r * d) (result not normalized) */
    
    // result shall be normalized before the final multiplication inside `n_from_mont` function
    sign_s  = ifma_lnorm52(sign_s);
    sign_s = n_from_mont(sign_s);
    sign_r = n_from_mont(sign_r);

    const mask8 is_zero = (mask8)(FESM2_IS_ZERO(sign_r) | FESM2_IS_ZERO(sign_s));
    if ((mask8)0xFF == is_zero)
        sts = ippStsEphemeralKeyErr;

    // return sign_s
    from_radix52((Ipp64u*)pTmp, sign_s);
    BN_SIGN(pSignS) = ippBigNumPOS;
    BN_SIZE(pSignS) = orderLen;
    ZEXPAND_COPY_BNU(BN_NUMBER(pSignS), BN_ROOM(pSignS), pTmp, orderLen);
    // return sign_r
    from_radix52((Ipp64u*)pTmp, sign_r);
    BN_SIGN(pSignR) = ippBigNumPOS;
    BN_SIZE(pSignR) = orderLen;
    ZEXPAND_COPY_BNU(BN_NUMBER(pSignR), BN_ROOM(pSignR), pTmp, orderLen);

    /* clear secret data */
    clear_secrets(&eph_key, &(P.x), &t);
    clear_secrets(&sign_r, &sign_s, &reg_key);

    /* clear buffer */
    cpGFpReleasePool(3, pME); /* pExtendedScalar(2) + tmp(1) */
    return sts;
}

#endif // (_IPP32E >= _IPP32E_K1)
