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

#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"

#include "gfpec/sm2/ifma_arith_method_sm2.h"
#include "gfpec/sm2/ifma_ecpoint_sm2.h"

IPP_OWN_DEFN(IppECResult, gfec_Verify_sm2_avx512,
             (const IppsBigNumState* pMsgDigest,
              const IppsGFpECPoint* pRegPublic,
              const IppsBigNumState* pSignR, const IppsBigNumState* pSignS,
              IppsGFpECState* pEC,
              Ipp8u* pScratchBuffer)) {
    IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

    IppECResult verifyResult = ippECInvalidSignature;

    gsModEngine* pME = GFP_PMA(ECP_GFP(pEC));
    gsModEngine* nME = ECP_MONT_R(pEC);

    const int orderBits = ECP_ORDBITSIZE(pEC);
    const int orderLen  = BITS_BNU_CHUNK(orderBits);
    const int elemLen   = GFP_FELEN(pME);

    ifmaArithMethod* pmeth = (ifmaArithMethod*)GFP_METHOD_ALT(pME);
    ifmaArithMethod* nmeth = (ifmaArithMethod*)GFP_METHOD_ALT(nME);

    ifma_import to_radix52   = pmeth->import_to52;
    ifma_export from_radix52 = pmeth->export_to64;

    /* Mod engine (mod p) */
    ifma_decode p_from_mont = pmeth->decode;

    /* Mod engine (mod n - subgroup order) */
    ifma_encode n_to_mont    = nmeth->encode;
    ifma_decode n_from_mont  = nmeth->decode;
    ifma_add n_add           = nmeth->add;
    ifma_red n_red           = nmeth->red;

    /* init message | sign_r | sing_s  */
    fesm2 msg, sign_r, sign_s, t;
    msg = sign_r = sign_s = t = setzero_i64();

    /* buffer extract msg */
    BNU_CHUNK_T* pPool     = cpGFpGetPool(3, pME);
    BNU_CHUNK_T* pBufMsg   = pPool;
    BNU_CHUNK_T* pBufSignR = pPool + elemLen;
    BNU_CHUNK_T* pBufSignS = pPool + 2 * elemLen;

    ZEXPAND_COPY_BNU(pBufMsg, orderLen, BN_NUMBER(pMsgDigest), BN_SIZE(pMsgDigest));
    ZEXPAND_COPY_BNU(pBufSignS, orderLen, BN_NUMBER(pSignS), BN_SIZE(pSignS));
    ZEXPAND_COPY_BNU(pBufSignR, orderLen, BN_NUMBER(pSignR), BN_SIZE(pSignR));

    /* radix64 -> radix52 */
    msg    = to_radix52((Ipp64u*)pBufMsg);
    msg    = n_red(msg); /* reduce just in case */
    sign_r = to_radix52((Ipp64u*)pBufSignR);
    sign_s = to_radix52((Ipp64u*)pBufSignS);

    /* Convert public point to proper Montgomery domain and 2^52 radix */
    __ALIGN64 PSM2_POINT_IFMA P;
    recode_point_to_mont52(&P, ECP_POINT_DATA(pRegPublic), pPool /* 3 elem */, pmeth, pME);

    /* compute t = (r + s) mod n */
    t      = n_to_mont(sign_r);
    sign_s = n_to_mont(sign_s);

    t = n_add(sign_s, t);

    t = n_from_mont(t);
    /* check zeros t != 0 */
    const mask8 sign_err_mask = FESM2_IS_ZERO(t);
    if ((mask8)0xFF == sign_err_mask)
        verifyResult = ippECInvalidSignature;

    BNU_CHUNK_T* pExtendedS = cpGFpGetPool(2, pME);
    BNU_CHUNK_T* pExtendedT = cpGFpGetPool(2, pME);
    BNU_CHUNK_T* pTmp       = cpGFpGetPool(1, pME);

    /* compute [s]G + t[P] */

    /* copmute [s]G */
    __ALIGN64 PSM2_POINT_IFMA sG;
    /* create s */
    cpGFpElementCopyPad(pExtendedS, orderLen + 1, pBufSignS, orderLen);
    if (ECP_PREMULBP(pEC)) {
        gesm2_mul_base(&sG, (Ipp8u*)pExtendedS);
    } else {
        /* Convert base point to a new Montgomery domain */
        __ALIGN64 PSM2_POINT_IFMA G52;
        recode_point_to_mont52(&G52, ECP_G(pEC), pPool /* 3 elem */, pmeth, pME);

        gesm2_mul(&sG, &G52, (Ipp8u*)pExtendedS, orderBits);
    }

    /* create t */
    from_radix52((Ipp64u*)pTmp, t);
    cpGFpElementCopyPad(pExtendedT, orderLen + 1, pTmp, orderLen);
    /* compute [t]P */
    gesm2_mul(&P, &P, (Ipp8u*)pExtendedT, orderBits);
    /* compute [s]G + [t]P */
    gesm2_add(&P, &P, &sG);

    fesm2 sign_r_restore;
    /* extract X affine coordinate */
    gesm2_to_affine(/* x = */ &sign_r_restore, /* y = */ NULL, &P);
    sign_r_restore = p_from_mont(sign_r_restore);
    /* x = x mod n */
    sign_r_restore = n_red(sign_r_restore);

    /* R = (e + x1) mod n */
    msg            = n_to_mont(msg);
    sign_r_restore = n_to_mont(sign_r_restore);

    sign_r_restore = n_add(msg, sign_r_restore);

    sign_r_restore = n_from_mont(sign_r_restore);

    const mask8 mask_ok = cmp_i64_mask(sign_r_restore, sign_r, _MM_CMPINT_EQ);
    if ((mask8)0xFF == mask_ok)
        verifyResult = ippECValid;

    cpGFpReleasePool(8, pME);

    return verifyResult;
}

#endif // (_IPP32E >= _IPP32E_K1)
