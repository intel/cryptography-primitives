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

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/sm2/sm2_stuff.h"

#include "gfpec/sm2/ifma_defs_sm2.h"
#include "gfpec/sm2/ifma_ecpoint_sm2.h"
#include "gfpec/sm2/ifma_arith_method_sm2.h"


/* clang-format off */
__IPPCP_INLINE void ifma_sm2_set_affine_point_radix52(PSM2_POINT_IFMA *rp,
                                                const BNU_CHUNK_T *x, const BNU_CHUNK_T *y,
                                                ifmaArithMethod *method)
/* clang-format on */
{
   ifma_import to_radix52 = method->import_to52;
   ifma_encode p_to_mont  = method->encode;

   rp->x = to_radix52(x);
   rp->y = to_radix52(y);

   rp->x = p_to_mont(rp->x);
   rp->y = p_to_mont(rp->y);
   rp->z = FESM2_LOADU(PSM2_R);

   return;
}

/* clang-format off */
__IPPCP_INLINE void ifma_sm2_get_affine(BNU_CHUNK_T *x, BNU_CHUNK_T *y,
                                  const PSM2_POINT_IFMA* p,
                                  ifmaArithMethod* method)
/* clang-format on */
{
   /* extract affine coordinate */
   fesm2 loc_x, loc_y;
   gesm2_to_affine(/* x = */ &loc_x, /* y = */ &loc_y, /* p = */ p);

   ifma_export to_radix64  = method->export_to64;
   ifma_decode p_from_mont = method->decode;

   loc_x = p_from_mont(loc_x);
   loc_y = p_from_mont(loc_y);

   to_radix64((Ipp64u *)x, loc_x);
   to_radix64((Ipp64u *)y, loc_y);

   return;
}

/* clang-format off */
IPP_OWN_DEFN(IppStatus, gfec_key_exchange_sm2_shared_key_avx512, (Ipp8u* pSharedKey, const int sharedKeySize,
                                                                  Ipp8u* pSSelf,
                                                                  const IppsBigNumState* pPrvKey,
                                                                  IppsBigNumState* pEphPrvKey,
                                                                  IppsGFpECKeyExchangeSM2State *pKE, Ipp8u* pScratchBuffer))
/* clang-format on */
{
   IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

   const IppsKeyExchangeRoleSM2 role = EC_SM2_KEY_EXCH_ROLE(pKE);

   const IppsGFpECPoint *pPubKey            = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE) : EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE);
   const IppsGFpECPoint *pSelfEphPubKey     = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) : EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE);
   const Ipp8u firstNum                     = (ippKESM2Requester == role) ? 0x03 : 0x02;

   IppStatus sts = ippStsNoErr;

   IppsGFpECState *pEC = EC_SM2_KEY_EXCH_EC(pKE);

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));
   gsModEngine *nME = ECP_MONT_R(pEC);

   const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
   const int elemBytes = (elemBits + 7) / 8; /* size Bytes */
   const int elemSize  = GFP_FELEN(pME);     /* size BNU_CHUNK */

   ifmaArithMethod *pmeth = (ifmaArithMethod *)GFP_METHOD_ALT(pME);
   ifmaArithMethod *nmeth = (ifmaArithMethod *)GFP_METHOD_ALT(nME);

   ifma_import to_radix52   = pmeth->import_to52;
   ifma_export from_radix52 = pmeth->export_to64;

   /* Mod engine (mod n - subgroup order) */
   ifma_encode n_to_mont   = nmeth->encode;
   ifma_decode n_from_mont = nmeth->decode;
   ifma_mul n_mul          = nmeth->mul;
   ifma_add n_add          = nmeth->add;

   /* check that Ephemeral Public and Private Keys are related (R(a/b)=r(a/b)G) */
   /* Ephemeral Private Key -> r(a/b) */
   IppsGFpECPoint pTmpPoint;
   cpEcGFpInitPoint(&pTmpPoint, cpEcGFpGetPool(1, pEC), 0, pEC);
   BNU_CHUNK_T *pDataEphPrv = BN_NUMBER(pEphPrvKey);
   gfec_PubKey_sm2_avx512(&pTmpPoint, pDataEphPrv, BN_SIZE(pEphPrvKey), pEC, pScratchBuffer); // r(a/b)*G
   int result = gfec_ComparePoint(&pTmpPoint, pSelfEphPubKey, pEC); // R(a/b) == r(a/b)G
   cpEcGFpReleasePool(1, pEC);
   IPP_BADARG_RET(!result, ippStsEphemeralKeyErr);

   /* create buffer data (it needs further use compute tmp_p)
    * -> SM3( x(u/v)(0) || Za(1) || Zb(2) || xa(3) || ya(4) || xb(5) || yb(6) )
    */
   BNU_CHUNK_T *pDataBuff = cpGFpGetPool(7, pME);
   BNU_CHUNK_T *xuv       = pDataBuff;                /* x(u/v)(0) */
   BNU_CHUNK_T *za        = pDataBuff + 1 * elemSize; /* Za(1) */
   BNU_CHUNK_T *zb        = pDataBuff + 2 * elemSize; /* Za(1) */
   BNU_CHUNK_T *xa        = pDataBuff + 3 * elemSize; /* xa(3) */
   BNU_CHUNK_T *ya        = pDataBuff + 4 * elemSize; /* ya(4) */
   BNU_CHUNK_T *xb        = pDataBuff + 5 * elemSize; /* xb(5) */
   BNU_CHUNK_T *yb        = pDataBuff + 6 * elemSize; /* yb(6) */

   PSM2_POINT_IFMA Ra; /* ephemeral public key User A */
   PSM2_POINT_IFMA Rb; /* ephemeral public key User B */
   PSM2_POINT_IFMA P;  /* public key User (A/B) */

   /* convert to Montgomery IFMA SM2 */
   /* extract -> xa | ya | xb | yb */
   BNU_CHUNK_T *_xa_ = za; /* use Za(1) */
   /* 2) x(a/b)` = 2^w + (x(a/b) & (2^w – 1)) */
   /* point to affine coordinate */
   cpSM2KE_get_affine_ext_euclid(/* x = */ xa, /* y = */ ya, /* p = */ EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE), /* pEC = */ pEC);
   /* set affine coordinate radix 52 */
   ifma_sm2_set_affine_point_radix52(/* rp = */ &Ra, /* x= */ xa, /* y = */ ya, pmeth);
   /* reduction x = 2^w + ( x & (2^w - 1) ) */
   cpSM2KE_reduction_x2w(_xa_, xa, pEC);
   /* to big endian */
   cpSM2KE_xy_to_BE(xa, ya, pEC);

   BNU_CHUNK_T *_xb_ = zb; /* use Zb(2) */
   /* 4) x(b/a)` = 2^w + ( x(b/a) & (2^w – 1) ) */
   cpSM2KE_get_affine_ext_euclid(/* x = */ xb, /* y = */ yb, /* p = */ EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE), /* pEC = */ pEC);
   /* set affine coordinate radix 52 */
   ifma_sm2_set_affine_point_radix52(/* rp = */ &Rb, /* x = */ xb, /* y = */ yb, pmeth);
   /* reduction x = 2^w + ( x & (2^w - 1) ) */
   cpSM2KE_reduction_x2w(_xb_, xb, pEC);
   /* to big endian */
   cpSM2KE_xy_to_BE(xb, yb, pEC);

   BNU_CHUNK_T *pPool = cpGFpGetPool(3, pME);
   recode_point_to_mont52(&P, ECP_POINT_DATA(pPubKey), pPool /* 3 elem */, pmeth, pME);
   cpGFpReleasePool(3, pME); /* pPool(3) */

   /* extract to role */
   BNU_CHUNK_T *_xf_  = (ippKESM2Requester == role) ? _xa_ : _xb_;
   BNU_CHUNK_T *_xs_  = (ippKESM2Requester == role) ? _xb_ : _xa_;
   PSM2_POINT_IFMA *R = (ippKESM2Requester == role) ? &Rb : &Ra;

   /* 3) t(a/b) = ( d(a/b) + x(a/b)`*r(a/b) ) mod n */
   fesm2 d, r, x1;
   d = r = x1 = setzero_i64();
   /* preparation d(a/b) */
   d = to_radix52((const Ipp64u *)BN_NUMBER(pPrvKey));
   d = n_to_mont(d);
   /* preparation r(a/b) */
   r = to_radix52((const Ipp64u *)pDataEphPrv);
   r = n_to_mont(r);
   /* preparation x(a/b)` */
   x1 = to_radix52((const Ipp64u *)_xf_);
   x1 = n_to_mont(x1);
   /* compute */
   r = n_mul(x1, r); /* r = x(a/b)`r(a/b) */
   d = n_add(d, r);  /* t = ( d(a/b) + x(a/b)`*r(a/b) ) */
   /* t -> convert form Montgomery */
   d = n_from_mont(d);

   /* 5) U/V = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) = ( x(u/v), y(u/v) ) */
   const int scalarBits = ((elemBits + 1) / 2);
   gesm2_mul(R, R, (const Ipp8u *)_xs_, scalarBits); /* R = [x(b/a)`]R(b/a) */
   gesm2_add(&P, &P, R);                             /* P = P(b/a) + [x(b/a)`]R(b/a) */
   BNU_CHUNK_T *pScalar = xuv;                       /* use buffer x(u/v)(0) and Za(1) */
   from_radix52((Ipp64u *)pScalar, d);
   pScalar[elemSize] = 0u;                              /* extended scalar - add 0 -> R = [scalar]P */
   gesm2_mul(&P, &P, (const Ipp8u *)pScalar, elemBits); /* P = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) */

   /* check U/V == 0 */
   const mask8 is_zero = (mask8)(FESM2_IS_ZERO(P.x) & FESM2_IS_ZERO(P.y) & FESM2_IS_ZERO(P.y));
   if ((mask8)0xFF == is_zero)
      sts = ippStsEphemeralKeyErr;

   /* extract x(u/v) ,y(u/v) */
   ifma_sm2_get_affine(/* x = */ EC_SM2_KEY_EXCH_POINT_X(pKE),
                       /* y = */ EC_SM2_KEY_EXCH_POINT_Y(pKE),
                       /* p = */ &P,
                       pmeth);
   cpSM2KE_xy_to_BE(/* x = */ EC_SM2_KEY_EXCH_POINT_X(pKE), /* y = */ EC_SM2_KEY_EXCH_POINT_Y(pKE), pEC);

   /* Precompute Hash */
   Ipp8u *pBuff = (Ipp8u *)pDataBuff;
   /* tmp_p = SM3( x(u/v) || Za || Zb || xa || ya || xb || yb ) */
   /* copy x(u/v)(0) */
   cpSM2_CopyBlock(xuv, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_X(pKE), elemBytes);
   /* copy Za(1) */
   cpSM2_CopyBlock(za, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE), IPP_SM3_DIGEST_BYTESIZE);
   /* copy Zb(2) */
   cpSM2_CopyBlock(zb, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE), IPP_SM3_DIGEST_BYTESIZE);
   /* xa || ya || xb || yb - is exists */

   const int sizeS_SM3 = elemBytes + 2 * IPP_SM3_DIGEST_BYTESIZE + 4 * elemBytes; /* 224 bytes */

   /* copy to next operation */
   cpSM2KE_compute_hash_SM3(EC_SM2_KEY_EXCH_PRECOM_HASH(pKE), pBuff, sizeS_SM3);

   if ((NULL != pSSelf) && (ippStsNoErr == sts)) {
      /* 6) S(a/b) = SM3( 0x0(3/2) || y(u/v) || tmp_p ) */
      /* copy 0x0(3/2) */
      pBuff[0] = firstNum;
      /* copy y(u/v) */
      cpSM2_CopyBlock(pBuff + 1, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_Y(pKE), elemBytes);
      /* copy tmp_p */
      cpSM2_CopyBlock(pBuff + 1 + elemBytes, EC_SM2_KEY_EXCH_PRECOM_HASH(pKE), IPP_SM3_DIGEST_BYTESIZE);

      const int sizeSab_SM3 = 1 + elemBytes + IPP_SM3_DIGEST_BYTESIZE; /* 65 bytes */
      cpSM2KE_compute_hash_SM3(pSSelf, pBuff, sizeSab_SM3);
   }

   /* compute KDF */
   /* 7) K(a/b) = KDF(x(u/v) || y(u/v) || Za || Zb, klen) */
   /* copy x(u/v)(0)*/
   cpSM2_CopyBlock(xuv, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_X(pKE), elemBytes); /* slot x(u/v)(0) */
   /* copy y(u/v)(1) */
   cpSM2_CopyBlock(za, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_Y(pKE), elemBytes); /* slot Za(1) */
   /* copy Za(2) */
   cpSM2_CopyBlock(zb, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE), IPP_SM3_DIGEST_BYTESIZE); /* slot Zb(2) */
   /* copy Zb(3) */
   cpSM2_CopyBlock(xa, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE), IPP_SM3_DIGEST_BYTESIZE); /* slot xa(3) */

   const int sizeKab_KDF = 2 * elemBytes + 2 * IPP_SM3_DIGEST_BYTESIZE; /* 128 bytes */

   /* set pointer start */
   pBuff = (Ipp8u *)pDataBuff;

   /* compute KDF */
   KDF_sm3(pSharedKey, sharedKeySize, (const Ipp8u *)pBuff, sizeKab_KDF);

   cpGFpReleasePool(7, pME);
   /* clear Ephemeral  Private Key */
   cpBN_zero(pEphPrvKey);
   /* clear secret register */
   PurgeBlock(&r, sizeof(r));
   PurgeBlock(&d, sizeof(d));

   return sts;
}

#endif // (_IPP32E >= _IPP32E_K1)
