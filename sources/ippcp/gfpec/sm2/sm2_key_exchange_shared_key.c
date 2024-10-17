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

#include "owncp.h"
#include "owndefs.h"
#include "gfpec/sm2/sm2_key_exchange_method.h"
#include "gfpec/sm2/sm2_stuff.h"

#define CHECK_PRIVATE_KEY(KEY)                                 \
   IPP_BAD_PTR1_RET((KEY))                                     \
   IPP_BADARG_RET(!BN_VALID_ID((KEY)), ippStsContextMatchErr)  \
   IPP_BADARG_RET(BN_NEGATIVE((KEY)), ippStsInvalidPrivateKey) \
   /* test if 0 < pPrivateA < Order */                         \
   IPP_BADARG_RET(0 == gfec_CheckPrivateKey((KEY), pEC), ippStsInvalidPrivateKey)

/**
 * @brief ippsGFpECKeyExchangeSM2_SharedKey
 * compute x(u/v) | y(u/v) | precomHash | shared key
 * see standard:
 * [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves
 * Part 3: Key exchange protocol
 * 6.2 Process of key exchange protocol
 * stack compute[standard link]:
 *                                                                       [user  A| user  B]
 * 2) x(a/b)` = 2^w + (x(a/b) & (2^w – 1))                               [step  4| step  3]
 * 3) t(a/b)  = (d(a/b) + x(a/b)`*r(a/b) ) mod n                         [step  5| step  4]
 * 4) x(b/a)` = 2^w + ( x(b/a) & (2^w – 1) )                             [step  6| step  5]
 * 5) U/V = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) = ( x(u/v), y(u/v) )  [step  7| step  6]
 * tmp_p = SM3( x(u/v) || Za || Zb || xa || ya || xb || yb )
 * 6) S(a/b) = SM3( 0x0(3/2) || y(u/v) || tmp_p )                        [step 10| step  8]
 * 7) K(a/b) = KDF(x(u/v) || y(u/v) || Za || Zb, klen)                   [step  8| step  7]
 * @param [out] pSharedKey     shared key [K(a/b) = KDF(x(u/v) || y(u/v) || Za || Zb, klen)]
 * @param [in]  sharedKeySize  length shared key
 * @param [out] pSSelf         (may be == NULL) self data confirmation
 * @param [in]  pPrvKey        private key
 * @param [in]  pEphPrvKey     ephemeral private key (!) will be cleared at the end if function successfully competed (!)
 * @param [out] pKE            context Key Exchange (save x(u/v) | y(u/v) | precompHash )
 * @param [in]  pScratchBuffer supported buffer
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pEC | pKE | pSharedKey | pPrvKey | PEphPrvKey | pSB is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsRangeErr            - if BitSize(pEC) < IPP_SM3_DIGEST_BITSIZE
 * ippStsBadArgErr           - if role(pKE) no equal ippKESM2Requester|ippKESM2Responder or sharedKeySize <= 0
 * ippStsInvalidPrivateKey   - if test is failed 0 < pPrvKey|pEphPrvKey < Order
 * ippStsEphemeralKeyErr     - if test is failed pEphPrvKey == pEphPublicKeySelf*G or if calculated U(V) is an
 *                             infinity point, U/V = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) = ( x(u/v), y(u/v) )
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECKeyExchangeSM2_SharedKey, (Ipp8u* pSharedKey, int sharedKeySize,
                                                      Ipp8u* pSSelf,
                                                      const IppsBigNumState* pPrvKey,
                                                      IppsBigNumState* pEphPrvKey,
                                                      IppsGFpECKeyExchangeSM2State *pKE, Ipp8u* pScratchBuffer))
/* clang-format on */
{
   /* check Key Exchange */
   IPP_BAD_PTR1_RET(pKE);
   /* check id */
   IPP_BADARG_RET(!EC_SM2_KEY_EXCH_VALID_ID(pKE), ippStsContextMatchErr);
   /* check User Role */
   const IppsKeyExchangeRoleSM2 role = EC_SM2_KEY_EXCH_ROLE(pKE);
   IPP_BADARG_RET(((ippKESM2Requester != role) && (ippKESM2Responder != role)), ippStsBadArgErr);

   /* check Elliptic Curve */
   IppsGFpECState *pEC = EC_SM2_KEY_EXCH_EC(pKE);

   IPP_BAD_PTR1_RET(pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC)); /* base P */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr);
   gsModEngine *nME = ECP_MONT_R(pEC); /* base N */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(nME), ippStsNotSupportedModeErr);
   /* check bitsize >= SM3_DIGSET */
   IPP_BADARG_RET(!(ECP_ORDBITSIZE(pEC) >= IPP_SM3_DIGEST_BITSIZE), ippStsRangeErr);

   /* check call Setup */
   /* check init Public Key | Ephemeral  Public Key */
   IPP_BADARG_RET( NULL == EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE)     ||
                   NULL == EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE)     ||
                   NULL == EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) ||
                   NULL == EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE), ippStsContextMatchErr)

   /* check Shared Key */
   IPP_BAD_PTR1_RET(pSharedKey);
   /* [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves
    * Part 3: Key exchange protocol
    * 5.4.3 Key derivation function
    * (0 < sharedKeySize) - (+) check
    * (sharedKeySize < (2^32 - 1)*log2(n) ) - NO NEED if use INT input data type
    */
   IPP_BADARG_RET(!(sharedKeySize > 0), ippStsOutOfRangeErr);

   /* check buffer */
   IPP_BAD_PTR1_RET(pScratchBuffer);

   /* check Private Key */
   CHECK_PRIVATE_KEY(pPrvKey)

   /* check Ephemeral  Private Key */
   CHECK_PRIVATE_KEY(pEphPrvKey)

#if (_IPP32E >= _IPP32E_K1)
   if (IsFeatureEnabled(ippCPUID_AVX512IFMA) && (cpID_PrimeTPM_SM2 == ECP_MODULUS_ID(pEC))) {
      const IppStatus sts = gfec_key_exchange_sm2_shared_key_avx512(pSharedKey, sharedKeySize, pSSelf, pPrvKey, pEphPrvKey, pKE, pScratchBuffer);
      return sts;
   }
#endif // (_IPP32E >= _IPP32E_K1)
   {
      IppStatus sts = ippStsNoErr;

      /* setup Public | Ephemeral  Public */
      const IppsGFpECPoint *pPubKey            = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE) : EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE);
      const IppsGFpECPoint *pEphPubKey         = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE) : EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE);
      const IppsGFpECPoint *pSelfEphPubKey     = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) : EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE);
      const Ipp8u firstNum                     = (ippKESM2Requester == role) ? 0x03 : 0x02;

      /* check that Ephemeral Public and Private Keys are related (R(a/b)=r(a/b)G) */
      IppsGFpECPoint pTmpPoint;
      cpEcGFpInitPoint(&pTmpPoint, cpEcGFpGetPool(1, pEC), 0, pEC);
      BNU_CHUNK_T *pDataEphPrv = BN_NUMBER(pEphPrvKey); // Ephemeral Private Key -> r(a/b)
      gfec_MulBasePoint(&pTmpPoint, pDataEphPrv, BN_SIZE(pEphPrvKey), pEC, pScratchBuffer); // r(a/b)*G
      int result = gfec_ComparePoint(&pTmpPoint, pSelfEphPubKey, pEC); // R(a/b) == r(a/b)G ?
      cpEcGFpReleasePool(1, pEC); // Release pool before the possible exit
      IPP_BADARG_RET(!result, ippStsEphemeralKeyErr);

      /* extract data Elliptic Curve */
      BNU_CHUNK_T *pOrder = MOD_MODULUS(nME); /* data oreder */
      const int ordLen    = MOD_LEN(nME);     /* len order */

      const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
      const int elemBytes = (elemBits + 7) / 8; /* size Bytes */
      const int elemSize  = GFP_FELEN(pME);     /* size BNU_CHUNK */

      /* create buffer data (it needs further use compute tmp_p)
       * -> SM3( x(u/v)(0) || Za(1) || Zb(2) || xa(3) || ya(4) || xb(5) || yb(6) )
       */
      BNU_CHUNK_T *pDataBuff = cpGFpGetPool(7, pME);
      BNU_CHUNK_T *_pXY_     = cpEcGFpGetPool(1, pEC); /* elem 3 */
      /* 2) x(a/b)` = 2^w + (x(a/b) & (2^w – 1)) */
      BNU_CHUNK_T *xa   = pDataBuff + 3 * elemSize; /* xa(3) */
      BNU_CHUNK_T *ya   = pDataBuff + 4 * elemSize; /* ya(4) */
      BNU_CHUNK_T *_xa_ = _pXY_;
      /* point to affine coordinate */
      cpSM2KE_get_affine_ext_euclid(/* x = */ xa, /* y = */ ya, /* p = */ EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE), /* pEC = */ pEC);
      /* reduction x = 2^w + ( x & (2^w - 1) ) */
      cpSM2KE_reduction_x2w(_xa_, xa, pEC);
      /* to big endian */
      cpSM2KE_xy_to_BE(xa, ya, pEC);
      /* 4) x(b/a)` = 2^w + ( x(b/a) & (2^w – 1) ) */
      BNU_CHUNK_T *xb   = pDataBuff + 5 * elemSize; /* xb(5) */
      BNU_CHUNK_T *yb   = pDataBuff + 6 * elemSize; /* yb(6) */
      BNU_CHUNK_T *_xb_ = _pXY_ + elemSize;
      /* point to affine coordinate */
      cpSM2KE_get_affine_ext_euclid(/* x = */ xb, /* y = */ yb, /* p = */ EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE), /* pEC = */ pEC);
      /* reduction x = 2^w + ( x & (2^w - 1) ) */
      cpSM2KE_reduction_x2w(_xb_, xb, pEC);
      /* to big endian */
      cpSM2KE_xy_to_BE(xb, yb, pEC);

      BNU_CHUNK_T *_xf_ = (ippKESM2Requester == role) ? _xa_ : _xb_;
      BNU_CHUNK_T *_xs_ = (ippKESM2Requester == role) ? _xb_ : _xa_;

      /* 3) t(a/b) = (d(a/b) + x(a/b)`*r(a/b) ) mod n */
      BNU_CHUNK_T *t = pDataBuff + elemSize; /* temporary use slot Za(1) */
      /* Private key -> d(a/b) */
      BNU_CHUNK_T *pTmpPrv = pDataBuff; /* temporary use slot x(u/v)(0) */
      cpGFpElementCopy(pTmpPrv, BN_NUMBER(pPrvKey), elemSize);
      GFP_METHOD(nME)->encode(pTmpPrv, pTmpPrv, nME);
      /* Ephemeral Private Key -> r(a/b) */
      GFP_METHOD(nME)->encode(pDataEphPrv, pDataEphPrv, nME);
      /* x(a/b)` */
      GFP_METHOD(nME)->encode(_xf_, _xf_, nME);

      GFP_METHOD(nME)->mul(pDataEphPrv, pDataEphPrv, _xf_, nME);       /* x(a/b)`*r(a/b) mod n  */
      BNU_CHUNK_T *pBuffTmp = pDataBuff + 2 * elemSize;                /* temporary use slot Zb(2) */
      cpModAdd_BNU(t, pDataEphPrv, pTmpPrv, pOrder, ordLen, pBuffTmp); /* (d(a/b) + x(a/b)`*r(a/b) ) mod n */

      /* 5) U/V = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) = ( x(u/v), y(u/v) ) */
      /* [x(b/a)`]R(b/a) */
      const int scalarBits = ((elemBits + 1) / 2);
      cpEcGFpInitPoint(&pTmpPoint, cpEcGFpGetPool(1, pEC), 0, pEC);
      gfec_point_mul(ECP_POINT_X(&pTmpPoint), ECP_POINT_X(pEphPubKey), (Ipp8u *)_xs_, scalarBits, pEC, pScratchBuffer);
      /* P(b/a) + [x(b/a)`]R(b/a) */
      gfec_point_add(ECP_POINT_X(&pTmpPoint), ECP_POINT_X(&pTmpPoint), ECP_POINT_X(pPubKey), pEC);

      /* h*t(a/b) */
      BNU_CHUNK_T *pCofactor = ECP_COFACTOR(pEC);
      const int cofactorLen  = cpGFpElementLen(pCofactor, elemSize);

      if (!GFP_IS_ONE(pCofactor, cofactorLen)) {
         cpMontMul_BNU_EX(t, t, elemSize, pCofactor, cofactorLen, nME);
      }
      GFP_METHOD(nME)->decode(t, t, nME);
      /* we can do this because slot Zb(2) not Use Now */
      cpGFpElementCopyPad(t, elemSize + 1, t, elemSize);
      /* U/V = [h*t(a/b)]( P(b/a) + [x(b/a)`]R(b/a) ) = ( x(u/v), y(u/v) ) */
      gfec_point_mul(ECP_POINT_X(&pTmpPoint), ECP_POINT_X(&pTmpPoint), (Ipp8u *)t, elemBits, pEC, pScratchBuffer);
      /* check U/V == 0 */
      ECP_POINT_FLAGS(&pTmpPoint) = gfec_IsPointAtInfinity(&pTmpPoint) ? 0 : ECP_FINITE_POINT;
      if(ECP_POINT_FLAGS(&pTmpPoint) == 0) {
         sts = ippStsEphemeralKeyErr;
      }

      /* extract Affine Coordinate X|Y */
      /* save x(u/v), y(u/v) */
      BNU_CHUNK_T *x_af = EC_SM2_KEY_EXCH_POINT_X(pKE);
      BNU_CHUNK_T *y_af = EC_SM2_KEY_EXCH_POINT_Y(pKE);
      /* point to affine coordinate */
      cpSM2KE_get_affine_ext_euclid(/* x = */ x_af, /* y = */ y_af, /* p = */ &pTmpPoint, /* pEC = */ pEC);
      /* to big endian */
      cpSM2KE_xy_to_BE(x_af, y_af, pEC);

      /* Precompute Hash */
      Ipp8u *pBuff = (Ipp8u *)pDataBuff;
      /* tmp_p = SM3( x(u/v) || Za || Zb || xa || ya || xb || yb ) */
      /* copy x(u/v)(0) */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)x_af, elemBytes);
      pBuff += elemBytes;
      /* copy Za(1) */
      cpSM2_CopyBlock(pBuff, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE), IPP_SM3_DIGEST_BYTESIZE);
      pBuff += IPP_SM3_DIGEST_BYTESIZE;
      /* copy Zb(2) */
      cpSM2_CopyBlock(pBuff, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE), IPP_SM3_DIGEST_BYTESIZE);
      pBuff += IPP_SM3_DIGEST_BYTESIZE;
      /* recopy xa */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)xa, elemBytes);
      pBuff += elemBytes;
      /* recopy ya */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)ya, elemBytes);
      pBuff += elemBytes;
      /* recopy xb */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)xb, elemBytes);
      pBuff += elemBytes;
      /* recopy yb */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)yb, elemBytes);

      /* set pointer start */
      pBuff = (Ipp8u *)pDataBuff;

      const int sizeS_SM3 = elemBytes + 2 * IPP_SM3_DIGEST_BYTESIZE + 4 * elemBytes;

      /* copy to next operation */
      cpSM2KE_compute_hash_SM3(EC_SM2_KEY_EXCH_PRECOM_HASH(pKE), pBuff, sizeS_SM3);

      /* check U/V == 0 and S == NULL */
      if ((NULL != pSSelf) && IS_ECP_FINITE_POINT(&pTmpPoint)) {
         /* 6) S(a/b) = SM3( 0x0(3/2) || y(u/v) || tmp_p ) */
         /* copy 0x0(3/2) */
         pBuff[0] = firstNum;
         /* copy y(u/v) */
         cpSM2_CopyBlock(pBuff + 1, (const Ipp8u *)y_af, elemBytes);
         /* copy tmp_p */
         cpSM2_CopyBlock(pBuff + 1 + elemBytes, EC_SM2_KEY_EXCH_PRECOM_HASH(pKE), IPP_SM3_DIGEST_BYTESIZE);

         const int sizeSab_SM3 = 1 + elemBytes + IPP_SM3_DIGEST_BYTESIZE;
         cpSM2KE_compute_hash_SM3(pSSelf, pBuff, sizeSab_SM3);
      }

      /* compute KDF */
      /* 7) K(a/b) = KDF(x(u/v) || y(u/v) || Za || Zb, klen) */
      /* copy x(u/v)(0)*/
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_X(pKE), elemBytes);
      pBuff += elemBytes;
      /* copy y(u/v)(1) */
      cpSM2_CopyBlock(pBuff, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_Y(pKE), elemBytes);
      pBuff += elemBytes;
      /* copy Za(2) */
      cpSM2_CopyBlock(pBuff, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE), IPP_SM3_DIGEST_BYTESIZE);
      pBuff += IPP_SM3_DIGEST_BYTESIZE;
      /* copy Zb(3) */
      cpSM2_CopyBlock(pBuff, EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE), IPP_SM3_DIGEST_BYTESIZE);

      const int sizeKab_KDF = 2 * elemBytes + 2 * IPP_SM3_DIGEST_BYTESIZE;

      /* set pointer start */
      pBuff = (Ipp8u *)pDataBuff;

      /* compute KDF */
      KDF_sm3(pSharedKey, sharedKeySize, (const Ipp8u *)pBuff, sizeKab_KDF);

      /* free buffers */
      cpEcGFpReleasePool(2, pEC);
      cpGFpReleasePool(7, pME);

      /* clear Ephemeral  Private Key */
      cpBN_zero(pEphPrvKey);

      return sts;
   }
}

#undef CHECK_PRIVATE_KEY
