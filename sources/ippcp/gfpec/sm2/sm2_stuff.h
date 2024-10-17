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

/*
//
//  Purpose:
//     Cryptography Primitive.
//     SM2 support function
//
//  Contents:
//     SM2 methods and constants
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "gfpec/pcpeccp.h"
#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/sm2/sm2_key_exchange_method.h"

#if !defined _SM2_STUFF_H
#define _SM2_STUFF_H

#define cpSM2_CopyBlock(DST, SRC, SIZE) CopyBlock((SRC), (DST), (SIZE))

/**
 * @brief
 * reverse inplace array ( Little Endian to Big Endian data )
 * @param[in out] arr array data
 * @param[in]     len length array
 */
__IPPCP_INLINE void cpSM2KE_reverse_inplace(Ipp8u *arr, const int len)
{
#define SWAPXOR(x, y) \
   (x) ^= (y);        \
   (y) ^= (x);        \
   (x) ^= (y);

   for (int i = 0; i < len / 2; ++i) {
      SWAPXOR(arr[i], arr[len - 1 - i])
   }
   return;
#undef SWAPXOR
}

/**
 * @brief cpSM2KE_CopyPointData
 * init and copy Pointer
 * @param[out] r    point in Elliptic Curve
 * @param[in]  data buffer init pointer data
 * @param[in]  p    point copy
 * @param[in]  pEC  context Elliptic Curve
 */
__IPPCP_INLINE void cpSM2KE_CopyPointData(IppsGFpECPoint *r, BNU_CHUNK_T *data, const IppsGFpECPoint *p, const IppsGFpECState *pEC)
{
   ECP_POINT_SET_ID(r);
   cpEcGFpInitPoint(r, data, ECP_POINT_FLAGS(p), pEC);
   gfec_CopyPoint(r, p, ECP_POINT_FELEN(p));
   return;
}

/**
 * @brief
 * reduction for the SM2 Key Exchange standard
 * x` = 2^w + (x & (2^w – 1))
 * when
 * w = log2(n)/2 - 1, n - number bytes order
 * @param[out] r   reduction value x`
 * @param[in]  a   value x
 * @param[in]  pEC context Elliptic Curve
 */
__IPPCP_INLINE void cpSM2KE_reduction_x2w(BNU_CHUNK_T *r, const BNU_CHUNK_T *a, const IppsGFpECState *pEC)
{
   const gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));

   const int elemBits = GFP_FEBITLEN(pME); /* size Bits */
   const int elemSize = GFP_FELEN(pME);    /* size BNU_CHUNK */
   /* compute w = [log2(n)/2 - 1] */
   const int w = ((elemBits + 1) / 2 - 1);

   /* compute copy BNU_CHUNK */
   const int num_copy_bc   = (w + (BNU_CHUNK_BITS - 1)) / BNU_CHUNK_BITS;
   const int num_bit_shift = (w - (num_copy_bc - 1) * BNU_CHUNK_BITS);
   const BNU_CHUNK_T vadd  = (BNU_CHUNK_T)(1ULL << num_bit_shift);
   const BNU_CHUNK_T mask  = (BNU_CHUNK_T)(vadd - 1);

   ZEXPAND_COPY_BNU(r, elemSize, a, num_copy_bc);
   r[num_copy_bc - 1] = (r[num_copy_bc - 1] & mask) + vadd;
   return;
}

/* clang-format off */
__IPPCP_INLINE void cpSM2KE_get_affine_ext_euclid(BNU_CHUNK_T *x, BNU_CHUNK_T *y,
                                            const IppsGFpECPoint *p,
                                            IppsGFpECState *pEC)
/* clang-format on */
{
   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));

   gfec_GetPoint(x, y, p, pEC);
   GFP_METHOD(pME)->decode(x, x, pME);
   GFP_METHOD(pME)->decode(y, y, pME);
   return;
}

__IPPCP_INLINE void cpSM2KE_xy_to_BE(BNU_CHUNK_T *x, BNU_CHUNK_T *y, const IppsGFpECState *pEC)
{
   const gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));

   const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
   const int elemBytes = (elemBits + 7) / 8; /* size Bytes */

   cpSM2KE_reverse_inplace((Ipp8u *)x, elemBytes);
   cpSM2KE_reverse_inplace((Ipp8u *)y, elemBytes);
   return;
}

/**
 * @brief
 * comput SM3 hash by message
 * @param[out] r        hash SM3 compute
 * @param[in]  a        hashing an array data
 * @param[in]  numBytes number of bytes
 */
__IPPCP_INLINE void cpSM2KE_compute_hash_SM3(Ipp8u *r, const Ipp8u *a, const int numBytes)
{
   static IppsHashState_rmf ctx;

   /* init */
   ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());
   /* update hash */
   ippsHashUpdate_rmf(a, numBytes, &ctx);
   /* final */
   ippsHashFinal_rmf(r, &ctx);
   return;
}

/* clang-format off */
/* compute Za digest = SM3( ENTL || ID || a || b || xG || yG || xA || yA ) */
#define computeZa_user_id_hash_sm2 OWNAPI(computeZa_user_id_hash_sm2)
IPP_OWN_DECL(IppStatus, computeZa_user_id_hash_sm2, (Ipp8u * pZa_digest,
                                                     const Ipp8u* p_user_id, const int user_id_len,
                                                     const int elem_len,
                                                     const Ipp8u* a, const Ipp8u* b,
                                                     const Ipp8u* Gx, const Ipp8u* Gy,
                                                     const Ipp8u* pub_key_x, const Ipp8u* pub_key_y))

/* KDF sm3 */
#define KDF_sm3 OWNAPI(KDF_sm3)
IPP_OWN_DECL(IppStatus, KDF_sm3, (Ipp8u * pKDF, int kdf_len,
                                  const Ipp8u* pZ, const int z_len))

/* IFMA optimization SM2 Key Exchange Shared Key */
#define gfec_key_exchange_sm2_shared_key_avx512 OWNAPI(gfec_key_exchange_sm2_shared_key_avx512)

IPP_OWN_DECL(IppStatus, gfec_key_exchange_sm2_shared_key_avx512, (Ipp8u* pSharedKey, const int sharedKeySize,
                                                                  Ipp8u* pSSelf,
                                                                  const IppsBigNumState* pPrvKey,
                                                                  IppsBigNumState* pEphPrvKey,
                                                                  IppsGFpECKeyExchangeSM2State *pKE, Ipp8u* pScratchBuffer))
/* clang-format on */

#endif // _SM2_STUFF_H
