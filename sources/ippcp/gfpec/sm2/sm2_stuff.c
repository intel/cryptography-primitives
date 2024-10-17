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
#include "owncp.h"
#include "gsmodstuff.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"

#include "gfpec/sm2/sm2_stuff.h"

/**
 * @brief
 * compute Za digest = SM3( ENTL || ID || a || b || xG || yG || xA || yA )
 * @param [out] pZa_digest   (Za)   output digest Za
 * @param [in]  p_user_id    (ID)   data user ID
 * @param [in]  user_id_len  (ENTL) length user ID
 * @param [in]  elem_len     length element bytes
 * @param [in]  a            (a)    coefficient a of Elliptic Curve
 * @param [in]  b            (b)    coefficient b of Elliptic Curve
 * @param [in]  Gx           (Gx)   base point coordinate X of Elliptic Curve
 * @param [in]  Gy           (Gy)   base point coordinate Y of Elliptic Curve
 * @param [in]  pub_key_x    (xA)   public point coordinate X
 * @param [in]  pub_key_y    (yA)   public point coordinate Y
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, computeZa_user_id_hash_sm2, (Ipp8u * pZa_digest,
                                                     const Ipp8u *p_user_id, const int user_id_len,
                                                     const int elem_len,
                                                     const Ipp8u *a, const Ipp8u *b,
                                                     const Ipp8u *Gx, const Ipp8u *Gy,
                                                     const Ipp8u *pub_key_x, const Ipp8u *pub_key_y))
/* clang-format on */
{
   /* check pointer Za Digest | user id */
   IPP_BAD_PTR2_RET(pZa_digest, p_user_id);
   /* check border (user_id_len > 0) | (elem_len > 0) */
   IPP_BADARG_RET(!(user_id_len > 0) || !(elem_len > 0), ippStsBadArgErr);
   /* check (user_id_len*8 <= 0xFFFF) ~ (user_id_len <= 0x1FFF) for two bytes overflow.
      user_id_len*8 operation will be executed in algorithm's flow */
   IPP_BADARG_RET(user_id_len > 0x1FFF, ippStsBadArgErr);
   /* param curve: a, b, Gx, Gy */
   IPP_BAD_PTR2_RET(a, b);
   IPP_BAD_PTR2_RET(Gx, Gy);
   /* Public X|Y */
   IPP_BAD_PTR2_RET(pub_key_x, pub_key_y)

   static IppsHashState_rmf ctx;

   ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());

   /* compute Za = SM3( ENTL || ID || a || b || xG || yG || xA || yA ) */
   /* ENLT */
   const Ipp16u entl = ((user_id_len * 8) & 0xFFFF);
   Ipp8u ENTL[sizeof(Ipp16u)];
   ENTL[0] = (Ipp8u)(entl >> 8);
   ENTL[1] = (Ipp8u)(entl & 0xFF);
   ippsHashUpdate_rmf(ENTL, sizeof(ENTL), &ctx);
   /* ID */
   ippsHashUpdate_rmf(p_user_id, user_id_len, &ctx);
   /* a */
   ippsHashUpdate_rmf(a, elem_len, &ctx);
   /* b */
   ippsHashUpdate_rmf(b, elem_len, &ctx);
   /* Gx */
   ippsHashUpdate_rmf(Gx, elem_len, &ctx);
   /* Gy */
   ippsHashUpdate_rmf(Gy, elem_len, &ctx);
   /* Px */
   ippsHashUpdate_rmf(pub_key_x, elem_len, &ctx);
   /* Py */
   ippsHashUpdate_rmf(pub_key_y, elem_len, &ctx);

   /* final */
   ippsHashFinal_rmf(pZa_digest, &ctx);

   /* clear stack data */
   PurgeBlock(ENTL, sizeof(ENTL));

   return ippStsNoErr;
}

#define SIZE_CT (4)

__IPPCP_INLINE void convert_ct_to_big_endian(Ipp8u pCt[SIZE_CT], const Ipp32u ct)
{
   pCt[0] = (Ipp8u)(ct >> 24);
   pCt[1] = (Ipp8u)(ct >> 16);
   pCt[2] = (Ipp8u)(ct >> 8);
   pCt[3] = (Ipp8u)(ct);
   return;
}

/**
 * @brief compute KDF base by SM3 hash
 * @param [out] pKDF    pointer output KDF
 * @param [in]  kdf_len length KDF
 * @param [in]  pZ      data Z to create KDF
 * @param [in]  z_len   length Z data
 * bound kdf_len in standard:
 *
 */
IPP_OWN_DEFN(IppStatus, KDF_sm3, (Ipp8u * pKDF, int kdf_len, const Ipp8u *pZ, const int z_len))
{
   /* check pointer input */
   IPP_BAD_PTR2_RET(pKDF, pZ);
   /* [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves Part 3: Key exchange protocol
    * 5.4.3 Key derivation function
    * kdf_len < (2^32 - 1) * 2^5 = 2^37 - 32 [bytes]
    * BUT if input INT type - NO NEED check this border
    */
   /* check border (kdf_len >= 0) */
   IPP_BADARG_RET(!(kdf_len >= 0), ippStsBadArgErr);
   /* check border (z_len > 0) */
   IPP_BADARG_RET(!(z_len > 0), ippStsBadArgErr);

   /* if kdf > 0 */
   if (kdf_len > 0) {
      /* buffer */
      Ipp8u buff[IPP_SM3_DIGEST_BYTESIZE];

      // step (a)
      Ipp8u pCt[SIZE_CT];

      const Ipp32u n = (Ipp32u)((kdf_len + IPP_SM3_DIGEST_BYTESIZE - 1) / IPP_SM3_DIGEST_BYTESIZE) + 1u; /* add 1 - loop start 1 */

      /* init copy output len */
      int num_copy = IPP_SM3_DIGEST_BYTESIZE;

      static IppsHashState_rmf ctx;
      ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());

      /* compute length K = Ha1 || Ha2 || ... */
      // step (b)
      for (Ipp32u i = 1u; i < n; ++i) {
         // step (b.1) -> Hai = H(Z || ct)
         /* Z */
         ippsHashUpdate_rmf(pZ, z_len, &ctx);
         /* ct */
         convert_ct_to_big_endian(pCt, i);
         ippsHashUpdate_rmf(pCt, sizeof(pCt), &ctx);
         /* auto init of end function - no need call in start loop */
         ippsHashFinal_rmf(buff, &ctx);
         /* copy result */
         if ((i == n - 1u) && (0 != kdf_len % IPP_SM3_DIGEST_BYTESIZE)) {
            num_copy = kdf_len % IPP_SM3_DIGEST_BYTESIZE;
         }
         cpSM2_CopyBlock(pKDF, buff, num_copy);

         /* update copy next result */
         pKDF += num_copy;
         kdf_len -= num_copy;
      }

      /* clear stack data */
      PurgeBlock(buff, sizeof(buff));
      PurgeBlock(pCt, sizeof(pCt));
   }

   return ippStsNoErr;
}

#undef SIZE_CT
