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

/* Paper referenced in this header:
 *
 *  [1] "Enhanced Montgomery Multiplication" DOI:10.1155/2008/583926
 *
 */

#ifndef IFMA_ECPOINT_P384_H
#define IFMA_ECPOINT_P384_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_arith_p384.h"
#include "pcpbnuimpl.h"

/* p384 point (x,y,z) */
typedef struct {
   m512 x;
   m512 y;
   m512 z;
} P384_POINT_IFMA;

/* p384 affine point(x,y) */
typedef struct {
   m512 x;
   m512 y;
} P384_POINT_AFFINE_IFMA;

/**
 * \brief
 *
 *   R = [pExtendedScalar]*P = (P + P + ... + P)
 *
 * \param[out] r point in radix 2^52
 * \param[in]  p point in radix 2^52
 * \param[in]  pExtendedScalar pointer to a scalar
 * \param[in]  scalarBitSize   scalar size in bits
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_mul_point, (P384_POINT_IFMA * r, const P384_POINT_IFMA *p, const Ipp8u *pExtendedScalar, const int scalarBitSize))

/**
 * \brief
 *
 *   R = [pExtendedScalar]*BasePoint
 *
 * \param[out] r point in radix 2^52
 * \param[in]  pExtendedScalar pointer to a scalar
 * \param[in]  scalarBitSize   scalar size in bits
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_mul_pointbase, (P384_POINT_IFMA * r, const Ipp8u *pExtendedScalar, int scalarBitSize))

/**
 * \brief
 *
 * Convert point to affine coordinate
 *
 * \param[out] rx X-affine coordinate
 * \param[out] ry Y-affine coordinate
 * \param[in]  a  point in projective coordinates
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_get_affine_coords, (m512 * rx, m512 *ry, const P384_POINT_IFMA *a))

/**
 * \brief
 *
 * Check if the point is on curve p384r1
 *
 * \param[in] p                point in radix 2^52
 * \param[in] use_jproj_coords flag whether coordinates are in Projective of Affine representation
 * \return int 1 - true
 *             0 - false
 */
IPP_OWN_DECL(int, ifma_ec_nistp384_is_on_curve, (const P384_POINT_IFMA *p, const int use_jproj_coords))

/**
 * \brief
 *
 * Point doubling on p384r1 curve (Enhanced Montgomery Algorithm, see [1])
 *
 * \param[out] r point in projective coordinates
 * \param[in]  p point in projective coordinates
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_dbl_point, (P384_POINT_IFMA * r, const P384_POINT_IFMA *p))

/**
 * \brief
 *
 * Point addition on p384r1 curve (Enhanced Montgomery Algorithm, see [1])
 *
 * \param[out] r result point
 * \param[in]  p first point
 * \param[in]  q second point
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_add_point, (P384_POINT_IFMA * r, const P384_POINT_IFMA *p, const P384_POINT_IFMA *q))

/**
 * \brief
 *
 * Point addition on p384r1 curve (Enhanced Montgomery Algorithm, see [1])
 *
 * \param[out] r point in projective coordinates
 * \param[in]  p point in projective coordinates
 * \param[in]  q point in affine coordinates
 */
IPP_OWN_DECL(void, ifma_ec_nistp384_add_point_affine, (P384_POINT_IFMA * r, const P384_POINT_IFMA *p, const P384_POINT_AFFINE_IFMA *q))

/**
 *  \brief
 *
 *  Extracts affine point from the precomputed table.
 *
 * \param[out] pAffinePoint array of x and y coordinates of affine point in 2^64 radix
 * \param[in]  pTable pointer to a precomputed table
 * \param[in]  index index of desired point in the table
 */
IPP_OWN_DECL(void, p384r1_select_ap_w4_ifma, (BNU_CHUNK_T * pAffinePoint, const BNU_CHUNK_T *pTable, int index))


#include "gfpec/ecnist/ifma_arith_method.h"
#include "gsmodstuff.h"
#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"

__IPPCP_INLINE void recode_point_to_mont52(P384_POINT_IFMA *pR,
                                     const BNU_CHUNK_T *pP,
                                     BNU_CHUNK_T *pPool,
                                     ifmaArithMethod *method,
                                     gsModEngine *pME)
{
   ifma_import to_radix52 = method->import_to52;
   ifma_encode p_to_mont  = method->encode;

   const int elemLen = GFP_FELEN(pME);

   BNU_CHUNK_T *pX = pPool;
   BNU_CHUNK_T *pY = pPool + elemLen;
   BNU_CHUNK_T *pZ = pPool + 2 * elemLen;

   GFP_METHOD(pME)->decode(pX, pP, pME);
   GFP_METHOD(pME)->decode(pY, pP + elemLen, pME);
   GFP_METHOD(pME)->decode(pZ, pP + 2 * elemLen, pME);

   pR->x = to_radix52((Ipp64u *)pX);
   pR->y = to_radix52((Ipp64u *)pY);
   pR->z = to_radix52((Ipp64u *)pZ);

   pR->x = p_to_mont(pR->x);
   pR->y = p_to_mont(pR->y);
   pR->z = p_to_mont(pR->z);
}

__IPPCP_INLINE void recode_point_to_mont64(const IppsGFpECPoint *pR,
                                     P384_POINT_IFMA *pP,
                                     BNU_CHUNK_T *pPool,
                                     ifmaArithMethod *method,
                                     gsModEngine *pME)
{
   ifma_export to_radix64  = method->export_to64;
   ifma_decode p_from_mont = method->decode;

   const int elemLen = GFP_PELEN(pME);
   BNU_CHUNK_T *pX   = pPool;
   BNU_CHUNK_T *pY   = pPool + elemLen;
   BNU_CHUNK_T *pZ   = pPool + 2 * elemLen;

   pP->x = p_from_mont(pP->x);
   pP->y = p_from_mont(pP->y);
   pP->z = p_from_mont(pP->z);

   to_radix64((Ipp64u *)pX, pP->x);
   to_radix64((Ipp64u *)pY, pP->y);
   to_radix64((Ipp64u *)pZ, pP->z);

   GFP_METHOD(pME)->encode(ECP_POINT_X(pR), pX, pME);
   GFP_METHOD(pME)->encode(ECP_POINT_Y(pR), pY, pME);
   GFP_METHOD(pME)->encode(ECP_POINT_Z(pR), pZ, pME);
}


#endif // (_IPP32E >= _IPP32E_K1)

#endif // IFMA_ECPOINT_P384_H
