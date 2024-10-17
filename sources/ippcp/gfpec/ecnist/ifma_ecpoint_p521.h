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
#ifndef IFMA_ECPOINT_P521_H
#define IFMA_ECPOINT_P521_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_defs_p521.h"

typedef struct P521_POINT_IFMA {
   fe521 x;
   fe521 y;
   fe521 z;
} P521_POINT_IFMA;

typedef struct P521_POINT_AFFINE_IFMA {
   fe521 x;
   fe521 y;
} P521_POINT_AFFINE_IFMA;

/**
 * \brief
 * compute R = [pExtendedScalar]*P = (P + P + ... + P)
 * \param[out] r point (in radix 2^52)
 * \param[in]  p point (in radix 2^52)
 * \param[in]  pExtendedScalar ptr Extended scalar
 * \param[in]  scalarBitSize   size bits scalar
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_mul_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const Ipp8u *pExtendedScalar, const int scalarBitSize))

/**
 * \brief
 * compute [pExtendedScalar]*BP
 * \param[out] r point (in radix 2^52)
 * \param pExtendedScalar ptr scaler (length 384 bits)
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_mul_pointbase, (P521_POINT_IFMA * r, const Ipp8u *pExtendedScalar, int scalarBitSize))

/**
 * \brief
 * convert point to affine coordinate
 * \param[out] prx affine X coordinate
 * \param[out] pry affine Y coordinate
 * \param[in]  a   point
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_get_affine_coords, (fe521 prx[], fe521 pry[], const P521_POINT_IFMA *a))

/**
 * \brief
 * check point on curve P521R1
 * \param[in] p                point (in radix 2^52)
 * \param[in] use_jproj_coords is Jacobian Projection coordinate or Affine Coordinate
 * \return int 1 - is true | 0 - is false
 */
IPP_OWN_DECL(int, ifma_ec_nistp521_is_on_curve, (const P521_POINT_IFMA *p, const int use_jproj_coords))

/**
 * \brief
 * compute double point P521R1 Enhanced Montgomery Algorithm
 * \param[out] r point
 * \param[in]  p value point (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_dbl_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p))

/**
 * \brief
 * compute add point P384R1 Enhanced Montgomery Algorithm
 * \param[out] r point
 * \param[in]  p first  point (in radix 2^52)
 * \param[in]  q second point (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_add_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const P521_POINT_IFMA *q))

/**
 * \brief
 * compute add point affine P384R1 Enhanced Montgomery Algorithm
 * \param[out] r point
 * \param[in]  p first  point (in radix 2^52)
 * \param[in]  q second affine point (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_ec_nistp521_add_point_affine, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const P521_POINT_AFFINE_IFMA *q))

#include "gfpec/ecnist/ifma_arith_method_p521.h"
#include "gsmodstuff.h"
#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"

__IPPCP_INLINE void recode_point_to_mont52(P521_POINT_IFMA *pR,
                                     const BNU_CHUNK_T *pP,
                                     BNU_CHUNK_T *pPool,
                                     ifmaArithMethod_p521 *method,
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

   to_radix52(&(pR->x), (Ipp64u *)pX);
   to_radix52(&(pR->y), (Ipp64u *)pY);
   to_radix52(&(pR->z), (Ipp64u *)pZ);

   p_to_mont(&(pR->x), pR->x);
   p_to_mont(&(pR->y), pR->y);
   p_to_mont(&(pR->z), pR->z);
}

__IPPCP_INLINE void recode_point_to_mont64(IppsGFpECPoint *pR,
                                     P521_POINT_IFMA *pP,
                                     BNU_CHUNK_T *pPool,
                                     ifmaArithMethod_p521 *method,
                                     gsModEngine *pME)
{
   ifma_export to_radix64  = method->export_to64;
   ifma_decode p_from_mont = method->decode;

   const int elemLen = GFP_PELEN(pME);
   BNU_CHUNK_T *pX   = pPool;
   BNU_CHUNK_T *pY   = pPool + elemLen;
   BNU_CHUNK_T *pZ   = pPool + 2 * elemLen;

   p_from_mont(&(pP->x), pP->x);
   p_from_mont(&(pP->y), pP->y);
   p_from_mont(&(pP->z), pP->z);

   to_radix64((Ipp64u *)pX, pP->x);
   to_radix64((Ipp64u *)pY, pP->y);
   to_radix64((Ipp64u *)pZ, pP->z);

   GFP_METHOD(pME)->encode(ECP_POINT_X(pR), pX, pME);
   GFP_METHOD(pME)->encode(ECP_POINT_Y(pR), pY, pME);
   GFP_METHOD(pME)->encode(ECP_POINT_Z(pR), pZ, pME);
}


#endif // (_IPP32E >= _IPP32E_K1)

#endif
