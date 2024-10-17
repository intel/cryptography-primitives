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

#if !defined(_IFMA_ECPOINT_SM2_H_)
#define _IFMA_ECPOINT_SM2_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/sm2/ifma_arith_psm2.h"
#include "pcpbnuimpl.h"

/* SM2 point (x,y,z) */
typedef struct PSM2_POINT_IFMA {
    fesm2 x;
    fesm2 y;
    fesm2 z;
} PSM2_POINT_IFMA;

/* SM2 affine point (x,y) */
typedef struct PSM2_AFFINE_POINT_IFMA {
    fesm2 x;
    fesm2 y;
} PSM2_AFFINE_POINT_IFMA;

/**
 * \brief
 *
 * compute R = [pExtendedScalar]*P = (P + P + ... + P)
 *
 * \param[out] r point (in radix 2^52)
 * \param[in]  p point (in radix 2^52)
 * \param[in]  pExtendedScalar ptr Extended scalar
 * \param[in]  scalarBitSize   size bits scalar
 */
IPP_OWN_DECL(void, gesm2_mul, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const Ipp8u* pExtendedScalar, const int scalarBitSize))

/**
 * \brief
 *
 * compute R = [pExtendedScalar]*BasePoint
 *
 * \param[out] r point (in radix 2^52)
 * \param pExtendedScalar ptr scaler (length 256 bits)
 */
IPP_OWN_DECL(void, gesm2_mul_base, (PSM2_POINT_IFMA * r, const Ipp8u* pExtendedScalar))

/**
 * \brief
 *
 * convert point to affine coordinate
 *
 * \param[out] r point affine coordinate
 * \param[in]  a point
 */
IPP_OWN_DECL(void, gesm2_to_affine, (fesm2 px[], fesm2 py[], const PSM2_POINT_IFMA* a))

/**
 * \brief
 *
 * check point on curve SM2
 *
 * \param[in] p                point (in radix 2^52)
 * \param[in] use_jproj_coords is Jacobian Projection coordinate or Affine Coordinate
 * \return int 1 - is true | 0 - is false
 */
IPP_OWN_DECL(int, gesm2_is_on_curve, (const PSM2_POINT_IFMA* p, const int use_jproj_coords))

/**
 * \brief
 *
 * compute double point SM2 (Enhanced Montgomery Algorithm)
 *
 * \param[out] r point
 * \param[in]  p value point (in radix 2^52)
 */
IPP_OWN_DECL(void, gesm2_dbl, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p))

/**
 * \brief
 *
 * compute add point SM2 (Enhanced Montgomery Algorithm)
 *
 * \param[out] r point
 * \param[in]  p first  point (in radix 2^52)
 * \param[in]  q second point (in radix 2^52)
 */
IPP_OWN_DECL(void, gesm2_add, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const PSM2_POINT_IFMA* q))

/**
 * \brief
 *
 * compute add point affine SM2 (Enhanced Montgomery Algorithm)
 *
 * \param[out] r point
 * \param[in]  p first  point (in radix 2^52)
 * \param[in]  q second affine point (in radix 2^52)
 */
IPP_OWN_DECL(void, gesm2_add_affine, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const PSM2_AFFINE_POINT_IFMA* q))

/**
 *  \brief
 *
 *  Extracts affine point from the precomputed table.
 *
 * \param[out] pAffinePoint array of x and y coordinates of affine point in 2^64 radix
 * \param[in]  pTable pointer to a precomputed table
 * \param[in]  index index of desired point in the table
 */
IPP_OWN_DECL(void, gesm2_select_ap_w7_ifma, (BNU_CHUNK_T * pAffinePoint, const BNU_CHUNK_T* pTable, int index))

#include "gfpec/sm2/ifma_arith_method_sm2.h"
#include "gsmodstuff.h"
#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"

__IPPCP_INLINE void recode_point_to_mont52(PSM2_POINT_IFMA* pR,
                                     const BNU_CHUNK_T* pP,
                                     BNU_CHUNK_T* pPool,
                                     ifmaArithMethod* method,
                                     gsModEngine* pME) {
    ifma_import to_radix52 = method->import_to52;
    ifma_encode p_to_mont  = method->encode;

    const int elemLen = GFP_FELEN(pME);

    BNU_CHUNK_T* pX = pPool;
    BNU_CHUNK_T* pY = pPool + elemLen;
    BNU_CHUNK_T* pZ = pPool + 2 * elemLen;

    GFP_METHOD(pME)->decode(pX, pP, pME);
    GFP_METHOD(pME)->decode(pY, pP + elemLen, pME);
    GFP_METHOD(pME)->decode(pZ, pP + 2 * elemLen, pME);

    pR->x = to_radix52((Ipp64u*)pX);
    pR->y = to_radix52((Ipp64u*)pY);
    pR->z = to_radix52((Ipp64u*)pZ);

    pR->x = p_to_mont(pR->x);
    pR->y = p_to_mont(pR->y);
    pR->z = p_to_mont(pR->z);
}

__IPPCP_INLINE void recode_point_to_mont64(IppsGFpECPoint* pR,
                                     PSM2_POINT_IFMA* pP,
                                     BNU_CHUNK_T* pPool,
                                     ifmaArithMethod* method,
                                     gsModEngine* pME) {
    ifma_export to_radix64  = method->export_to64;
    ifma_decode p_from_mont = method->decode;

    const int elemLen = GFP_PELEN(pME);
    BNU_CHUNK_T* pX   = pPool;
    BNU_CHUNK_T* pY   = pPool + elemLen;
    BNU_CHUNK_T* pZ   = pPool + 2 * elemLen;

    pP->x = p_from_mont(pP->x);
    pP->y = p_from_mont(pP->y);
    pP->z = p_from_mont(pP->z);

    to_radix64((Ipp64u*)pX, pP->x);
    to_radix64((Ipp64u*)pY, pP->y);
    to_radix64((Ipp64u*)pZ, pP->z);

    GFP_METHOD(pME)->encode(ECP_POINT_X(pR), pX, pME);
    GFP_METHOD(pME)->encode(ECP_POINT_Y(pR), pY, pME);
    GFP_METHOD(pME)->encode(ECP_POINT_Z(pR), pZ, pME);
}

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_ECPOINT_SM2_H_
