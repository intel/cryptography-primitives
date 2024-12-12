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

#ifndef IFMA_ED25519_H
#define IFMA_ED25519_H

#include <crypto_mb/ed25519.h>
#include <internal/ed25519/ifma_arith_p25519.h>

#if (_MBX >= _MBX_K1)

/* homogeneous: (X:Y:Z) satisfying x=X/Z, y=Y/Z */
typedef struct ge52_homo_mb_t {
    fe52_mb X;
    fe52_mb Y;
    fe52_mb Z;
} ge52_homo_mb;

/* extended homogeneous: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT */
typedef struct ge52_mb_t {
    fe52_mb X;
    fe52_mb Y;
    fe52_mb T;
    fe52_mb Z;
} ge52_ext_mb;

/* copmpleted: (X:Y:Z:T) satisfying x=X/Z, y=Y/T */
typedef struct ge52_p1p1_mb_t {
    fe52_mb X;
    fe52_mb Y;
    fe52_mb T;
    fe52_mb Z;
} ge52_p1p1_mb;

/* scalar precomputed group element: (y-x:y+x:2*t*d), t=x*y, ed25519 parameter d = -(121665/121666)*/
typedef struct ge52_precomp_t {
    fe52 ysubx;
    fe52 yaddx;
    fe52 t2d;
} ge52_precomp;

/* mb precomputed group element: (y-x:y+x:2*t*d), t=x*y, ed25519 parameter d = -(121665/121666)*/
typedef struct ge52_precomp_mb_t {
    fe52_mb ysubx;
    fe52_mb yaddx;
    fe52_mb t2d;
} ge52_precomp_mb;

/* projective falvor of the ge52_precomp_mb */
typedef struct ge52_cached_mb_t {
    fe52_mb YsubX;
    fe52_mb YaddX;
    fe52_mb T2d;
    fe52_mb Z;
} ge52_cached_mb;

/* bitsize of compression point */
#define GE25519_COMP_BITSIZE (P25519_BITSIZE + 1)

/*
// conversion
*/

/* ext => homo */
__MBX_INLINE void ge52_ext_to_homo_mb(ge52_homo_mb* r, const ge52_ext_mb* p)
{
    fe52_copy_mb(r->X, p->X);
    fe52_copy_mb(r->Y, p->Y);
    fe52_copy_mb(r->Z, p->Z);
}

/* p1p1 => homo */
__MBX_INLINE void ge52_p1p1_to_homo_mb(ge52_homo_mb* r, const ge52_p1p1_mb* p)
{
    fe52_mul(r->X, p->X, p->T);
    fe52_mul(r->Y, p->Y, p->Z);
    fe52_mul(r->Z, p->Z, p->T);
}

/* p1p1 => ext */
__MBX_INLINE void ge52_p1p1_to_ext_mb(ge52_ext_mb* r, const ge52_p1p1_mb* p)
{
    fe52_mul(r->X, p->X, p->T);
    fe52_mul(r->Y, p->Y, p->Z);
    fe52_mul(r->T, p->X, p->Y);
    fe52_mul(r->Z, p->Z, p->T);
}


/* set GE to neutral */
__MBX_INLINE void neutral_ge52_homo_mb(ge52_homo_mb* ge)
{
    fe52_0_mb(ge->X);
    fe52_1_mb(ge->Y);
    fe52_1_mb(ge->Z);
}
__MBX_INLINE void neutral_ge52_ext_mb(ge52_ext_mb* ge)
{
    fe52_0_mb(ge->X);
    fe52_1_mb(ge->Y);
    fe52_0_mb(ge->T);
    fe52_1_mb(ge->Z);
}
__MBX_INLINE void neutral_ge52_precomp_mb(ge52_precomp_mb* ge)
{
    fe52_1_mb(ge->ysubx);
    fe52_1_mb(ge->yaddx);
    fe52_0_mb(ge->t2d);
}
__MBX_INLINE void neutral_ge52_cached_mb(ge52_cached_mb* ge)
{
    fe52_1_mb(ge->YsubX);
    fe52_1_mb(ge->YaddX);
    fe52_0_mb(ge->T2d);
    fe52_1_mb(ge->Z);
}

/* move GE under mask (conditionally): r = k? a : b */
__MBX_INLINE void ge52_cmov1_precomp_mb(ge52_precomp_mb* r,
                                        const ge52_precomp_mb* b,
                                        __mb_mask k,
                                        const ge52_precomp* a)
{
    fe52_cmov1_mb(r->ysubx, b->ysubx, k, a->ysubx);
    fe52_cmov1_mb(r->yaddx, b->yaddx, k, a->yaddx);
    fe52_cmov1_mb(r->t2d, b->t2d, k, a->t2d);
}
__MBX_INLINE void cmov_ge52_precomp_mb(ge52_precomp_mb* r,
                                       const ge52_precomp_mb* b,
                                       __mb_mask k,
                                       const ge52_precomp_mb* a)
{
    fe52_cmov_mb(r->ysubx, b->ysubx, k, a->ysubx);
    fe52_cmov_mb(r->yaddx, b->yaddx, k, a->yaddx);
    fe52_cmov_mb(r->t2d, b->t2d, k, a->t2d);
}
__MBX_INLINE void cmov_ge52_cached_mb(ge52_cached_mb* r,
                                      const ge52_cached_mb* b,
                                      __mb_mask k,
                                      const ge52_cached_mb* a)
{
    fe52_cmov_mb(r->YsubX, b->YsubX, k, a->YsubX);
    fe52_cmov_mb(r->YaddX, b->YaddX, k, a->YaddX);
    fe52_cmov_mb(r->T2d, b->T2d, k, a->T2d);
    fe52_cmov_mb(r->Z, b->Z, k, a->Z);
}


/* private functions */
void ifma_ed25519_mul_basepoint(ge52_ext_mb* r, const U64 scalar[]);
void ifma_ed25519_mul_point(ge52_ext_mb* r, const ge52_ext_mb* p, const U64 scalar[]);
void ifma_ed25519_prod_point(ge52_ext_mb* r,
                             const ge52_ext_mb* p,
                             const U64 scalarP[],
                             const U64 scalarG[]);

void ge52_ext_compress(fe52_mb fe, const ge52_ext_mb* p);
__mb_mask ge52_ext_decompress(ge52_ext_mb* p, const fe52_mb fe);

mbx_status MB_FUNC_NAME(internal_avx512_ed25519_public_key_)(
    ed25519_public_key* pa_public_key[8],
    const ed25519_private_key* const pa_private_key[8]);

mbx_status MB_FUNC_NAME(internal_avx512_ed25519_sign_)(
    ed25519_sign_component* pa_sign_r[8],
    ed25519_sign_component* pa_sign_s[8],
    const int8u* const pa_msg[8],
    const int32u msgLen[8],
    const ed25519_private_key* const pa_private_key[8],
    const ed25519_public_key* const pa_public_key[8]);

mbx_status MB_FUNC_NAME(internal_avx512_ed25519_verify_)(
    const ed25519_sign_component* const pa_sign_r[8],
    const ed25519_sign_component* const pa_sign_s[8],
    const int8u* const pa_msg[8],
    const int32u msgLen[8],
    const ed25519_public_key* const pa_public_key[8]);

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* IFMA_ED25519_H */
