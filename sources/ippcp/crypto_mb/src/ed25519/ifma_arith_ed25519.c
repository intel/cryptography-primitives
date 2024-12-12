/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>

#include <internal/ed25519/ifma_arith_p25519.h>
#include <internal/ed25519/ifma_arith_ed25519.h>
#include <internal/ed25519/ifma_ed25519_precomp4.h>

#if (_MBX >= _MBX_K1)

#define BP_WIN_SIZE MUL_BASEPOINT_WIN_SIZE /* defined in the header above */

/*
// Twisted Edwards Curve parameters
*/

/* d = -(121665/121666) */
__ALIGN64 static const int64u ed25519_d[FE_LEN52][sizeof(U64) / sizeof(int64u)] = {
    { REP8_DECL(0x000b4dca135978a3) },
    { REP8_DECL(0x0004d4141d8ab75e) },
    { REP8_DECL(0x000779e89800700a) },
    { REP8_DECL(0x000fe738cc740797) },
    { REP8_DECL(0x000052036cee2b6f) }
};

/* (2*d) */
__ALIGN64 static const int64u ed25519_d2[FE_LEN52][sizeof(U64) / sizeof(int64u)] = {
    { REP8_DECL(0x00069b9426b2f159) },
    { REP8_DECL(0x0009a8283b156ebd) },
    { REP8_DECL(0x000ef3d13000e014) },
    { REP8_DECL(0x000fce7198e80f2e) },
    { REP8_DECL(0x00002406d9dc56df) }
};

/* 2^((p-1)/4) = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0 */
__ALIGN64 static const int64u ed25519_2_pm1_4[FE_LEN52][sizeof(U64) / sizeof(int64u)] = {
    { REP8_DECL(0x000e1b274a0ea0b0) },
    { REP8_DECL(0x00006ad2fe478c4e) },
    { REP8_DECL(0x000dfbd7a72f4318) },
    { REP8_DECL(0x000df0b2b4d00993) },
    { REP8_DECL(0x00002b8324804fc1) }
};

/* ext => cached */
__MBX_INLINE void ge_ext_to_cached_mb(ge52_cached_mb* r, const ge52_ext_mb* p)
{
    fe52_add(r->YaddX, p->Y, p->X);
    fe52_sub(r->YsubX, p->Y, p->X);
    fe52_copy_mb(r->Z, p->Z);
    fe52_mul(r->T2d, p->T, (U64*)ed25519_d2);
}

/*
// r = p + q
*/
static void ge52_add_precomp(ge52_p1p1_mb* r, const ge52_ext_mb* p, const ge52_precomp_mb* q)
{
    fe52_mb t0;

    fe52_add(r->X, p->Y, p->X);     // X3 = Y1+X1
    fe52_sub(r->Y, p->Y, p->X);     // Y3 = Y1-X1
    fe52_mul(r->Z, r->X, q->yaddx); // Z3 = X3*yplusx2
    fe52_mul(r->Y, r->Y, q->ysubx); // Y3 = Y3*yminisx2
    fe52_mul(r->T, q->t2d, p->T);   // T3 = T1*xy2d2
    fe52_add(t0, p->Z, p->Z);       // t0 = Z1+Z1
    // X3 = Z3-Y3 = X3*yplusx2 - Y3*yminisx2 = (Y1+X1)*yplusx2 - (Y1-X1)*yminisx2
    fe52_sub(r->X, r->Z, r->Y);
    // Y3 = Z3+Y3 = X3*yplusx2 + Y3*yminisx2 = (Y1+X1)*yplusx2 + (Y1-X1)*yminisx2
    fe52_add(r->Y, r->Z, r->Y);
    fe52_add(r->Z, t0, r->T); // Z3 = 2*Z1 + T1*xy2d2
    fe52_sub(r->T, t0, r->T); // T3 = 2*Z1 - T1*xy2d2
}

static void ge_add(ge52_p1p1_mb* r, const ge52_ext_mb* p, const ge52_cached_mb* q)
{
    fe52_mb t0;

    fe52_add(r->X, p->Y, p->X);
    fe52_sub(r->Y, p->Y, p->X);
    fe52_mul(r->Z, r->X, q->YaddX);
    fe52_mul(r->Y, r->Y, q->YsubX);
    fe52_mul(r->T, q->T2d, p->T);
    fe52_mul(r->X, p->Z, q->Z);
    fe52_add(t0, r->X, r->X);
    fe52_sub(r->X, r->Z, r->Y);
    fe52_add(r->Y, r->Z, r->Y);
    fe52_add(r->Z, t0, r->T);
    fe52_sub(r->T, t0, r->T);
}

/* r = 2 * p */
static void ge_dbl(ge52_p1p1_mb* r, const ge52_homo_mb* p)
{
    fe52_mb t0;

    fe52_sqr(r->X, p->X);
    fe52_sqr(r->Z, p->Y);
    fe52_sqr(r->T, p->Z);
    fe52_add(r->T, r->T, r->T);
    fe52_add(r->Y, p->X, p->Y);
    fe52_sqr(t0, r->Y);
    fe52_add(r->Y, r->Z, r->X);
    fe52_sub(r->Z, r->Z, r->X);
    fe52_sub(r->X, t0, r->Y);
    fe52_sub(r->T, r->T, r->Z);
}


#define PARITY_SLOT ((GE25519_COMP_BITSIZE - 1) / DIGIT_SIZE)
#define PARITY_BIT  (1LL << ((GE25519_COMP_BITSIZE - 1) % DIGIT_SIZE))

#define SIGN_FE52(fe)   srli64((fe)[PARITY_SLOT], ((GE25519_COMP_BITSIZE - 1) % DIGIT_SIZE))
#define PARITY_FE52(fe) and64_const((fe)[0], 1)

/* compress point */
void ge52_ext_compress(fe52_mb r, const ge52_ext_mb* p)
{
    fe52_mb recip;
    fe52_mb x;
    fe52_mb y;

    fe52_inv(recip, p->Z);
    fe52_mul(x, p->X, recip);
    fe52_mul(y, p->Y, recip);
    fe52_red(x, x);
    fe52_red(y, y);

    __mb_mask is_negative = cmp64_mask(and64_const(x[0], 1), set1(1), _MM_CMPINT_EQ);
    y[(GE25519_COMP_BITSIZE - 1) / DIGIT_SIZE] =
        _mm512_mask_or_epi64(y[(GE25519_COMP_BITSIZE - 1) / DIGIT_SIZE],
                             is_negative,
                             y[(GE25519_COMP_BITSIZE - 1) / DIGIT_SIZE],
                             set1(1LL << (GE25519_COMP_BITSIZE - 1) % DIGIT_SIZE));

    fe52_copy_mb(r, y);
}

/* decompress point */
__mb_mask ge52_ext_decompress(ge52_ext_mb* r, const fe52_mb compressed_point)
{
    fe52_mb x;
    fe52_mb y;

    fe52_mb u;
    fe52_mb v;
    fe52_mb v3;
    fe52_mb vxx;

    /* initial values are neutral */
    neutral_ge52_ext_mb(r);

    /* y = fe and clear "x-sign" bit */
    fe52_copy_mb(y, compressed_point);
    y[FE_LEN52 - 1] = and64_const(y[FE_LEN52 - 1], PRIME25519_HI);

    /* x^2 = (y^2 -1) / (d y^2 +1) = u/v. compute numerator (u) and denominator (v) */
    fe52_sqr(u, y);
    fe52_mul(v, u, (U64*)ed25519_d);
    fe52_sub(u, u, r->Z); /* u = y^2-1 */
    fe52_add(v, v, r->Z); /* v = dy^2+1 */

    /*
   // compute candidate x = sqrt(u/v) = uv^3(uv^7)^((p-5)/8)
   */
    fe52_sqr(v3, v);
    fe52_mul(v3, v3, v);   /* v3 = v^3 */
    fe52_sqr(x, v3);
    fe52_mul(x, x, v);
    fe52_mul(x, x, u);     /* x = uv^7 */

    fe52_p2_252m3(x, x);   /* x = (uv^7)^((p-5)/8) */
    fe52_mul(x, x, v3);
    fe52_mul(x, x, u);     /* x = uv^3(uv^7)^((p-5)/8) */

    fe52_sqr(vxx, x);
    fe52_mul(vxx, vxx, v); /* vxx = v*x^2 */

    /* case 1: check if v*x^2 == u */
    fe52_sub(v3, vxx, u); /* v*x^2-u */
    __mb_mask k1 = fe52_mb_is_zero(v3);
    fe52_cmov_mb(r->X, r->X, k1, x);

    /* case 2: check if v*x^2 == -u */
    fe52_add(v3, vxx, u);
    __mb_mask k2 = fe52_mb_is_zero(v3);
    fe52_mul(x, x, (U64*)ed25519_2_pm1_4);
    fe52_cmov_mb(r->X, r->X, k2, x);

    /* copy y coordinate*/
    __mb_mask k = k1 | k2;
    fe52_cmov_mb(r->Y, r->Y, k, y);

    /* set x to (-x) if x.parity different with compressed_point.sign */
    k1 = cmp64_mask(SIGN_FE52(compressed_point), PARITY_FE52(r->X), _MM_CMPINT_NE);
    fe52_neg(v3, r->X);
    fe52_cmov_mb(r->X, r->X, k1, v3);

    /* update T component */
    fe52_mul(r->T, r->X, r->Y);

    return k;
}


/* select from the pre-computed table */
static void extract_precomputed_basepoint_dual(ge52_precomp_mb* p0,
                                               ge52_precomp_mb* p1,
                                               const ge52_precomp* tbl,
                                               U64 idx0,
                                               U64 idx1)
{
    /* set h0, h1 to neutral point */
    neutral_ge52_precomp_mb(p0);
    neutral_ge52_precomp_mb(p1);

    /* indexes are considered as signed values */
    __mb_mask is_neg_idx0 = cmp64_mask(idx0, get_zero64(), _MM_CMPINT_LT);
    __mb_mask is_neg_idx1 = cmp64_mask(idx1, get_zero64(), _MM_CMPINT_LT);
    idx0                  = mask_sub64(idx0, is_neg_idx0, get_zero64(), idx0);
    idx1                  = mask_sub64(idx1, is_neg_idx1, get_zero64(), idx1);

    /* select p0, p1 wrt idx0, idx1 indexes */
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(1), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(1), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(2), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(2), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(3), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(3), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(4), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(4), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(5), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(5), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(6), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(6), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(7), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(7), _MM_CMPINT_EQ), tbl);
    tbl++;
    ge52_cmov1_precomp_mb(p0, p0, cmp64_mask(idx0, set1(8), _MM_CMPINT_EQ), tbl);
    ge52_cmov1_precomp_mb(p1, p1, cmp64_mask(idx1, set1(8), _MM_CMPINT_EQ), tbl);

    /* adjust for sign */
    fe52_mb neg;
    fe52_neg(neg, p0->t2d);
    fe52_cswap_mb(p0->ysubx, is_neg_idx0, p0->yaddx);
    fe52_cmov_mb(p0->t2d, p0->t2d, is_neg_idx0, neg);

    fe52_neg(neg, p1->t2d);
    fe52_cswap_mb(p1->ysubx, is_neg_idx1, p1->yaddx);
    fe52_cmov_mb(p1->t2d, p1->t2d, is_neg_idx1, neg);
}

/*
// r = [s]*G
//
// where s = s[0] + 256*s[1] +...+ 256^31*s[31]
//       G is the Ed25519 base point (x,4/5) with x positive.
//
// Preconditions:
//   s[31] <= 127
*/

/* if msb set */
__MBX_INLINE int32u isMsb_ct(int32u a) { return (int32u)0 - (a >> (sizeof(a) * 8 - 1)); }

/* tests if a==0 */
__MBX_INLINE int32u isZero(int32u a) { return isMsb_ct(~a & (a - 1)); }

/* tests if a==b */
__MBX_INLINE int32u isEqu(int32u a, int32u b) { return isZero(a ^ b); }

void ifma_ed25519_mul_basepoint(ge52_ext_mb* r, const U64 scalar[])
{
    /* implementation uses scalar representation over base b=16, q[i] are half-bytes */
    __ALIGN64 ge52_ext_mb r0; /* q[0]*16^0 + q[2]*16^2 + q[4]*16^4 + ...+ q[30]*16^30 */
    __ALIGN64 ge52_ext_mb r1; /* q[1]*16^1 + q[3]*16^3 + q[5]*16^5 + ...+ q[31]*16^31 */

    /* point extracted from the pre-computed table */
    __ALIGN64 ge52_precomp_mb h0;
    __ALIGN64 ge52_precomp_mb h1;

    /* temporary */
    __ALIGN64 ge52_p1p1_mb t;
    __ALIGN64 ge52_homo_mb s;

    /* initial values are neutral */
    neutral_ge52_ext_mb(&r0);
    neutral_ge52_ext_mb(&r1);

    /* pre-computed basepoint table  */
    ge52_precomp* tbl = &ifma_ed25519_bp_precomp[0][0];

    __mb_mask carry = 0; /* used in conversion to signed value */

    for (int n = 0; n < FE_LEN64; n++) {
        /* scalar value*/
        U64 scalarV = loadu64(&scalar[n]);

        for (int m = 0; m < sizeof(int64u); m++) {
            /* set if last byte processed */
            __mb_mask last_byte =
                (__mb_mask)(isEqu((n * sizeof(int64u) + m), FE_LEN64 * sizeof(int64u) - 1));

            /* extract 2 half-bytes */
            U64 q_even = and64_const(scalarV, 0x0f);
            U64 q_odd  = and64_const(srli64(scalarV, 4), 0x0f);
            /* to the next byte of scalar value */
            scalarV = srli64(scalarV, 8);

            /* convert half-bytes to signed */
            q_even = mask_add64(q_even, carry, q_even, set1(1));
            carry  = cmp64_mask(set1(8), q_even, _MM_CMPINT_LE);
            q_even = mask_sub64(q_even, carry, q_even, set1(0x10));

            q_odd = mask_add64(q_odd, carry, q_odd, set1(1));
            carry = cmp64_mask(set1(8), q_odd, _MM_CMPINT_LE);
            carry &= ~last_byte; /* avoid sign conversion for the last half-byte*/
            q_odd = mask_sub64(q_odd, carry, q_odd, set1(0x10));

            /* extract points from the pre-computed table */
            extract_precomputed_basepoint_dual(&h0, &h1, tbl, q_even, q_odd);
            tbl += BP_N_ENTRY;

            /* r0 += h0, r1 += h1 */
            ge52_add_precomp(&t, &r0, &h0);
            ge52_p1p1_to_ext_mb(&r0, &t);

            ge52_add_precomp(&t, &r1, &h1);
            ge52_p1p1_to_ext_mb(&r1, &t);
        }
    }

    /* r1 = [16]*r1 */
    ge52_ext_to_homo_mb(&s, &r1);

    ge_dbl(&t, &s);
    ge52_p1p1_to_homo_mb(&s, &t);

    ge_dbl(&t, &s);
    ge52_p1p1_to_homo_mb(&s, &t);

    ge_dbl(&t, &s);
    ge52_p1p1_to_homo_mb(&s, &t);

    ge_dbl(&t, &s);
    ge52_p1p1_to_ext_mb(&r1, &t);

    // r = r0 + r1
    __ALIGN64 ge52_cached_mb c;
    ge_ext_to_cached_mb(&c, &r0);
    ge_add(&t, &r1, &c);

    ge52_p1p1_to_ext_mb(r, &t);
}


#define SCALAR_BITSIZE (256)
#define WIN_SIZE       (4)
/*
   s = (Ipp8u)(~((wvalue >> ws) - 1)); //sign
   d = (1 << (ws+1)) - wvalue - 1;     // digit, win size "ws"
   d = (d & s) | (wvaluen & ~s);
   d = (d >> 1) + (d & 1);
   *sign = s & 1;
   *digit = (Ipp8u)d;
*/
__MBX_INLINE void booth_recode(__mb_mask* sign, U64* dvalue, U64 wvalue)
{
    U64 one     = set1(1);
    U64 zero    = get_zero64();
    U64 t       = srli64(wvalue, WIN_SIZE);
    __mb_mask s = cmp64_mask(t, zero, _MM_CMPINT_NE);
    U64 d       = sub64(sub64(set1(1 << (WIN_SIZE + 1)), wvalue), one);
    d           = mask_mov64(wvalue, s, d);
    U64 odd     = and64(d, one);
    d           = add64(srli64(d, 1), odd);

    *sign   = s;
    *dvalue = d;
}

/* extract point */
static void extract_cached_point(ge52_cached_mb* r,
                                 const ge52_cached_mb tbl[],
                                 U64 idx,
                                 __mb_mask sign)
{
    /* decrement index (the table does not contain neutral element) */
    U64 idx_target = sub64(idx, set1(1));

    neutral_ge52_cached_mb(r);

    /* find out what we actually need or just keep neutral */
    int32u n;
    for (n = 0; n < (1 << (WIN_SIZE - 1)); n++) {
        U64 idx_curr = set1(n);
        __mb_mask k  = cmp64_mask(idx_curr, idx_target, _MM_CMPINT_EQ);
        /* r = k? tbl[] : r */
        cmov_ge52_cached_mb(r, r, k, &tbl[n]);
    }

    /* adjust for sign */
    fe52_mb neg;
    fe52_neg(neg, r->T2d);
    fe52_cswap_mb(r->YsubX, sign, r->YaddX);
    fe52_cmov_mb(r->T2d, r->T2d, sign, neg);
}

/*
// r = [s]*P
//
// where s = s[0] + 256*s[1] +...+ 256^31*s[31]
//       P is an arbitrary Ed25519 point.
*/
void ifma_ed25519_mul_point(ge52_ext_mb* r, const ge52_ext_mb* p, const U64 scalar[])
{
    __ALIGN64 ge52_p1p1_mb p1p1;
    __ALIGN64 ge52_homo_mb homo;
    __ALIGN64 ge52_cached_mb cached;
    __ALIGN64 ge52_ext_mb ext;

    /* generate the table  tbl[] = {p, [2]p, [3]p, [4]p, [5]p, [6]p, [7]p, [8]p} */
    __ALIGN64 ge52_cached_mb tbl[1 << (WIN_SIZE - 1)];
    int n;
    ge_ext_to_cached_mb(&tbl[0], p);   /* tbl[0] = p */
    for (n = 1; n < (1 << (WIN_SIZE - 1)); n++) {
        ge_add(&p1p1, p, &tbl[n - 1]); /* tbl[n] = p + tbl[n-1] */
        ge52_p1p1_to_ext_mb(&ext, &p1p1);
        ge_ext_to_cached_mb(&tbl[n], &ext);
    }

    /* ext = neutral */
    neutral_ge52_ext_mb(&ext);

    /*
   // point (LR) multiplication, 256-bit scalar
   */
    U64 idx_mask    = set1((1 << (WIN_SIZE + 1)) - 1);
    int bit         = SCALAR_BITSIZE - (SCALAR_BITSIZE % WIN_SIZE);
    int chunk_no    = (bit - 1) / 64;
    int chunk_shift = (bit - 1) % 64;

    U64 dvalue;      /* digit value */
    __mb_mask dsign; /* digit sign  */

    /*
   // first window
   */
    U64 wvalue = loadu64(&scalar[chunk_no]);
    wvalue     = and64(srli64(wvalue, chunk_shift), idx_mask);

    booth_recode(&dsign, &dvalue, wvalue);
    extract_cached_point(&cached, tbl, dvalue, dsign);

    /* ext = cached */
    ge_add(&p1p1, &ext, &cached);
    ge52_p1p1_to_ext_mb(&ext, &p1p1);

    /*
   // other windows
   */
    for (bit -= WIN_SIZE; bit >= WIN_SIZE; bit -= WIN_SIZE) {
        /* 4-x doubling: ext = [16]ext */
        ge52_ext_to_homo_mb(&homo, &ext);

        ge_dbl(&p1p1, &homo);
        ge52_p1p1_to_homo_mb(&homo, &p1p1);
        ge_dbl(&p1p1, &homo);
        ge52_p1p1_to_homo_mb(&homo, &p1p1);
        ge_dbl(&p1p1, &homo);
        ge52_p1p1_to_homo_mb(&homo, &p1p1);
        ge_dbl(&p1p1, &homo);
        ge52_p1p1_to_ext_mb(&ext, &p1p1);

        /* extract precomputed []P */
        chunk_no    = (bit - 1) / 64;
        chunk_shift = (bit - 1) % 64;

        wvalue = loadu64(&scalar[chunk_no]);
        wvalue =
            _mm512_shrdv_epi64(wvalue, loadu64(&scalar[chunk_no + 1]), set1((int32u)chunk_shift));
        wvalue = and64(wvalue, idx_mask);

        booth_recode(&dsign, &dvalue, wvalue);
        extract_cached_point(&cached, tbl, dvalue, dsign);

        /* accumulate ext += cached */
        ge_add(&p1p1, &ext, &cached);
        ge52_p1p1_to_ext_mb(&ext, &p1p1);
    }

    /*
   // last window
   */
    ge52_ext_to_homo_mb(&homo, &ext);
    ge_dbl(&p1p1, &homo);
    ge52_p1p1_to_homo_mb(&homo, &p1p1);
    ge_dbl(&p1p1, &homo);
    ge52_p1p1_to_homo_mb(&homo, &p1p1);
    ge_dbl(&p1p1, &homo);
    ge52_p1p1_to_homo_mb(&homo, &p1p1);
    ge_dbl(&p1p1, &homo);
    ge52_p1p1_to_ext_mb(&ext, &p1p1);

    /* extract precomputed []P */
    wvalue = loadu64(&scalar[0]);
    wvalue = and64(slli64(wvalue, 1), idx_mask);
    booth_recode(&dsign, &dvalue, wvalue);
    extract_cached_point(&cached, tbl, dvalue, dsign);

    /* accumulate ext += cached */
    ge_add(&p1p1, &ext, &cached);
    ge52_p1p1_to_ext_mb(r, &p1p1);
}
#undef SCALAR_BITSIZE
#undef WIN_SIZE

/* R = [p]P + [g]G */
void ifma_ed25519_prod_point(ge52_ext_mb* r,
                             const ge52_ext_mb* p,
                             const U64 scalarP[],
                             const U64 scalarG[])
{
    __ALIGN64 ge52_ext_mb T_mb;
    ifma_ed25519_mul_point(r, p, scalarP);
    ifma_ed25519_mul_basepoint(&T_mb, scalarG);

    __ALIGN64 ge52_cached_mb c;
    __ALIGN64 ge52_p1p1_mb t;
    ge_ext_to_cached_mb(&c, &T_mb);
    ge_add(&t, r, &c);
    ge52_p1p1_to_ext_mb(r, &t);
}

#endif /* #if (_MBX>=_MBX_K1) */
