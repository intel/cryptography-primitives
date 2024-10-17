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

/* Paper referenced in this file:
 *
 *  [1] "Enhanced Montgomery Multiplication" DOI:10.1155/2008/583926
 *
 */

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/pcpgfpecstuff.h"

#include "gfpec/ecnist/ifma_arith_p256.h"
#include "gfpec/ecnist/ifma_defs.h"
#include "gfpec/ecnist/ifma_ecpoint_p256.h"

#define LEN64 (4)
#define LEN52 (5 + 3) /* 5 digits + 3 zero padding */

/* Modulus scaled: 2*p */
static const __ALIGN64 Ipp64u p256_x2[LEN52] = {
   0x000ffffffffffffe, 0x00001fffffffffff, 0x0000000000000000, 0x0000002000000000, 0x0001fffffffe0000, 0x0, 0x0, 0x0
};

/* Modulus scaled: 4*p */
static const __ALIGN64 Ipp64u p256_x4[LEN52] = {
   0x000ffffffffffffc, 0x00003fffffffffff, 0x0000000000000000, 0x0000004000000000, 0x0003fffffffc0000, 0x0, 0x0, 0x0
};

/* Modulus scaled: 6*p */
static const __ALIGN64 Ipp64u p256_x6[LEN52] = {
   0x000ffffffffffffa, 0x00005fffffffffff, 0x0000000000000000, 0x0000006000000000, 0x0005fffffffa0000, 0x0, 0x0, 0x0
};

/* Modulus scaled: 8*p */
static const __ALIGN64 Ipp64u p256_x8[LEN52] = {
   0x000ffffffffffff8, 0x00007fffffffffff, 0x0000000000000000, 0x0000008000000000, 0x0007fffffff80000, 0x0, 0x0, 0x0
};

/* Mont(a) = a*r mod p256, where r = 2^(6*52) mod p256 */
static const __ALIGN64 Ipp64u p256_a[LEN52] = {
   0x000ffffffd000000, 0x000fffffffffffcf, 0x000300000002ffff, 0x0000000000000000, 0x0000000000000300, 0x0, 0x0, 0x0
};

/* Mont(b) = b*r mod p256, where r = 2^(6*52) mod p256 */
static const __ALIGN64 Ipp64u p256_b[LEN52] = {
   0x000c30061de0b74e, 0x000916229c4bddfd, 0x000c9c542a72f7e5, 0x00069e0d6acf005c, 0x000051ea29688e16, 0x0, 0x0, 0x0
};

/*
 * r = 2^(P256_LEN52*DIGIT_SIZE) mod p256
 */
static const __ALIGN64 Ipp64u p256_r[LEN52] = {
   0x0000000000ffffff, 0x0000100000000010, 0x000effffffff0000, 0x0000000fffffffff, 0x0000fffffffeff00, 0x0, 0x0, 0x0
};

/* Aliases for operations */
#define add(R, A, B) (R) = add_i64((A), (B))
#define sub(R, A, B) (R) = sub_i64((A), (B))
#define mul(R, A, B) (R) = ifma_amm52_p256((A), (B))
#define sqr(R, A) (R) = ifma_ams52_p256((A))
#define div2(R, A) (R) = ifma_half52_p256((A))
#define inv(R, A) (R) = ifma_aminv52_p256((A))
#define norm(R, A) (R) = ifma_norm52((A))
#define lnorm(R, A) (R) = ifma_lnorm52((A))
#define from_mont(R, A) (R) = ifma_frommont52_p256((A))

/* Aliases for dual operations */
#define mul_dual(R1, A1, B1, R2, A2, B2) ifma_amm52_dual_p256(&(R1), (A1), (B1), &(R2), (A2), (B2))
#define sqr_dual(R1, A1, R2, A2) ifma_ams52_dual_p256(&(R1), (A1), &(R2), (A2))
#define norm_dual(R1, A1, R2, A2) ifma_norm52_dual(&(R1), (A1), &(R2), (A2))
#define lnorm_dual(R1, A1, R2, A2) ifma_lnorm52_dual(&(R1), (A1), &(R2), (A2))

/* to affine coordinate */
IPP_OWN_DEFN(void, ifma_ec_nistp256_get_affine_coords, (m512 * rx, m512 *ry, const P256_POINT_IFMA *a))
{
   m512 z1, z2, z3;

   inv(z1, a->z); /* 1/z */
   sqr(z2, z1);   /* (1/z)^2 */
   lnorm(z2, z2);

   /* x = x/z^2 */
   if (NULL != rx) {
      mul(*rx, a->x, z2); /* x = x/z^2 */
      lnorm(*rx, *rx);
   }
   /* y = y/z^3 */
   if (NULL != ry) {
      mul(z3, z1, z2); /* (1/z)^3 */
      lnorm(z3, z3);
      mul(*ry, a->y, z3); /* y = y/z^3 */
      lnorm(*ry, *ry);
   }
}

IPP_OWN_DEFN(void, ifma_ec_nistp256_dbl_point, (P256_POINT_IFMA * r, const P256_POINT_IFMA *p))
{
   /*
     * Enhanced Montgomery group algorithm described in [1].
     *
     * l1 = 3x^2 + a*z^4 = [a = -3]= 3*(x^2 - z^4) = 3*(x - z^2)*(x + z^2)
     * z2 = 2*y*z
     * l2 = 4*x*y^2
     * x2 = l1^2 - 2*l2
     * l3 = 8*y^4
     * y2 = l1*(l2 - x2) - l3
     *
     */
   const m512 *x1 = &p->x;
   const m512 *y1 = &p->y;
   const m512 *z1 = &p->z;

   m512 x2;
   m512 y2;
   m512 z2;
   x2 = y2 = z2 = setzero_i64();

   m512 T, U, V, A, B, H;
   T = U = V = A = B = H = setzero_i64();

   const m512 M2 = loadu_i64(p256_x2);
   const m512 M4 = loadu_i64(p256_x4);
   const m512 M8 = loadu_i64(p256_x8);

   add(T, *y1, *y1); /* T = 2*y1 */
   lnorm(T, T);

   sqr_dual(V, T,    /* V = 4*y1^2 */
            U, *z1); /* U = z1^2 */

   sub(B, *x1, U); /* B = x1 - z1^2 */
   add(B, B, M2);
   add(U, *x1, U); /* U = x1 + z1^2 */

   lnorm_dual(V, V,
              U, U);
   norm(B, B);

   mul_dual(A, V, *x1, /* A = 4*x1*y1^2 */
            B, B, U);  /* B = (x1 - z1^2)*(x1 + z1^2) */

   add(x2, A, A); /* x2 = 8*x1*y1^2 */
   add(H, B, B);
   add(B, B, H); /* B(l1) = 3*(x1 - z1^2)*(x1 + z1^2) */

   lnorm(B, B);

   sqr_dual(U, B,   /* U = l1^2 */
            y2, V); /* y2 = 16*y^2 */

   sub(x2, U, x2); /* x2 = l1^2 - 2*l2 */
   add(x2, x2, M4);
   div2(y2, y2);

   sub(U, A, x2); /* U = l2 - x2 */
   add(U, U, M8);

   norm(U, U);

   mul_dual(z2, T, *z1, /* z2 = 2*y1*z1 */
            U, U, B);   /* U = B(l1)*(A(l2) - x2) */

   sub(y2, U, y2); /* y2 = B(l1)*(A(l2) - x2) - y2(l3) */
   add(y2, y2, M2);

   norm_dual(r->x, x2,
             r->y, y2);
   lnorm(r->z, z2);
}

IPP_OWN_DEFN(void, ifma_ec_nistp256_add_point, (P256_POINT_IFMA * r, const P256_POINT_IFMA *p, const P256_POINT_IFMA *q))
{
   /*
     * Enhanced Montgomery group algorithm described in [1].
     *
     * A = x1*z2^2    B = x2*z1^2      C = y1*z2^3      D = y2*z1^3
     * E = B - A      F = D - C
     * x3 = -E^3 - 2*A*E^2 + F^2
     * y3 = -C*E^3 + F*(A*E^2 - x3)
     * z3 = z1*z2*E
     */
   const m512 *x1       = &p->x;
   const m512 *y1       = &p->y;
   const m512 *z1       = &p->z;
   const mask8 p_is_inf = is_zero_i64(p->z);

   const m512 *x2       = &q->x;
   const m512 *y2       = &q->y;
   const m512 *z2       = &q->z;
   const mask8 q_is_inf = is_zero_i64(q->z);

   m512 x3;
   m512 y3;
   m512 z3;
   x3 = y3 = z3 = setzero_i64();

   const m512 M2 = loadu_i64(p256_x2);
   const m512 M4 = loadu_i64(p256_x4);
   const m512 M8 = loadu_i64(p256_x8);

   m512 U1, U2, S1, S2, H, R;
   U1 = U2 = S1 = S2 = H = R = setzero_i64();

   mul_dual(S1, *y1, *z2,  /* s1 = y1*z2 */
            U1, *z2, *z2); /* u1 = z2^2  */

   lnorm_dual(S1, S1,
              U1, U1);

   mul_dual(S2, *y2, *z1,  /* s2 = y2*z1 */
            U2, *z1, *z1); /* u2 = z1^2 */

   lnorm_dual(S2, S2,
              U2, U2);

   mul_dual(S1, S1, U1,  /* s1 = y1*z2^3 (C) */
            S2, S2, U2); /* s2 = y2*z1^3 (D) */

   lnorm_dual(S1, S1,
              S2, S2);

   mul_dual(U1, *x1, U1,  /* u1 = x1*z2^2 (A) */
            U2, *x2, U2); /* u2 = x2*z1^2 (B) */

   lnorm_dual(U1, U1,
              U2, U2);

   sub(R, S2, S1); /* r = D - C (F) */
   sub(H, U2, U1); /* h = B - A (E) */

   /* checking the equality of X and Y coordinates (D - C == 0) and (B - A == 0) */
   const mask8 f_are_zero     = is_zero_i64(R);
   const mask8 e_are_zero     = is_zero_i64(H);
   const mask8 point_is_equal = ((e_are_zero & f_are_zero) & (~p_is_inf) & (~q_is_inf));

   __ALIGN64 P256_POINT_IFMA r2;
   r2.x = r2.y = r2.z = setzero_i64();
   if ((mask8)0xFF == point_is_equal) {
      ifma_ec_nistp256_dbl_point(&r2, p);
   }

   add(R, R, M2);
   add(H, H, M2);
   norm_dual(R, R,
             H, H);

   mul_dual(z3, *z1, *z2, /* z3 = z1*z2 */
            U2, H, H);    /* u2 = E^2 */

   lnorm_dual(z3, z3,
              U2, U2);

   mul_dual(z3, z3, H, /* z3 = (z1*z2)*E */
            S2, R, R); /* s2 = F^2 */
   mul(H, H, U2);      /* h  = E^3 */

   lnorm(H, H);

   mul(U1, U1, U2); /* u1 = A*E^2 */
   sub(x3, S2, H);  /* x3 = F^2 - E^3 */
   add(x3, x3, M2);
   add(U2, U1, U1); /* u2 = 2*A*E^2 */
   mul(S1, S1, H);  /* s1 = C*E^3 */
   sub(x3, x3, U2); /* x3 = (F^2 - E^3) -2*A*E^2 */
   add(x3, x3, M4);

   sub(y3, U1, x3); /* y3 = A*E^2 - x3 */
   add(y3, y3, M8);

   norm(y3, y3);

   mul(y3, y3, R);  /* y3 = F*(A*E^2 - x3) */
   sub(y3, y3, S1); /* y3 = F*(A*E^2 - x3) - C*E^3 */
   add(y3, y3, M2);

   norm_dual(x3, x3,
             y3, y3);
   lnorm(z3, z3);

   /* T = p_is_inf ? q : T */
   x3 = mask_mov_i64(x3, p_is_inf, *x2);
   y3 = mask_mov_i64(y3, p_is_inf, *y2);
   z3 = mask_mov_i64(z3, p_is_inf, *z2);

   /* T = q_is_inf ? p : T */
   x3 = mask_mov_i64(x3, q_is_inf, *x1);
   y3 = mask_mov_i64(y3, q_is_inf, *y1);
   z3 = mask_mov_i64(z3, q_is_inf, *z1);

   /* r = point_is_equal ? r2 : T */
   x3 = mask_mov_i64(x3, point_is_equal, r2.x);
   y3 = mask_mov_i64(y3, point_is_equal, r2.y);
   z3 = mask_mov_i64(z3, point_is_equal, r2.z);

   r->x = x3;
   r->y = y3;
   r->z = z3;
}

IPP_OWN_DEFN(void, ifma_ec_nistp256_add_point_affine, (P256_POINT_IFMA * r, const P256_POINT_IFMA *p, const P256_POINT_AFFINE_IFMA *q))
{
   /*
     * Enhanced Montgomery group algorithm described in [1].
     *
     *  A = x1         B = x2*z1^2       C = y1    D = y2*z1^3
     *  E = B - A(x1)  F = D - C(y1)
     * x3 = -E^3 - 2*A(x1)*E^2 + F^2
     * y3 = -C(y1)*E^3 + F*(A(x1)*E^2 - x3)
     * z3 = z1*E
     */

   /* Coordinates of p (jacobian projective) */
   const m512 *x1       = &p->x;
   const m512 *y1       = &p->y;
   const m512 *z1       = &p->z;
   const mask8 p_is_inf = is_zero_i64(p->z);

   /* Coordinates of q (affine) */
   const m512 *x2       = &q->x;
   const m512 *y2       = &q->y;
   const mask8 q_is_inf = (is_zero_i64(q->x) & is_zero_i64(q->y));

   const m512 M2 = loadu_i64(p256_x2);
   const m512 M4 = loadu_i64(p256_x4);
   const m512 M8 = loadu_i64(p256_x8);

   m512 x3, y3, z3;
   x3 = y3 = z3 = setzero_i64();

   m512 U2, S2, H, R;
   U2 = S2 = H = R = setzero_i64();

   mul_dual(R, *z1, *z1,   /* R = z1^2 */
            S2, *y2, *z1); /* S2 = y2*z1 */

   lnorm_dual(R, R,
              S2, S2);

   mul_dual(U2, *x2, R, /* U2 = x2*z1^2 (B) */
            S2, S2, R); /* S2 = y2*z1^3 (D) */

   sub(H, U2, *x1); /* H = B - A (E) */
   add(H, H, M8);
   sub(R, S2, *y1); /* R = D - C (F) */
   add(R, R, M4);

   norm_dual(H, H,
             R, R);

   mul(z3, H, *z1); /* z3 = z1*E */

   sqr_dual(U2, H,  /* U2 = E^2 */
            S2, R); /* S2 = F^2 */

   lnorm(U2, U2);

   mul(H, H, U2); /* H = E^3 */

   lnorm(H, H);

   mul_dual(U2, U2, *x1, /* U2 = A*E^2 */
            y3, H, *y1); /* y3 = C*E^3 */

   add(x3, U2, U2); /* x2 = 2*A*E^2 */
   sub(x3, S2, x3); /* x3 = F^2 - 2*A*E^2 */
   add(x3, x3, M4);
   sub(x3, x3, H); /* x3 = F^2 - 2*A*E^2 - E^3 */
   add(x3, x3, M2);

   sub(U2, U2, x3); /* U2 = A*E^2 - x3 */
   add(U2, U2, M8);
   norm(U2, U2);
   mul(U2, U2, R);  /* U2 = F*(A*E^2 - x3) */
   sub(y3, U2, y3); /* y3 = F*(A*E^2 - x3) - C*E^2 */
   add(y3, y3, M2);

   norm_dual(x3, x3,
             y3, y3);
   lnorm(z3, z3);

   /* T = p_is_inf ? q : T */
   x3 = mask_mov_i64(x3, p_is_inf, *x2);
   y3 = mask_mov_i64(y3, p_is_inf, *y2);
   z3 = mask_mov_i64(z3, p_is_inf, loadu_i64(p256_r));

   /* T = q_is_inf ? p : T */
   x3 = mask_mov_i64(x3, q_is_inf, *x1);
   y3 = mask_mov_i64(y3, q_is_inf, *y1);
   z3 = mask_mov_i64(z3, q_is_inf, *z1);

   r->x = x3;
   r->y = y3;
   r->z = z3;
}

IPP_OWN_DEFN(int, ifma_ec_nistp256_is_on_curve, (const P256_POINT_IFMA *p, const int use_jproj_coords))
{
   /*
     * y^2 = x^3 + a*x + b (1)
     *
     * if input
     * * Jacobian projective coordinate (x,y,z) reprepresented by (x/z^2,y/z^3,1)
     * * Affine coordinate -> (x/z^2,y/z^3,z/z=1)
     *
     * Mult (1) by z^6
     *
     * y^2 = x^3 + a*x*z^4 + b*z^6
     */
   const m512 M6 = loadu_i64(p256_x6);
   const m512 a  = loadu_i64(p256_a);
   const m512 b  = loadu_i64(p256_b);

   m512 rh, Z4, Z6, tmp;
   rh = Z4 = Z6 = tmp = setzero_i64();

   sqr(rh, p->x); /* rh = x^2 */

   /* rh = x*(x^2 + a*z^4) + b*z^6 = x*(x^2 - 3*z^4) + b*z^6 */
   if (0 != use_jproj_coords) {
      sqr(tmp, p->z); /* tmp = z^2 */
      lnorm(tmp, tmp);

      sqr(Z4, tmp);     /* z4 = z^4 */
      lnorm(Z4,Z4);     /* norm */
      mul(Z6, Z4, tmp); /* z6 = z^6 */
      lnorm(Z6,Z6);     /* norm */

      add(tmp, Z4, Z4);  /* tmp = 2*z^4 */
      add(tmp, tmp, Z4); /* tmp = 3*z^4 */

      sub(rh, rh, tmp); /* rh = x^2 - 3*z^4 */
      add(rh, rh, M6);
      norm(rh, rh);

      mul_dual(rh, rh, p->x, /* rh = x*(x^2 - 3*z^4) */
               tmp, Z6, b);  /* tmp = b*z^6 */

      add(rh, rh, tmp); /* rh = x*(x^2 - 3*z^4) + b*z^6 */
   }

   /* rh = x*(x^2 + a) + b */
   else {
      add(rh, rh, a); /* rh = x^2 + a */
      lnorm(rh, rh);
      mul(rh, rh, p->x); /* rh = x*(x^2 + a) */
      add(rh, rh, b);    /* rh = x*(x^2 + a) + b */
   }

   lnorm(rh, rh);

   /* rl = Y^2 */
   sqr(tmp, p->y);  /* tmp = y^2 */
   lnorm(tmp, tmp); /**/

   /* from mont */
   from_mont(tmp, tmp);
   from_mont(rh, rh);

   const mask8 mask = cmp_i64_mask(rh, tmp, _MM_CMPINT_EQ);
   return (mask == 0xFF) ? 1 : 0;
}

#undef add
#undef sub
#undef mul
#undef sqr
#undef div2
#undef norm
#undef from_mont
#undef mul_dual
#undef sqr_dual
#undef norm_dual

static __NOINLINE void clear_secret_context(Ipp16u *wval,
                                            Ipp32s *chunk_no, Ipp32s *chunk_shift,
                                            Ipp8u *sign, Ipp8u *digit,
                                            P256_POINT_IFMA *R, P256_POINT_IFMA *H,
                                            P256_POINT_AFFINE_IFMA *A)
{
   *wval        = 0;
   *chunk_no    = 0;
   *chunk_shift = 0;
   *sign        = 0;
   *digit       = 0;

   if (NULL != R)
      (*R).x = (*R).y = (*R).z = setzero_i64();
   if (NULL != H)
      (*H).x = (*H).y = (*H).z = setzero_i64();
   if (NULL != A)
      (*A).x = (*A).y = setzero_i64();
}

#define WIN_SIZE (5)

__IPPCP_INLINE mask8 is_eq_mask(const Ipp32s a, const Ipp32s b)
{
   const Ipp32s eq  = a ^ b;
   const Ipp32s v   = ~eq & (eq - 1);
   const Ipp32s msb = 0 - (v >> (sizeof(a) * 8 - 1));
   return (mask8)(0 - msb);
}

__IPPCP_INLINE void extract_table_point(P256_POINT_IFMA *r, const Ipp32s digit, const P256_POINT_IFMA *tbl)
{
   Ipp32s idx = digit - 1;

   __ALIGN64 P256_POINT_IFMA R;
   R.x = R.y = R.z = setzero_i64();

   for (Ipp32s n = 0; n < (1 << (WIN_SIZE - 1)); ++n) {
      const mask8 mask = is_eq_mask(n, idx);

      R.x = mask_mov_i64(R.x, mask, tbl[n].x);
      R.y = mask_mov_i64(R.y, mask, tbl[n].y);
      R.z = mask_mov_i64(R.z, mask, tbl[n].z);
   }

   r->x = R.x;
   r->y = R.y;
   r->z = R.z;
}

#define dbl_point ifma_ec_nistp256_dbl_point
#define add_point ifma_ec_nistp256_add_point
#define neg_coord ifma_neg52_p256
#define add_point_affine ifma_ec_nistp256_add_point_affine

/* r = n*P = (P + P + ... + P) */
IPP_OWN_DEFN(void, ifma_ec_nistp256_mul_point, (P256_POINT_IFMA * r, const P256_POINT_IFMA *p, const Ipp8u *pExtendedScalar, const int scalarBitSize))
{
   /* Precompute table */
   __ALIGN64 P256_POINT_IFMA tbl[(1 << (WIN_SIZE - 1))];

   __ALIGN64 P256_POINT_IFMA R;
   __ALIGN64 P256_POINT_IFMA H;

   R.x = R.y = R.z = setzero_i64();
   H.x = H.y = H.z = setzero_i64();
   m512 negHy      = setzero_i64();

   /* compute tbl[] = [n]P, n = 1, ... , 2^(win_size - 1)
     * tbl[2*n]     = tbl[2*n - 1] + p
     * tbl[2*n + 1] = [2]*tbl[n]
     */

   /* tbl[0] = p */
   tbl[0].x = p->x;
   tbl[0].y = p->y;
   tbl[0].z = p->z;

   /* tbl[1] = [2]*p */
   dbl_point(/* r = */ (tbl + 1), /* a = */ p);

   for (int n = 1; n < ((1 << (WIN_SIZE - 1)) / 2); ++n) {
      add_point((tbl + 2 * n), (tbl + 2 * n - 1), p);
      dbl_point((tbl + 2 * n + 1), (tbl + n));
   }

   Ipp16u wval;
   Ipp8u digit, sign;
   const Ipp32s mask = ((1 << (WIN_SIZE + 1)) - 1); /* mask 0b111111 */
   Ipp32s bit        = scalarBitSize - (scalarBitSize % WIN_SIZE);

   Ipp32s chunk_no    = (bit - 1) / 8;
   Ipp32s chunk_shift = (bit - 1) % 8;

   if (0 != bit) {
      wval = *((Ipp16u *)(pExtendedScalar + chunk_no));
      wval = (Ipp16u)((wval >> chunk_shift) & mask);
   } else {
      wval = 0;
   }

   booth_recode(&sign, &digit, (Ipp8u)wval, WIN_SIZE);
   extract_table_point(&R, (Ipp32s)digit, tbl);

   for (bit -= WIN_SIZE; bit >= WIN_SIZE; bit -= WIN_SIZE) {
      dbl_point(&R, &R);
      dbl_point(&R, &R);
      dbl_point(&R, &R);
      dbl_point(&R, &R);
#if (WIN_SIZE == 5)
      dbl_point(&R, &R);
#endif
      chunk_no    = (bit - 1) / 8;
      chunk_shift = (bit - 1) % 8;

      wval = *((Ipp16u *)(pExtendedScalar + chunk_no));
      wval = (Ipp16u)((wval >> chunk_shift) & mask);

      booth_recode(&sign, &digit, (Ipp8u)wval, WIN_SIZE);
      extract_table_point(&H, (Ipp32s)digit, tbl);

      negHy = neg_coord(H.y);

      const mask8 mask_neg = (mask8)(~(sign - 1));
      H.y                  = mask_mov_i64(H.y, mask_neg, negHy);

      add_point(&R, &R, &H);
   }

   /* last window */
   dbl_point(&R, &R);
   dbl_point(&R, &R);
   dbl_point(&R, &R);
   dbl_point(&R, &R);
#if (WIN_SIZE == 5)
   dbl_point(&R, &R);
#endif

   wval = *((Ipp16u *)(pExtendedScalar + 0));
   wval = (Ipp16u)((wval << 1) & mask);

   booth_recode(&sign, &digit, (Ipp8u)wval, WIN_SIZE);
   extract_table_point(&H, (Ipp32s)digit, tbl);

   negHy = neg_coord(H.y);

   const mask8 mask_neg = (mask8)(~(sign - 1));
   H.y                  = mask_mov_i64(H.y, mask_neg, negHy);

   add_point(&R, &R, &H);

   r->x = R.x;
   r->y = R.y;
   r->z = R.z;

   /* clear secret data */
   clear_secret_context(&wval,
                        &chunk_no, &chunk_shift,
                        &sign, &digit,
                        &R, &H, NULL);

   return;
}

/* #include "gfpec/ecnist/ifma_ecprecomp4_p256.h" */
#include "gfpec/ecnist/ifma_ecprecomp7_p256.h"

/* mul point base */
#define BP_WIN_SIZE BASE_POINT_WIN_SIZE
#define BP_N_ENTRY BASE_POINT_N_ENTRY

__IPPCP_INLINE void extract_point_affine(P256_POINT_AFFINE_IFMA *r,
                                   const P256_POINT_AFFINE_IFMA_MEM *tbl,
                                   const Ipp32s digit)
{
   Ipp32s idx = digit - 1;

   m512 x, y;
   x = y = setzero_i64();

   for (Ipp32s n = 0; n < (1 << ((BP_WIN_SIZE)-1)); ++n, ++tbl) {
      const mask8 mask = is_eq_mask(n, idx);

      x = mask_mov_i64(x, mask, maskz_loadu_i64(0x1f, tbl->X));
      y = mask_mov_i64(y, mask, maskz_loadu_i64(0x1f, tbl->Y));
   }

   r->x = x;
   r->y = y;
}

IPP_OWN_DEFN(void, p256r1_select_ap_w7_ifma, (BNU_CHUNK_T * pAffinePoint, const BNU_CHUNK_T *pTable, int index))
{
   __ALIGN64 P256_POINT_AFFINE_IFMA ap;

   extract_point_affine(&ap, (P256_POINT_AFFINE_IFMA_MEM *)pTable, index);

   ap.x = ifma_frommont52_p256(ap.x);
   ap.y = ifma_frommont52_p256(ap.y);

   convert_radix_to_64x4(pAffinePoint, ap.x);
   convert_radix_to_64x4(pAffinePoint + LEN64, ap.y);
}

IPP_OWN_DEFN(void, ifma_ec_nistp256_mul_pointbase, (P256_POINT_IFMA * r, const Ipp8u *pExtendedScalar, int scalarBitSize))
{
   /* precompute table */
   const P256_POINT_AFFINE_IFMA_MEM *tbl = &ifma_ec_nistp256r1_bp_precomp[0][0];

   __ALIGN64 P256_POINT_IFMA R;
   R.x = R.y = R.z = setzero_i64();
   __ALIGN64 P256_POINT_AFFINE_IFMA A;
   A.x = A.y = setzero_i64();

   m512 Ty = setzero_i64();

   Ipp16u wval;
   Ipp8u digit, sign;
   const Ipp32s mask = ((1 << (BP_WIN_SIZE + 1)) - 1); /* mask 0b11111 */
   Ipp32s bit        = 0;
   Ipp32s chunk_no, chunk_shift;

   wval = *((Ipp16u *)(pExtendedScalar + 0));
   wval = (Ipp16u)((wval << 1) & mask);

   booth_recode(&sign, &digit, (Ipp8u)wval, BP_WIN_SIZE);
   extract_point_affine(&A, tbl, (Ipp32s)digit);
   tbl += BP_N_ENTRY;

   /* A = sign == 1 ? -A : A */
   Ty             = neg_coord(A.y);
   mask8 mask_neg = (mask8)(~(sign - 1));
   A.y            = mask_mov_i64(A.y, mask_neg, Ty);

   /* R += A */
   add_point_affine(&R, &R, &A);

   for (bit += BP_WIN_SIZE; bit <= scalarBitSize; bit += BP_WIN_SIZE) {
      chunk_no    = (bit - 1) / 8;
      chunk_shift = (bit - 1) % 8;

      wval = *((Ipp16u *)(pExtendedScalar + chunk_no));
      wval = (Ipp16u)((wval >> chunk_shift) & mask);

      booth_recode(&sign, &digit, (Ipp8u)wval, BP_WIN_SIZE);
      extract_point_affine(&A, tbl, (Ipp32s)digit);
      tbl += BP_N_ENTRY;

      /* A = sign == 1 ? -A : A */
      Ty       = neg_coord(A.y);
      mask_neg = (mask8)(~(sign - 1));
      A.y      = mask_mov_i64(A.y, mask_neg, Ty);

      /* R += A */
      add_point_affine(&R, &R, &A);
   }

   r->x = R.x;
   r->y = R.y;
   r->z = R.z;

   /* clear secret data */
   clear_secret_context(&wval,
                        &chunk_no, &chunk_shift,
                        &sign, &digit,
                        &R, NULL, &A);
   return;
}

#undef dbl_point
#undef add_point
#undef neg_coord
#undef add_point_affine

#endif // (_IPP32E >= _IPP32E_K1)
