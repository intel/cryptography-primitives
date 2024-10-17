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

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_arith_p521.h"
#include "gfpec/ecnist/ifma_ecpoint_p521.h"
#include "gfpec/pcpgfpecstuff.h"

#define add(R, A, B) fe521_add_no_red((R), (A), (B))
#define sub(R, A, B) fe521_sub_no_red((R), (A), (B))
#define mul(R, A, B) ifma_amm52_p521(&(R), (A), (B))
#define sqr(R, A) ifma_ams52_p521(&(R), (A))
#define div2(R, A) ifma_half52_p521(&(R), (A))
#define norm(R, A) ifma_norm52_p521(&(R), (A))
#define lnorm(R, A) ifma_lnorm52_p521(&(R), (A))
#define inv(R, A) ifma_aminv52_p521(&(R), (A))
#define from_mont(R, A) ifma_frommont52_p521(&(R), (A))
/* duplicate mult/sqr/norm */
#define mul_dual(R1, A1, B1, R2, A2, B2) ifma_amm52_dual_p521(&(R1), (A1), (B1), &(R2), (A2), (B2))
#define sqr_dual(R1, A1, R2, A2) ifma_ams52_dual_p521(&(R1), (A1), &(R2), (A2))
#define norm_dual(R1, A1, R2, A2) ifma_norm52_dual_p521(&(R1), (A1), &(R2), (A2))
#define lnorm_dual(R1, A1, R2, A2) ifma_lnorm52_dual_p521(&(R1), (A1), &(R2), (A2))

IPP_OWN_DEFN(void, ifma_ec_nistp521_get_affine_coords, (fe521 prx[], fe521 pry[], const P521_POINT_IFMA *a))
{

   fe521 z1, z2, z3;
   FE521_SET(z1) = FE521_SET(z2) = FE521_SET(z3) = m256_setzero_i64();
   inv(z1, a->z); /* 1/z */
   sqr(z2, z1);   /* (1/z)^2 */
   lnorm(z2, z2); /**/

   /* x = x/z^2 */
   if (NULL != prx) {
      mul(*prx, a->x, z2); /* x = x/z^2 */
      lnorm(*prx, *prx);   /**/
   }
   /* y = y/z^3 */
   if (NULL != pry) {
      mul(z3, z1, z2);     /* (1/z)^3 */
      lnorm(z3, z3);       /**/
      mul(*pry, a->y, z3); /* y = y/z^3 */
      lnorm(*pry, *pry);   /**/
   }

   return;
}

IPP_OWN_DEFN(void, ifma_ec_nistp521_dbl_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p))
{
   /*
     * Algorithm (Gueron - Enhanced Montgomery Multiplication)
     * l1 = 3x^2 + a*z^4 = (if p384 a = -3) = 3*(x^2 - z^4) = 3*(x - z^2)*(x + z^2)
     * z2 = 2*y*z
     * l2 = 4*x*y^2
     * x2 = l1^2 - 2*l2
     * l3 = 8*y^4
     * y2 = l1*(l2 - x2) - l3
     *
     * sum aripmetic: 8 mul; 9 add/sub; 1 div2.
     */
   const fe521 *x1 = &p->x;
   const fe521 *y1 = &p->y;
   const fe521 *z1 = &p->z;

   fe521 x2;
   fe521 y2;
   fe521 z2;
   FE521_SET(x2) = FE521_SET(y2) = FE521_SET(z2) = m256_setzero_i64();

   fe521 T, U, V, A, B, H;
   FE521_SET(T) = FE521_SET(U) = FE521_SET(V) = m256_setzero_i64();
   FE521_SET(A) = FE521_SET(B) = FE521_SET(H) = m256_setzero_i64();

   fe521 M2, M4, M8;
   FE521_LOADU(M2, p521_x2); /* 2*p */
   FE521_LOADU(M4, p521_x4); /* 4*p */
   FE521_LOADU(M8, p521_x8); /* 8*p */

   add(T, *y1, *y1);    /* T = 2*y1 */
   lnorm(T, T);         /**/
                        /*=====*/
   sqr_dual(V, T,       /* V = 4*y1^2 */
            U, *z1);    /* U = z1^2 */
                        /*=====*/
   sub(B, *x1, U);      /* B = 2*p + x1 - z1^2 */
   add(B, B, M2);       /**/
   add(U, *x1, U);      /* U = x1 + z1^2 */
                        /*=====*/
                        /* normalization */
   lnorm_dual(V, V,     /**/
              U, U);    /**/
   norm(B, B);          /**/
                        /*=====*/
   mul_dual(A, V, *x1,  /* A = 4*x1*y1^2 */
            B, B, U);   /* B = (x1 - z1^2)*(x1 + z1^2) */
                        /*=====*/
   add(x2, A, A);       /* x2 = 8*x1*y1^2 (4p) */
   add(H, B, B);        /**/
   add(B, B, H);        /* B(l1) = 3*(x1 - z1^2)*(x1 + z1^2) */
                        /*=====*/
                        /* normalization */
   lnorm(B, B);         /**/
                        /*=====*/
   sqr_dual(U, B,       /* U = l1^2 */
            y2, V);     /* y2 = 16*y^2 */
                        /*=====*/
   sub(x2, U, x2);      /* x2 = 4*p + l1^2 - 2*l2 */
   add(x2, x2, M4);     /**/
   div2(y2, y2);        /**/
                        /*=====*/
   sub(U, A, x2);       /* U = 8*p + l2 - x2 */
   add(U, U, M8);       /**/
                        /*=====*/
                        /* normalization */
   norm(U, U);          /**/
                        /*=====*/
   mul_dual(z2, T, *z1, /* z2 = 2*y1*z1 */
            U, U, B);   /* U = B(l1)*(A(l2) - x2) */
                        /*=====*/
   sub(y2, U, y2);      /* y2 = 2*p + B(l1)*(A(l2) - x2) - y2(l3) */
   add(y2, y2, M2);     /**/
                        /*=====*/
                        /* normalization */
   norm_dual(r->x, x2,  /**/
             r->y, y2); /**/
   lnorm(r->z, z2);     /**/
   return;
}

IPP_OWN_DEFN(void, ifma_ec_nistp521_add_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const P521_POINT_IFMA *q))
{
   /*
     * Algorithm (Gueron - Enhanced Montgomery Multiplication)
     *
     * A = x1*z2^2    B = x2*z1^2      C = y1*z2^3      D = y2*z1^3
     * E = B - A      F = D - C
     * x3 = -E^3 - 2*A*E^2 + F^2
     * y3 = -C*E^3 + F*(A*E^2 - x3)
     * z3 = z1*z2*E
     */
   const fe521 *x1      = &p->x;
   const fe521 *y1      = &p->y;
   const fe521 *z1      = &p->z;
   const mask8 p_is_inf = FE521_IS_ZERO(p->z);

   const fe521 *x2      = &q->x;
   const fe521 *y2      = &q->y;
   const fe521 *z2      = &q->z;
   const mask8 q_is_inf = FE521_IS_ZERO(q->z);

   fe521 x3;
   fe521 y3;
   fe521 z3;
   FE521_SET(x3) = FE521_SET(y3) = FE521_SET(z3) = m256_setzero_i64();

   fe521 M2, M4, M8;
   FE521_LOADU(M2, p521_x2); /* 2*p */
   FE521_LOADU(M4, p521_x4); /* 4*p */
   FE521_LOADU(M8, p521_x8); /* 8*p */

   fe521 U1, U2, S1, S2, H, R;
   FE521_SET(U1) = FE521_SET(U2) = FE521_SET(S1) = m256_setzero_i64();
   FE521_SET(S2) = FE521_SET(H) = FE521_SET(R) = m256_setzero_i64();

   mul_dual(S1, *y1, *z2,  /* s1 = y1*z2 */
            U1, *z2, *z2); /* u1 = z2^2  */
                           /*=====*/
                           /* normalization */
   lnorm_dual(S1, S1,      /**/
              U1, U1);     /**/
                           /*=====*/
   mul_dual(S2, *y2, *z1,  /* s2 = y2*z1 */
            U2, *z1, *z1); /* u2 = z1^2 */
                           /*=====*/
                           /* normalization */
   lnorm_dual(S2, S2,      /**/
              U2, U2);     /**/
                           /*=====*/
   mul_dual(S1, S1, U1,    /* s1 = y1*z2^3 (C) */
            S2, S2, U2);   /* s2 = y2*z1^3 (D) */
                           /*=====*/
                           /* normalization */
   lnorm_dual(S1, S1,      /**/
              S2, S2);     /* (need by correct compute F = D - C) */
                           /*=====*/
   mul_dual(U1, *x1, U1,   /* u1 = x1*z2^2 (A) */
            U2, *x2, U2);  /* u2 = x2*z1^2 (B) */
                           /*=====*/
                           /* normalization */
   lnorm_dual(U1, U1,      /**/
              U2, U2);     /**/
                           /*=====*/
   sub(R, S2, S1);         /* r = D - C (F) */
   sub(H, U2, U1);         /* h = B - A (E) */

   /* checking the equality of X and Y coordinates (D - C == 0) and (B - A == 0) */
   const mask8 f_are_zero     = FE521_IS_ZERO(R);
   const mask8 e_are_zero     = FE521_IS_ZERO(H);
   const mask8 point_is_equal = ((e_are_zero & f_are_zero) & (~p_is_inf) & (~q_is_inf));

   __ALIGN64 P521_POINT_IFMA r2;
   FE521_SET(r2.x) = FE521_SET(r2.y) = FE521_SET(r2.z) = m256_setzero_i64();
   if ((mask8)0xFF == point_is_equal) {
      ifma_ec_nistp521_dbl_point(&r2, p);
   }

   add(R, R, M2);         /**/
   add(H, H, M2);         /**/
                          /*=====*/
                          /* normalization */
   norm_dual(R, R,        /**/
             H, H);       /**/
                          /**/
   mul_dual(z3, *z1, *z2, /* z3 = z1*z2 */
            U2, H, H);    /* u2 = E^2 */
                          /*=====*/
                          /* normalization */
   lnorm_dual(z3, z3,     /**/
              U2, U2);    /**/
                          /**/
   mul_dual(z3, z3, H,    /* z3 = (z1*z2)*E */
            S2, R, R);    /* s2 = F^2 */
   mul(H, H, U2);         /* h  = E^3 */
                          /*=====*/
                          /* normalization */
   lnorm(H, H);           /**/
                          /*=====*/
   mul(U1, U1, U2);       /* u1 = A*E^2 */
   sub(x3, S2, H);        /* x3 = F^2 - E^3 */
   add(x3, x3, M2);       /**/
   add(U2, U1, U1);       /* u2 = 2*A*E^2 */
   mul(S1, S1, H);        /* s1 = C*E^3 */
   sub(x3, x3, U2);       /* x3 = (F^2 - E^3) -2*A*E^2 */
   add(x3, x3, M4);       /**/
                          /*=====*/
   sub(y3, U1, x3);       /* y3 = A*E^2 - x3 */
   add(y3, y3, M8);       /**/
                          /*=====*/
                          /* normalization */
   norm(y3, y3);          /**/
                          /**/
   mul(y3, y3, R);        /* y3 = F*(A*E^2 - x3) */
   sub(y3, y3, S1);       /* y3 = F*(A*E^2 - x3) - C*E^3 */
   add(y3, y3, M2);

   /* normalization */
   norm_dual(x3, x3,  /**/
             y3, y3); /**/
   lnorm(z3, z3);     /**/

   /* T = p_is_inf ? q : T */
   FE521_MASK_MOV(x3, x3, p_is_inf, *x2);
   FE521_MASK_MOV(y3, y3, p_is_inf, *y2);
   FE521_MASK_MOV(z3, z3, p_is_inf, *z2);

   /* T = q_is_inf ? p : T */
   FE521_MASK_MOV(x3, x3, q_is_inf, *x1);
   FE521_MASK_MOV(y3, y3, q_is_inf, *y1);
   FE521_MASK_MOV(z3, z3, q_is_inf, *z1);

   /* r = point_is_equal ? r2 : T */
   FE521_MASK_MOV(x3, x3, point_is_equal, r2.x);
   FE521_MASK_MOV(y3, y3, point_is_equal, r2.y);
   FE521_MASK_MOV(z3, z3, point_is_equal, r2.z);

   FE521_COPY(r->x, x3);
   FE521_COPY(r->y, y3);
   FE521_COPY(r->z, z3);

   return;
}

IPP_OWN_DEFN(void, ifma_ec_nistp521_add_point_affine, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const P521_POINT_AFFINE_IFMA *q))
{
   /*
     * Algorithm (Gueron - Enhanced Montgomery Multiplication)
     *
     *  A = x1         B = x2*z1^2       C = y1    D = y2*z1^3
     *  E = B - A(x1)  F = D - C(y1)
     * x3 = -E^3 - 2*A(x1)*E^2 + F^2
     * y3 = -C(y1)*E^3 + F*(A(x1)*E^2 - x3)
     * z3 = z1*E
     */
   /* coordinates of p (jacobian projective) */
   const fe521 *x1      = &p->x;
   const fe521 *y1      = &p->y;
   const fe521 *z1      = &p->z;
   const mask8 p_is_inf = FE521_IS_ZERO(p->z);

   /* coordinate of q (affine) */
   const fe521 *x2      = &q->x;
   const fe521 *y2      = &q->y;
   const mask8 q_is_inf = (FE521_IS_ZERO(q->x) & FE521_IS_ZERO(q->y));

   fe521 x3;
   fe521 y3;
   fe521 z3;
   FE521_SET(x3) = FE521_SET(y3) = FE521_SET(z3) = m256_setzero_i64();

   fe521 M2, M4, M8;
   FE521_LOADU(M2, p521_x2); /* 2*p */
   FE521_LOADU(M4, p521_x4); /* 4*p */
   FE521_LOADU(M8, p521_x8); /* 8*p */

   fe521 U2, S2, H, R;
   FE521_SET(U2) = FE521_SET(S2) = FE521_SET(H) = FE521_SET(R) = m256_setzero_i64();

   mul_dual(R, *z1, *z1,   /* R = z1^2 */
            S2, *y2, *z1); /* S2 = y2*z1 */
                           /*=====*/
   lnorm_dual(R, R,        /**/
              S2, S2);     /**/
                           /*=====*/
   mul_dual(U2, *x2, R,    /* U2 = x2*z1^2 (B) */
            S2, S2, R);    /* S2 = y2*z1^3 (D) */
                           /**/
   sub(H, U2, *x1);        /* H = B - A (E) */
   add(H, H, M8);          /**/
   sub(R, S2, *y1);        /* R = D - C (F) */
   add(R, R, M4);          /**/
                           /*=====*/
   norm_dual(H, H,         /**/
             R, R);        /**/
                           /**/
   mul(z3, H, *z1);        /* z3 = z1*E */
                           /**/
   sqr_dual(U2, H,         /* U2 = E^2 */
            S2, R);        /* S2 = F^2 */
                           /**/
   lnorm(U2, U2);          /**/
                           /**/
   mul(H, H, U2);          /* H = E^3 */
                           /**/
   lnorm(H, H);            /**/
                           /**/
   mul_dual(U2, U2, *x1,   /* U2 = A*E^2 */
            y3, H, *y1);   /* y3 = C*E^3 */
                           /**/
   add(x3, U2, U2);        /* x2 = 2*A*E^2 */
   sub(x3, S2, x3);        /* x3 = F^2 - 2*A*E^2 */
   add(x3, x3, M4);        /**/
   sub(x3, x3, H);         /* x3 = F^2 - 2*A*E^2 - E^3 */
   add(x3, x3, M2);        /**/
                           /**/
   sub(U2, U2, x3);        /* U2 = A*E^2 - x3 */
   add(U2, U2, M8);        /**/
   norm(U2, U2);           /**/
   mul(U2, U2, R);         /* U2 = F*(A*E^2 - x3) */
   sub(y3, U2, y3);        /* y3 = F*(A*E^2 - x3) - C*E^2 */
   add(y3, y3, M2);        /**/

   /* normalization */
   norm_dual(x3, x3,  /**/
             y3, y3); /**/
   lnorm(z3, z3);     /**/

   fe521 ONE;
   FE521_LOADU(ONE, P521R1_R52);
   /* T = p_is_inf ? q : T */
   FE521_MASK_MOV(x3, x3, p_is_inf, *x2);
   FE521_MASK_MOV(y3, y3, p_is_inf, *y2);
   FE521_MASK_MOV(z3, z3, p_is_inf, ONE);

   /* T = q_is_inf ? p : T */
   FE521_MASK_MOV(x3, x3, q_is_inf, *x1);
   FE521_MASK_MOV(y3, y3, q_is_inf, *y1);
   FE521_MASK_MOV(z3, z3, q_is_inf, *z1);

   FE521_COPY(r->x, x3);
   FE521_COPY(r->y, y3);
   FE521_COPY(r->z, z3);

   return;
}

/* P521 mont(a) */
const static __ALIGN64 Ipp64u p512_a[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = { { 0x0007FFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFE,
                                                                                 0x000FFFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFF },
                                                                               { 0x000FFFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFF },
                                                                               { 0x000FFFFFFFFFFFFF,
                                                                                 0x000FFFFFFFFFFFFF,
                                                                                 0x0000000000000001,
                                                                                 0x0000000000000000 } };
/* P521R1 mont(b) */
const static __ALIGN64 Ipp64u p512_b[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = { { 0x00014654FAE58638,
                                                                                 0x00028FEA35A81F80,
                                                                                 0x000C41E961A78F7A,
                                                                                 0x000DD8DF839AB9EF },
                                                                               { 0x00049BD8B29605E9,
                                                                                 0x0000AB0C9CA8F63F,
                                                                                 0x0005A44C8C77884F,
                                                                                 0x00092DCCD98AF9DC },
                                                                               { 0x0005B42A077516D3,
                                                                                 0x000E4D0FC94D10D0,
                                                                                 0x0000000000000000,
                                                                                 0x0000000000000000 } };

IPP_OWN_DEFN(int, ifma_ec_nistp521_is_on_curve, (const P521_POINT_IFMA *p, const int use_jproj_coords))
{
   /*
     * Algorithm
     *
     * y^2 = x^3 + a*x + b (1)
     *
     * if input
     * * Jacobian projection coordinate (x,y,z) - represent by (x/z^2,y/z^3,1)
     * * Affine coordinate (x/z^2,y/z^3,z/z=1)
     *
     * mult formala (1) by z^6
     *
     * y^2 = x^3 + a*x*z^4 + b*z^6
     */
   fe521 M6;
   FE521_LOADU(M6, p521_x6);
   fe521 a, b;
   FE521_LOADU(a, p512_a);
   FE521_LOADU(b, p512_b);

   fe521 rh, Z4, Z6, tmp;
   FE521_SET(rh) = FE521_SET(Z4) = FE521_SET(Z6) = FE521_SET(tmp) = m256_setzero_i64();

   sqr(rh, p->x); /* rh = x^2 */
   /* rh = x*(x^2 + a*z^4) + b*z^6 = x*(x^2 - 3*z^4) + b*z^6 */
   if (0 != use_jproj_coords) {
      sqr(tmp, p->z);        /* tmp = z^2 */
      lnorm(tmp, tmp);       /**/
                             /**/
      sqr(Z4, tmp);          /* z4 = z^4 */
      lnorm(Z4, Z4);         /**/
      mul(Z6, Z4, tmp);      /* z6 = z^6 */
      lnorm(Z6, Z6);         /**/
                             /**/
      add(tmp, Z4, Z4);      /* tmp = 2*z^4 */
      add(tmp, tmp, Z4);     /* tmp = 3*z^4 */
                             /**/
      sub(rh, rh, tmp);      /* rh = x^2 - 3*z^4 */
      add(rh, rh, M6);       /**/
      norm(rh, rh);          /**/
                             /**/
      mul_dual(rh, rh, p->x, /* rh = x*(x^2 - 3*z^4) */
               tmp, Z6, b);  /* tmp = b*z^6 */
                             /**/
      add(rh, rh, tmp);      /* rh = x*(x^2 - 3*z^4) + b*z^6 */
   }
   /* rh = x*(x^2 + a) + b */
   else {
      add(rh, rh, a);    /* rh = x^2 + a */
      lnorm(rh, rh);     /**/
      mul(rh, rh, p->x); /* rh = x*(x^2 + a) */
      add(rh, rh, b);    /* rh = x*(x^2 + a) + b */
   }
   lnorm(rh, rh); /**/

   /* rl = Y^2 */
   sqr(tmp, p->y);  /* tmp = y^2 */
   lnorm(tmp, tmp); /**/

   /* from mont */
   from_mont(tmp, tmp);
   from_mont(rh, rh);

   const mask8 mask = FE521_CMP_MASK(rh, tmp, _MM_CMPINT_EQ);
   return (mask == 0xF) ? 1 : 0;
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
                                            P521_POINT_IFMA *R, P521_POINT_IFMA *H,
                                            P521_POINT_AFFINE_IFMA *A)
{
   *wval        = 0;
   *chunk_no    = 0;
   *chunk_shift = 0;
   *sign        = 0;
   *digit       = 0;

   if (NULL != R)
      FE521_SET((*R).x) = FE521_SET((*R).y) = FE521_SET((*R).z) = m256_setzero_i64();
   if (NULL != H)
      FE521_SET((*H).x) = FE521_SET((*H).y) = FE521_SET((*H).z) = m256_setzero_i64();
   if (NULL != A)
      FE521_SET((*A).x) = FE521_SET((*A).y) = m256_setzero_i64();
   return;
}

#define WIN_SIZE (5)

__IPPCP_INLINE mask8 is_eq_mask(const Ipp32s a, const Ipp32s b)
{
   const Ipp32s eq  = a ^ b;
   const Ipp32s v   = ~eq & (eq - 1);
   const Ipp32s msb = 0 - (v >> (sizeof(a) * 8 - 1));
   return (mask8)(0 - msb);
}

__IPPCP_INLINE void extract_table_point(P521_POINT_IFMA *r, const Ipp32s digit, const P521_POINT_IFMA tbl[])
{
   Ipp32s idx = digit - 1;

   __ALIGN64 P521_POINT_IFMA R;
   FE521_SET(R.x) = FE521_SET(R.y) = FE521_SET(R.z) = m256_setzero_i64();

   for (Ipp32s n = 0; n < (1 << (WIN_SIZE - 1)); ++n) {
      const mask8 mask = is_eq_mask(n, idx);

      FE521_MASK_MOV(R.x, R.x, mask, tbl[n].x);
      FE521_MASK_MOV(R.y, R.y, mask, tbl[n].y);
      FE521_MASK_MOV(R.z, R.z, mask, tbl[n].z);
   }

   FE521_COPY(r->x, R.x);
   FE521_COPY(r->y, R.y);
   FE521_COPY(r->z, R.z);
}

#define dbl_point ifma_ec_nistp521_dbl_point
#define add_point ifma_ec_nistp521_add_point
#define neg_coord(R, A) ifma_neg52_p521(&(R), (A))
#define add_point_affine ifma_ec_nistp521_add_point_affine

/* r = n*P = (P + P + ... + P) */
IPP_OWN_DEFN(void, ifma_ec_nistp521_mul_point, (P521_POINT_IFMA * r, const P521_POINT_IFMA *p, const Ipp8u *pExtendedScalar, const int scalarBitSize))
{
   /* default params */
   __ALIGN64 P521_POINT_IFMA tbl[(1 << (WIN_SIZE - 1))];

   __ALIGN64 P521_POINT_IFMA R;
   __ALIGN64 P521_POINT_IFMA H;

   fe521 negHy;
   FE521_SET(negHy) = m256_setzero_i64();
   FE521_SET(R.x) = FE521_SET(R.y) = FE521_SET(R.z) = m256_setzero_i64();
   FE521_SET(H.x) = FE521_SET(H.y) = FE521_SET(H.z) = m256_setzero_i64();

   /* compute tbl[] = [n]P, n = 1, ... , 2^(win_size - 1)
     * tbl[2*n]     = tbl[2*n - 1] + p
     * tbl[2*n + 1] = [2]*tbl[n]
     */
   /* tbl[0] = p */
   FE521_COPY(tbl[0].x, p->x);
   FE521_COPY(tbl[0].y, p->y);
   FE521_COPY(tbl[0].z, p->z);
   /* tbl[1] = [2]*p */
   dbl_point(/* r = */ (tbl + 1), /* a = */ p);
   for (int n = 1; n < ((1 << (WIN_SIZE - 1)) / 2); ++n) {
      add_point(/* r = */ (tbl + 2 * n), /* a = */ (tbl + 2 * n - 1), /* b = */ p);
      dbl_point(/* r = */ (tbl + 2 * n + 1), /* a = */ (tbl + n));
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

   booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, WIN_SIZE);
   extract_table_point(/* r = */ &R, /* digit = */ (Ipp32s)digit, /* tbl = */ tbl);

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

      booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, WIN_SIZE);
      extract_table_point(/* r = */ &H, /* idx = */ (Ipp32s)digit, /* tbl = */ tbl);

      neg_coord(negHy, H.y);

      const mask8 mask_neg = (mask8)(~(sign - 1));
      FE521_MASK_MOV(H.y, H.y, mask_neg, negHy);
      add_point(/* r = */ &R, /* a = */ &R, /* b = */ &H);
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
   wval = (wval << 1) & mask;

   booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, WIN_SIZE);
   extract_table_point(/* r = */ &H, /* idx = */ (Ipp32s)digit, /* tbl = */ tbl);

   neg_coord(negHy, H.y);

   const mask8 mask_neg = (mask8)(~(sign - 1));
   FE521_MASK_MOV(H.y, H.y, mask_neg, negHy);

   add_point(/* r = */ &R, /* a = */ &R, /* b = */ &H);

   FE521_COPY(r->x, R.x);
   FE521_COPY(r->y, R.y);
   FE521_COPY(r->z, R.z);

   /* clear secret data */
   clear_secret_context(&wval,
                        &chunk_no, &chunk_shift,
                        &sign, &digit,
                        &R, &H, NULL);

   return;
}

#include "gfpec/ecnist/ifma_ecprecomp4_p521.h"

/* affine */
#define BP_WIN_SIZE BASE_POINT_WIN_SIZE
#define BP_N_ENTRY BASE_POINT_N_ENTRY

__IPPCP_INLINE void extract_point_affine(P521_POINT_AFFINE_IFMA *r,
                                   const P521_POINT_AFFINE_IFMA_MEM *tbl,
                                   const Ipp32s digit)
{
   Ipp32s idx = digit - 1;

   fe521 x, y;
   FE521_SET(x) = FE521_SET(y) = m256_setzero_i64();

   for (Ipp32s n = 0; n < (1 << ((BP_WIN_SIZE)-1)); ++n, ++tbl) {
      const mask8 mask = is_eq_mask(n, idx);

      /* x */
      FE521_LO(x)  = m256_mask_mov_i64(FE521_LO(x), mask, m256_loadu_i64(FE521_LO(tbl->x)));
      FE521_MID(x) = m256_mask_mov_i64(FE521_MID(x), mask, m256_loadu_i64(FE521_MID(tbl->x)));
      FE521_HI(x)  = m256_mask_mov_i64(FE521_HI(x), mask, m256_loadu_i64(FE521_HI(tbl->x)));
      /* y */
      FE521_LO(y)  = m256_mask_mov_i64(FE521_LO(y), mask, m256_loadu_i64(FE521_LO(tbl->y)));
      FE521_MID(y) = m256_mask_mov_i64(FE521_MID(y), mask, m256_loadu_i64(FE521_MID(tbl->y)));
      FE521_HI(y)  = m256_mask_mov_i64(FE521_HI(y), mask, m256_loadu_i64(FE521_HI(tbl->y)));
   }

   FE521_COPY(r->x, x);
   FE521_COPY(r->y, y);
}

IPP_OWN_DEFN(void, ifma_ec_nistp521_mul_pointbase, (P521_POINT_IFMA * r, const Ipp8u *pExtendedScalar, int scalarBitSize))
{
   /* precompute table */
   const P521_POINT_AFFINE_IFMA_MEM *tbl = &ifma_ec_nistp521r1_bp_precomp[0][0];

   __ALIGN64 P521_POINT_IFMA R;
   __ALIGN64 P521_POINT_AFFINE_IFMA A;
   fe521 Ty;
   FE521_SET(R.x) = FE521_SET(R.y) = FE521_SET(R.z) = m256_setzero_i64();
   FE521_SET(A.x) = FE521_SET(A.y) = m256_setzero_i64();
   FE521_SET(Ty)                   = m256_setzero_i64();

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
   neg_coord(Ty, A.y);
   mask8 mask_neg = (mask8)(~(sign - 1));
   FE521_MASK_MOV(A.y, A.y, mask_neg, Ty);

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
      neg_coord(Ty, A.y);
      mask_neg = (mask8)(~(sign - 1));
      FE521_MASK_MOV(A.y, A.y, mask_neg, Ty);

      /* R += A */
      add_point_affine(&R, &R, &A);
   }

   FE521_COPY(r->x, R.x);
   FE521_COPY(r->y, R.y);
   FE521_COPY(r->z, R.z);

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
