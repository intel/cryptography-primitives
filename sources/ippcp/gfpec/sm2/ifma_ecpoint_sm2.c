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

#include "gfpec/pcpgfpecstuff.h"

#include "gfpec/sm2/ifma_arith_psm2.h"
#include "gfpec/sm2/ifma_defs_sm2.h"
#include "gfpec/sm2/ifma_ecpoint_sm2.h"

/* 2*p */
static const __ALIGN64 Ipp64u psm2_x2[PSM2_LEN52] = {
    0x000ffffffffffffe, 0x000fe00000001fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0001fffffffdffff};
/* 4*p */
static const __ALIGN64 Ipp64u psm2_x4[PSM2_LEN52] = {
    0x000ffffffffffffc, 0x000fc00000003fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0003fffffffbffff};
/* 6*p */
static const __ALIGN64 Ipp64u psm2_x6[PSM2_LEN52] = {
    0x000ffffffffffffa, 0x000fa00000005fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0005fffffff9ffff};
/* 8*p */
static const __ALIGN64 Ipp64u psm2_x8[PSM2_LEN52] = {
    0x000ffffffffffff8, 0x000f800000007fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0007fffffff7ffff};

/* Mont(a) = a*r mod psm2, where r = 2^(6*52) mod psm2 */
static const __ALIGN64 Ipp64u psm2_a[PSM2_LEN52] = {
    0x000ffffffcffffff, 0x000ff03000000fcf, 0x000cffffffffffff, 0x000fffffffffffff, 0x0000fcfffffeffff};

/* Mont(b) = b*r mod psm2, where r = 2^(6*52) mod psm2 */
static const __ALIGN64 Ipp64u psm2_b[PSM2_LEN52] = {
    0x00040fe188de30c4, 0x00012da4d9019422, 0x000b0dc519344af3, 0x000a51c3c71cf379, 0x00005130aa45505e};


#define add(R, A, B)    (R) = fesm2_add_no_red((A), (B))
#define sub(R, A, B)    (R) = fesm2_sub_no_red((A), (B))
#define mul(R, A, B)    (R) = fesm2_mul((A), (B))
#define sqr(R, A)       (R) = fesm2_sqr((A))
#define div2(R, A)      (R) = fesm2_div2_norm((A))
#define norm(R, A)      (R) = ifma_norm52((A))
#define lnorm(R, A)     (R) = ifma_lnorm52((A))
#define inv(R, A)       (R) = fesm2_inv_norm((A))
#define from_mont(R, A) (R) = fesm2_from_mont((A))
/* duplicate mult/sqr/norm */
#define mul_dual(R1, A1, B1, R2, A2, B2) fesm2_mul_dual(&(R1), (A1), (B1), &(R2), (A2), (B2))
#define sqr_dual(R1, A1, R2, A2)         fesm2_sqr_dual(&(R1), (A1), &(R2), (A2))
#define norm_dual(R1, A1, R2, A2)        ifma_norm52_dual(&(R1), (A1), &(R2), (A2))
#define lnorm_dual(R1, A1, R2, A2)       ifma_lnorm52_dual(&(R1), (A1), &(R2), (A2))

IPP_OWN_DEFN(void, gesm2_to_affine, (fesm2 prx[], fesm2 pry[], const PSM2_POINT_IFMA* a)) {

    fesm2 z1, z2, z3;
    z1 = z2 = z3 = setzero_i64();

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

IPP_OWN_DEFN(void, gesm2_dbl, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p)) {
    /*
     * Algorithm (Gueron - Enhanced Montgomery Multiplication)
     * l1 = 3x^2 + a*z^4 = (if sm2 a = -3) = 3*(x^2 - z^4) = 3*(x - z^2)*(x + z^2)
     * z2 = 2*y*z
     * l2 = 4*x*y^2
     * x2 = l1^2 - 2*l2
     * l3 = 8*y^4
     * y2 = l1*(l2 - x2) - l3
     *
     * sum aripmetic: 8 mul; 9 add/sub; 1 div2.
     */
    const fesm2* x1 = &p->x;
    const fesm2* y1 = &p->y;
    const fesm2* z1 = &p->z;

    fesm2 x2;
    fesm2 y2;
    fesm2 z2;
    x2 = y2 = z2 = setzero_i64();

    fesm2 T, U, V, A, B, H;
    T = U = V = setzero_i64();
    A = B = H = setzero_i64();

    const fesm2 M2 = FESM2_LOADU(psm2_x2); /* 2*p */
    const fesm2 M4 = FESM2_LOADU(psm2_x4); /* 4*p */
    const fesm2 M8 = FESM2_LOADU(psm2_x8); /* 8*p */

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

IPP_OWN_DEFN(void, gesm2_add, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const PSM2_POINT_IFMA* q)) {
    /*
     * Algorithm (Gueron - Enhanced Montgomery Multiplication)
     *
     * A = x1*z2^2    B = x2*z1^2      C = y1*z2^3      D = y2*z1^3
     * E = B - A      F = D - C
     * x3 = -E^3 - 2*A*E^2 + F^2
     * y3 = -C*E^3 + F*(A*E^2 - x3)
     * z3 = z1*z2*E
     */
    const fesm2* x1      = &p->x;
    const fesm2* y1      = &p->y;
    const fesm2* z1      = &p->z;
    const mask8 p_is_inf = FESM2_IS_ZERO(p->z);

    const fesm2* x2      = &q->x;
    const fesm2* y2      = &q->y;
    const fesm2* z2      = &q->z;
    const mask8 q_is_inf = FESM2_IS_ZERO(q->z);

    fesm2 x3;
    fesm2 y3;
    fesm2 z3;
    x3 = y3 = z3 = setzero_i64();

    const fesm2 M2 = FESM2_LOADU(psm2_x2); /* 2*p */
    const fesm2 M4 = FESM2_LOADU(psm2_x4); /* 4*p */
    const fesm2 M8 = FESM2_LOADU(psm2_x8); /* 8*p */

    fesm2 U1, U2, S1, S2, H, R;
    U1 = U2 = S1 = setzero_i64();
    S2 = H = R = setzero_i64();

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
   const mask8 f_are_zero     = FESM2_IS_ZERO(R);
   const mask8 e_are_zero     = FESM2_IS_ZERO(H);
   const mask8 point_is_equal = ((e_are_zero & f_are_zero) & (~p_is_inf) & (~q_is_inf));

    __ALIGN64 PSM2_POINT_IFMA r2;
    r2.x = r2.y = r2.z = setzero_i64();
    if ((mask8)0xFF == point_is_equal) {
        gesm2_dbl(&r2, p);
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
    FESM2_MASK_MOV(x3, x3, p_is_inf, *x2);
    FESM2_MASK_MOV(y3, y3, p_is_inf, *y2);
    FESM2_MASK_MOV(z3, z3, p_is_inf, *z2);

    /* T = q_is_inf ? p : T */
    FESM2_MASK_MOV(x3, x3, q_is_inf, *x1);
    FESM2_MASK_MOV(y3, y3, q_is_inf, *y1);
    FESM2_MASK_MOV(z3, z3, q_is_inf, *z1);

    /* r = point_is_equal ? r2 : T */
    FESM2_MASK_MOV(x3, x3, point_is_equal, r2.x);
    FESM2_MASK_MOV(y3, y3, point_is_equal, r2.y);
    FESM2_MASK_MOV(z3, z3, point_is_equal, r2.z);

    r->x = x3;
    r->y = y3;
    r->z = z3;

    return;
}

IPP_OWN_DEFN(void, gesm2_add_affine, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const PSM2_AFFINE_POINT_IFMA* q)) {
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
    const fesm2* x1      = &p->x;
    const fesm2* y1      = &p->y;
    const fesm2* z1      = &p->z;
    const mask8 p_is_inf = FESM2_IS_ZERO(p->z);

    /* coordinate of q (affine) */
    const fesm2* x2      = &q->x;
    const fesm2* y2      = &q->y;
    const mask8 q_is_inf = (FESM2_IS_ZERO(q->x) & FESM2_IS_ZERO(q->y));

    fesm2 x3;
    fesm2 y3;
    fesm2 z3;
    x3 = y3 = z3 = setzero_i64();

    const fesm2 M2 = FESM2_LOADU(psm2_x2); /* 2*p */
    const fesm2 M4 = FESM2_LOADU(psm2_x4); /* 4*p */
    const fesm2 M8 = FESM2_LOADU(psm2_x8); /* 8*p */

    fesm2 U2, S2, H, R;
    U2 = S2 = H = R = setzero_i64();

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

    const fesm2 ONE = FESM2_LOADU(PSM2_R);
    /* T = p_is_inf ? q : T */
    FESM2_MASK_MOV(x3, x3, p_is_inf, *x2);
    FESM2_MASK_MOV(y3, y3, p_is_inf, *y2);
    FESM2_MASK_MOV(z3, z3, p_is_inf, ONE);

    /* T = q_is_inf ? p : T */
    FESM2_MASK_MOV(x3, x3, q_is_inf, *x1);
    FESM2_MASK_MOV(y3, y3, q_is_inf, *y1);
    FESM2_MASK_MOV(z3, z3, q_is_inf, *z1);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    return;
}

IPP_OWN_DEFN(int, gesm2_is_on_curve, (const PSM2_POINT_IFMA* p, const int use_jproj_coords)) {
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
    const fesm2 M6 = FESM2_LOADU(psm2_x6);
    const fesm2 a  = FESM2_LOADU(psm2_a);
    const fesm2 b  = FESM2_LOADU(psm2_b);

    fesm2 rh, Z4, Z6, tmp;
    rh = Z4 = Z6 = tmp = setzero_i64();

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

    const mask8 mask = FESM2_CMP_MASK(rh, tmp, _MM_CMPINT_EQ);
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

static __NOINLINE void clear_secret_context(Ipp16u* wval,
                                            Ipp32s* chunk_no, Ipp32s* chunk_shift,
                                            Ipp8u* sign, Ipp8u* digit,
                                            PSM2_POINT_IFMA* R, PSM2_POINT_IFMA* H,
                                            PSM2_AFFINE_POINT_IFMA* A) {
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
    return;
}

__IPPCP_INLINE mask8 is_eq_mask(const Ipp32s a, const Ipp32s b) {
    const Ipp32s eq  = a ^ b;
    const Ipp32s v   = ~eq & (eq - 1);
    const Ipp32s msb = 0 - (v >> (sizeof(a) * 8 - 1));
    return (mask8)(0 - msb);
}

#define WIN_SIZE (5)

static void table_get_point(PSM2_POINT_IFMA* r, const Ipp32s digit, const PSM2_POINT_IFMA tbl[]) {
    const Ipp32s idx = digit - 1;

    __ALIGN64 PSM2_POINT_IFMA R;
    R.x = R.y = R.z = setzero_i64();

    for (Ipp32s n = 0; n < (1 << (WIN_SIZE - 1)); ++n) {
        const mask8 mask = is_eq_mask(n, idx);

        FESM2_MASK_MOV(R.x, R.x, mask, tbl[n].x);
        FESM2_MASK_MOV(R.y, R.y, mask, tbl[n].y);
        FESM2_MASK_MOV(R.z, R.z, mask, tbl[n].z);
    }

    r->x = R.x;
    r->y = R.y;
    r->z = R.z;
    return;
}

#define dbl_point        gesm2_dbl
#define add_point        gesm2_add
#define neg_coord(R, A)  (R) = fesm2_neg_norm((A))
#define add_point_affine gesm2_add_affine

/* r = n*P = (P + P + ... + P) */
IPP_OWN_DEFN(void, gesm2_mul, (PSM2_POINT_IFMA * r, const PSM2_POINT_IFMA* p, const Ipp8u* pExtendedScalar, const int scalarBitSize)) {
    /* default params */
    __ALIGN64 PSM2_POINT_IFMA tbl[(1 << (WIN_SIZE - 1))];

    __ALIGN64 PSM2_POINT_IFMA R;
    __ALIGN64 PSM2_POINT_IFMA H;

    fesm2 negHy;
    negHy = setzero_i64();
    R.x = R.y = R.z = setzero_i64();
    H.x = H.y = H.z = setzero_i64();

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
        add_point(/* r = */ (tbl + 2 * n), /* a = */ (tbl + 2 * n - 1), /* b = */ p);
        dbl_point(/* r = */ (tbl + 2 * n + 1), /* a = */ (tbl + n));
    }

    Ipp16u wval;
    Ipp8u digit, sign;
    mask8 mask_neg;
    const Ipp32s mask = ((1 << (WIN_SIZE + 1)) - 1); /* mask 0b111111 */
    Ipp32s bit        = scalarBitSize - (scalarBitSize % WIN_SIZE);

    Ipp32s chunk_no    = (bit - 1) / 8;
    Ipp32s chunk_shift = (bit - 1) % 8;

    if (0 != bit) {
        wval = *((Ipp16u*)(pExtendedScalar + chunk_no));
        wval = (Ipp16u)((wval >> chunk_shift) & mask);
    } else {
        wval = 0;
    }

    booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, /* w = */ WIN_SIZE);
    table_get_point(/* r = */ &R, /* digit = */ (Ipp32s)digit, /* tbl = */ tbl);

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

        wval = *((Ipp16u*)(pExtendedScalar + chunk_no));
        wval = (Ipp16u)((wval >> chunk_shift) & mask);

        booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, /* w = */ WIN_SIZE);
        table_get_point(/* r = */ &H, /* idx = */ (Ipp32s)digit, /* tbl = */ tbl);

        neg_coord(negHy, H.y);

        mask_neg = (mask8)(~(sign - 1));
        FESM2_MASK_MOV(H.y, H.y, mask_neg, negHy);
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

    wval = *((Ipp16u*)(pExtendedScalar + 0));
    wval = (wval << 1) & mask;

    booth_recode(/* sign = */ &sign, /* digit = */ &digit, /* in = */ (Ipp8u)wval, /* w = */ WIN_SIZE);
    table_get_point(/* r = */ &H, /* idx = */ (Ipp32s)digit, /* tbl = */ tbl);

    neg_coord(negHy, H.y);

    mask_neg = (mask8)(~(sign - 1));
    FESM2_MASK_MOV(H.y, H.y, mask_neg, negHy);

    add_point(/* r = */ &R, /* a = */ &R, /* b = */ &H);

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

#include "gfpec/sm2/ifma_ecprecomp7_sm2.h"

/* affine */
#define BP_WIN_SIZE BASE_POINT_WIN_SIZE
#define BP_N_ENTRY  BASE_POINT_N_ENTRY

__IPPCP_INLINE void extract_point_affine(PSM2_AFFINE_POINT_IFMA* r,
                                   const SINGLE_PSM2_AFFINE_POINT_IFMA* tbl,
                                   const Ipp32s digit) {
    const Ipp32s idx = digit - 1;

    __ALIGN64 PSM2_AFFINE_POINT_IFMA R;
    R.x = R.y = setzero_i64();

    for (Ipp32s n = 0; n < (1 << ((BP_WIN_SIZE)-1)); ++n, ++tbl) {
        const mask8 mask = is_eq_mask(n, idx);

        FESM2_MASK_MOV(R.x, R.x, mask, FESM2_LOADU(tbl->x));
        FESM2_MASK_MOV(R.y, R.y, mask, FESM2_LOADU(tbl->y));
    }

    r->x = R.x;
    r->y = R.y;
    return;
}

IPP_OWN_DEFN(void, gesm2_select_ap_w7_ifma, (BNU_CHUNK_T * pAffinePoint, const BNU_CHUNK_T* pTable, int index)) {
    __ALIGN64 PSM2_AFFINE_POINT_IFMA ap;

    extract_point_affine(&ap, (SINGLE_PSM2_AFFINE_POINT_IFMA*)pTable, index);

    ap.x = fesm2_from_mont(ap.x);
    ap.y = fesm2_from_mont(ap.y);

    fesm2_convert_radix52_radix64(pAffinePoint, ap.x);
    fesm2_convert_radix52_radix64(pAffinePoint + PSM2_LEN64, ap.y);
}

IPP_OWN_DEFN(void, gesm2_mul_base, (PSM2_POINT_IFMA * r, const Ipp8u* pExtendedScalar)) {
    const SINGLE_PSM2_AFFINE_POINT_IFMA* tbl = &ifma_ec_sm2_bp_precomp[0][0];

    __ALIGN64 PSM2_POINT_IFMA R;
    __ALIGN64 PSM2_AFFINE_POINT_IFMA A;
    fesm2 Ty;
    R.x = R.y = R.z = setzero_i64();
    A.x = A.y = setzero_i64();
    Ty        = setzero_i64();

    Ipp16u wval;
    Ipp8u digit, sign;
    const Ipp32s mask = ((1 << (BP_WIN_SIZE + 1)) - 1); /* mask 0b11111 */
    Ipp32s bit        = 0;
    Ipp32s chunk_no, chunk_shift;

    wval = *((Ipp16u*)(pExtendedScalar + 0));
    wval = (Ipp16u)((wval << 1) & mask);

    booth_recode(&sign, &digit, (Ipp8u)wval, BP_WIN_SIZE);
    extract_point_affine(&A, tbl, (Ipp32s)digit);
    tbl += BP_N_ENTRY;

    /* A = sign == 1 ? -A : A */
    neg_coord(Ty, A.y);
    mask8 mask_neg = (mask8)(~(sign - 1));
    FESM2_MASK_MOV(A.y, A.y, mask_neg, Ty);

    /* R += A */
    add_point_affine(&R, &R, &A);

    for (bit += BP_WIN_SIZE; bit <= 256; bit += BP_WIN_SIZE) {
        chunk_no    = (bit - 1) / 8;
        chunk_shift = (bit - 1) % 8;

        wval = *((Ipp16u*)(pExtendedScalar + chunk_no));
        wval = (Ipp16u)((wval >> chunk_shift) & mask);

        booth_recode(&sign, &digit, (Ipp8u)wval, BP_WIN_SIZE);
        extract_point_affine(&A, tbl, (Ipp32s)digit);
        tbl += BP_N_ENTRY;

        /* A = sign == 1 ? -A : A */
        neg_coord(Ty, A.y);
        mask_neg = (mask8)(~(sign - 1));
        FESM2_MASK_MOV(A.y, A.y, mask_neg, Ty);

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

#endif // (_IPP32E >= _IPP32E_K1)
