/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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
 * Inline assembly implementations for P-256 IFMA arithmetic
 * to eliminate stack usage for security against memory attacks
 *
 * This file contains:
 * - External assembly function declarations (implemented in ifma_arith_p256.asm)
 * - These functions operate directly on ZMM registers (m512 type)
 */

#ifndef IFMA_ARITH_P256_ASM_H
#define IFMA_ARITH_P256_ASM_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_defs.h"
#include "gfpec/ecnist/ifma_ecpoint_p256.h"
#include "gfpec/ecnist/ifma_arith_p256.h"

/* Dual Montgomery multiplication - operates directly on registers */
#define ifma_amm52_dual_p256_asm_zmm OWNAPI(ifma_amm52_dual_p256_asm_zmm)
/* clang-format off */
IPP_OWN_DECL(void, ifma_amm52_dual_p256_asm_zmm, (m512* out_r1,
                                                  const m512* in_a1,
                                                  const m512* in_b1,
                                                  m512* out_r2,
                                                  const m512* in_a2,
                                                  const m512* in_b6))

#define ifma_lnorm52_dual_p256_asm_zmm OWNAPI(ifma_lnorm52_dual_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_lnorm52_dual_p256_asm_zmm, (m512* out_pr1,
                                                    m512* in_a1,
                                                    m512* out_pr2,
                                                    m512* in_a2))
/* clang-format on */

/* Montgomery multiplication - operates directly on registers */
#define ifma_amm52_p256_asm_zmm OWNAPI(ifma_amm52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_amm52_p256_asm_zmm, (m512 * out_pr, const m512* in_a, const m512* in_b))

/* Dual full normalization - operates directly on registers */
#define ifma_norm52_dual_p256_asm_zmm OWNAPI(ifma_norm52_dual_p256_asm_zmm)
/* clang-format off */
IPP_OWN_DECL(void, ifma_norm52_dual_p256_asm_zmm, (m512* out_pr1,
                                                   m512* in_a1,
                                                   m512* out_pr2,
                                                   m512* in_a2))
/* clang-format on */

/* Single light normalization - operates directly on registers */
#define ifma_lnorm52_p256_asm_zmm OWNAPI(ifma_lnorm52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_lnorm52_p256_asm_zmm, (m512 * out_pr, m512* in_a))

/* Single full normalization - operates directly on registers */
#define ifma_norm52_p256_asm_zmm OWNAPI(ifma_norm52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_norm52_p256_asm_zmm, (m512 * out_pr, m512* in_a))

/* Half (divide by 2) - operates directly on registers */
#define ifma_half52_p256_asm_zmm OWNAPI(ifma_half52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_half52_p256_asm_zmm, (m512 * out_pr, m512* in_a))

/* Inversion (R = 1/z) - operates directly on registers */
#define ifma_aminv52_p256_asm_zmm OWNAPI(ifma_aminv52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_aminv52_p256_asm_zmm, (m512 * out_pr, m512* in_a))

/* Point doubling - operates directly on registers */
#define ifma_ec_nistp256_dbl_point_asm_zmm OWNAPI(ifma_ec_nistp256_dbl_point_asm_zmm)
/* clang-format off */
IPP_OWN_DECL(void, ifma_ec_nistp256_dbl_point_asm_zmm, (m512* out_R_X,
                                                        m512* out_R_Y,
                                                        m512* out_R_Z,
                                                        const m512* in_P_X,
                                                        const m512* in_P_Y,
                                                        const m512* in_P_Z))

/* Point addition - operates directly on registers (in-place)
 * Computes P = P + Q
 * P is passed by pointer (input/output), Q is passed by value.
 * Special cases (infinity, point equality) handled in assembly. */
#define ifma_ec_nistp256_add_point_asm_zmm OWNAPI(ifma_ec_nistp256_add_point_asm_zmm)
IPP_OWN_DECL(void, ifma_ec_nistp256_add_point_asm_zmm, (m512* P_X,
                                                        m512* P_Y,
                                                        m512* P_Z,
                                                        const m512* in_Q_X,
                                                        const m512* in_Q_Y,
                                                        const m512* in_Q_Z))
/* clang-format on */

/* Main scalar multiplication loop - combines precomputation, booth extraction, and dbl3_add
 * Performs the complete scalar multiplication:
 *   1. Compute table: tbl[0]=P, tbl[1]=2P, tbl[2]=3P, tbl[3]=4P
 *   2. R = get_booth_point(first_window)
 *   3. for (bit -= WIN_SIZE; bit >= 0; bit -= WIN_SIZE) {
 *          H = get_booth_point(pScalar, bit);
 *          R = 8*R + H;
 *      }
 *   4. Normalize result
 * R: output point, pScalar: extended scalar, scalarBitSize: bit size, P: input point (in ZMM) */
#define ifma_ec_nistp256_mul_point_loop_asm_zmm OWNAPI(ifma_ec_nistp256_mul_point_loop_asm_zmm)
/* clang-format off */
IPP_OWN_DECL(void, ifma_ec_nistp256_mul_point_loop_asm_zmm, (P256_POINT_IFMA* R,
                                                             const Ipp8u* pScalar,
                                                             Ipp32s scalarBitSize,
                                                             const m512* px,
                                                             const m512* py,
                                                             const m512* pz))

                                                             /*
 * Transformation to affine coordinate
 * Computes affine coordinates from the given point A passed in the projective representation. */
#define ifma_ec_nistp256_get_affine_coords_asm_zmm OWNAPI(ifma_ec_nistp256_get_affine_coords_asm_zmm)
IPP_OWN_DECL(void, ifma_ec_nistp256_get_affine_coords_asm_zmm, (m512* out_R_X, m512* out_R_Y,
                                                                const P256_POINT_IFMA* A))
/* clang-format on */

/*
 * Transformation from Montgomery domain. */
#define ifma_frommont52_p256_asm_zmm OWNAPI(ifma_frommont52_p256_asm_zmm)
IPP_OWN_DECL(void, ifma_frommont52_p256_asm_zmm, (m512 * out_pr, m512* in_a))


/* Convenience macros - these just call the assembly functions directly */

/**
 * \brief Dual Montgomery multiplication
 * Computes r1 = a1 * b1 mod p256 and r2 = a2 * b2 mod p256 simultaneously
 */
#define ifma_amm52_dual_p256_mul_asm(out_r1, in_a1, in_b1, out_r2, in_a2, in_b6) \
    ifma_amm52_dual_p256_asm_zmm((out_r1), (in_a1), (in_b1), (out_r2), (in_a2), (in_b6))

/**
 * \brief Dual squaring using assembly
 */
#define ifma_amm52_dual_p256_sqr_asm(r1, a1, r2, a2) \
    ifma_amm52_dual_p256_asm_zmm(r1, a1, a1, r2, a2, a2);

/**
 * \brief Squaring using assembly
 */
#define ifma_ams52_p256_asm(out_pr, in_a) ifma_amm52_p256_asm_zmm(out_pr, in_a, in_a);

/**
 * \brief Dual light normalization (carry propagation only)
 */
#define ifma_lnorm52_dual_p256_asm(out_pr1, in_a1, out_pr2, in_a2) \
    ifma_lnorm52_dual_p256_asm_zmm((out_pr1), (in_a1), (out_pr2), (in_a2))

/**
 * \brief Dual full normalization
 */
#define ifma_norm52_dual_p256_asm(out_pr1, in_a1, out_pr2, in_a2) \
    ifma_norm52_dual_p256_asm_zmm((out_pr1), (in_a1), (out_pr2), (in_a2))

/**
 * \brief Single Montgomery multiplication
 * Computes r = a * b mod p256.
 */
#define ifma_amm52_p256_asm(out_pr, in_a, in_b) ifma_amm52_p256_asm_zmm(out_pr, in_a, in_b);

/**
 * \brief Single light normalization (carry propagation only)
 */
#define ifma_lnorm52_p256_asm(out_pr, in_a) ifma_lnorm52_p256_asm_zmm((out_pr), (in_a))

/**
 * \brief Single full normalization
 */
#define ifma_norm52_p256_asm(out_pr, in_a) ifma_norm52_p256_asm_zmm((out_pr), (in_a))

/**
 * \brief Transformation to affine coordinate
 */
#define ifma_ec_nistp256_get_affine_coords_asm(out_R_X, out_R_Y, A) \
    ifma_ec_nistp256_get_affine_coords_asm_zmm((out_R_X), (out_R_Y), (A))

/**
 * \brief Transformation from Montgomery domain
 */
#define ifma_frommont52_p256_asm(out_pr, in_a) ifma_frommont52_p256_asm_zmm((out_pr), (in_a))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // IFMA_ARITH_P256_ASM_H
