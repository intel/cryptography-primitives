/*************************************************************************
 * Copyright (C) 2019-2024 Intel Corporation
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

#include <crypto_mb/rsa.h>
#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/rsa/ifma_rsa_method.h>

#if (_MBX >= _MBX_K1)

/*
// public exponent e=65537 implied
*/
void ifma_cp_rsa_pub_layer_mb8(const int8u* const from_pa[8],
                               int8u* const to_pa[8],
                               const int64u* const n_pa[8],
                               int rsaBitlen,
                               const mbx_RSA_Method* m,
                               int8u* pBuffer)
{
    int len52 = NUMBER_OF_DIGITS(rsaBitlen, DIGIT_SIZE);

    /* 64-byte aligned buffer of int64[8] */
    pint64u_x8 pBuffer_x8 = (pint64u_x8)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb8 buffers */
    pint64u_x8 k0_mb8      = pBuffer_x8;
    pint64u_x8 rr_mb8      = k0_mb8 + 1;
    pint64u_x8 inout_mb8   = rr_mb8 + len52;
    pint64u_x8 n_mb8       = inout_mb8 + len52;
    pint64u_x8 work_buffer = n_mb8 + len52;

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(len52, 10));
    ifma_BNU_to_mb8(n_mb8, n_pa, rsaBitlen);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8[0], n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, rsaBitlen);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, rsaBitlen);

    /* exponentiation */
    m->expfunc65537(inout_mb8,
                    (const int64u(*)[8])inout_mb8,
                    (const int64u(*)[8])n_mb8,
                    (const int64u(*)[8])rr_mb8,
                    k0_mb8[0],
                    (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, rsaBitlen);
}

/*
// private key
*/
void ifma_cp_rsa_prv2_layer_mb8(const int8u* const from_pa[8],
                                int8u* const to_pa[8],
                                const int64u* const d_pa[8],
                                const int64u* const n_pa[8],
                                int rsaBitlen,
                                const mbx_RSA_Method* m,
                                int8u* pBuffer)

{
    int len52 = NUMBER_OF_DIGITS(rsaBitlen, DIGIT_SIZE);
    int len64 = NUMBER_OF_DIGITS(rsaBitlen, 64);

    /* 64-byte aligned buffer of int64[8] */
    pint64u_x8 pBuffer_x8 = (pint64u_x8)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb8 buffers */
    pint64u_x8 k0_mb8      = pBuffer_x8;
    pint64u_x8 d_mb8       = k0_mb8 + 1;
    pint64u_x8 rr_mb8      = d_mb8 + len64;
    pint64u_x8 inout_mb8   = rr_mb8 + len52;
    pint64u_x8 n_mb8       = inout_mb8 + len52;
    pint64u_x8 work_buffer = n_mb8 + len52;

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(len52, 10));
    ifma_BNU_to_mb8(n_mb8, n_pa, rsaBitlen);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8[0], n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, rsaBitlen);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, rsaBitlen);

    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy(d_mb8, d_pa, rsaBitlen);

    /* exponentiation */
    m->expfun(inout_mb8,
              (const int64u(*)[8])inout_mb8,
              (const int64u(*)[8])d_mb8,
              (const int64u(*)[8])n_mb8,
              (const int64u(*)[8])rr_mb8,
              k0_mb8[0],
              (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, rsaBitlen);

    /* clear exponents */
    zero_mb8(d_mb8, len64);
}

/*
// private key (ctr)
*/
void ifma_cp_rsa_prv5_layer_mb8(const int8u* const from_pa[8],
                                int8u* const to_pa[8],
                                const int64u* const p_pa[8],
                                const int64u* const q_pa[8],
                                const int64u* const dp_pa[8],
                                const int64u* const dq_pa[8],
                                const int64u* const iq_pa[8],
                                int rsaBitlen,
                                const mbx_RSA_Method* m,
                                int8u* pBuffer)

{
    int factorBitlen = rsaBitlen / 2;
    int len52        = NUMBER_OF_DIGITS(factorBitlen, DIGIT_SIZE);
    int len64        = NUMBER_OF_DIGITS(factorBitlen, 64);

    /* 64-byte aligned buffer of int64[8] */
    pint64u_x8 pBuffer_x8 = (pint64u_x8)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb8 buffers */
    pint64u_x8 k0_mb8      = pBuffer_x8;
    pint64u_x8 p_mb8       = k0_mb8 + 1;
    pint64u_x8 q_mb8       = p_mb8 + len52;
    pint64u_x8 d_mb8       = q_mb8 + len52;
    pint64u_x8 rr_mb8      = d_mb8 + len64;
    pint64u_x8 xp_mb8      = rr_mb8 + len52;
    pint64u_x8 xq_mb8      = xp_mb8 + len52;
    pint64u_x8 inp_mb8     = xq_mb8 + len52;
    pint64u_x8 work_buffer = inp_mb8 + len52 * 2;

    /* convert input to ifma fmt */
    zero_mb8(inp_mb8, len52 * 2);
    ifma_HexStr8_to_mb8(inp_mb8, from_pa, rsaBitlen);

    /*
   // q exponentiation
   */

    /* convert modulus to ifma fmt */
    ifma_BNU_to_mb8(q_mb8, q_pa, factorBitlen);
    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8[0], q_mb8[0]);
    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, q_mb8, factorBitlen);
    /* xq = x mod q */
    m->amred52x(xq_mb8, (const int64u(*)[8])inp_mb8, (const int64u(*)[8])q_mb8, k0_mb8[0]);
    m->ammul52x((int64u*)xq_mb8, (int64u*)xq_mb8, (int64u*)rr_mb8, (int64u*)q_mb8, k0_mb8[0]);
    m->modsub52x(xq_mb8,
                 (const int64u(*)[8])xq_mb8,
                 (const int64u(*)[8])q_mb8,
                 (const int64u(*)[8])q_mb8); // ??
    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy(d_mb8, dq_pa, factorBitlen);

    m->expfun(xq_mb8,
              (const int64u(*)[8])xq_mb8,
              (const int64u(*)[8])d_mb8,
              (const int64u(*)[8])q_mb8,
              (const int64u(*)[8])rr_mb8,
              k0_mb8[0],
              (int64u(*)[8])work_buffer);

    /*
   // p exponentiation
   */

    /* convert modulus to ifma fmt */
    ifma_BNU_to_mb8(p_mb8, p_pa, factorBitlen);
    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8[0], p_mb8[0]);
    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, p_mb8, factorBitlen);
    /* xq = x mod q */
    m->amred52x(xp_mb8, (const int64u(*)[8])inp_mb8, (const int64u(*)[8])p_mb8, k0_mb8[0]);
    m->ammul52x((int64u*)xp_mb8, (int64u*)xp_mb8, (int64u*)rr_mb8, (int64u*)p_mb8, k0_mb8[0]);
    m->modsub52x(xp_mb8,
                 (const int64u(*)[8])xp_mb8,
                 (const int64u(*)[8])p_mb8,
                 (const int64u(*)[8])p_mb8); // ??
    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy(d_mb8, dp_pa, factorBitlen);

    m->expfun(xp_mb8,
              (const int64u(*)[8])xp_mb8,
              (const int64u(*)[8])d_mb8,
              (const int64u(*)[8])p_mb8,
              (const int64u(*)[8])rr_mb8,
              k0_mb8[0],
              (int64u(*)[8])work_buffer);

    /*
   // crt recombination
   */

    /* xp = (xp-xq) mod p */
    m->modsub52x(inp_mb8,
                 (const int64u(*)[8])xq_mb8,
                 (const int64u(*)[8])p_mb8,
                 (const int64u(*)[8])p_mb8); /* for specific case p<q */
    m->modsub52x(
        xp_mb8, (const int64u(*)[8])xp_mb8, (const int64u(*)[8])inp_mb8, (const int64u(*)[8])p_mb8);

    /* xp = (xp*coef) mod p */
    ifma_BNU_to_mb8(inp_mb8, iq_pa, factorBitlen); /* coef */
    m->ammul52x((int64u*)xp_mb8,
                (int64u*)xp_mb8,
                (int64u*)rr_mb8,
                (int64u*)p_mb8,
                k0_mb8[0]); /* -> mont domain */
    m->ammul52x(
        (int64u*)xp_mb8, (int64u*)xp_mb8, (int64u*)inp_mb8, (int64u*)p_mb8, k0_mb8[0]); /* mmul */
    m->modsub52x(xp_mb8,
                 (const int64u(*)[8])xp_mb8,
                 (const int64u(*)[8])p_mb8,
                 (const int64u(*)[8])p_mb8); /* correction */

    /* xp = (xp*q + xq) */
    zero_mb8(inp_mb8, len52 * 2);
    copy_mb8(inp_mb8, (const int64u(*)[8])xq_mb8, len52);
    m->mla52x(inp_mb8, (const int64u(*)[8])xp_mb8, (const int64u(*)[8])q_mb8);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inp_mb8, rsaBitlen);

    /* clear exponents, p, q */
    zero_mb8(d_mb8, len64);
    zero_mb8(q_mb8, len52);
    zero_mb8(p_mb8, len52);
}

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

/*
// public exponent e=65537 implied
*/
void ifma_cp_rsa_pub_layer_mb4(const int8u* const from_pa[4],
                               int8u* const to_pa[4],
                               const int64u* const n_pa[4],
                               int rsaBitlen,
                               const mbx_RSA_Method* m,
                               int8u* pBuffer)
{
    int len52 = NUMBER_OF_DIGITS(rsaBitlen, DIGIT_SIZE);

    /* 64-byte aligned buffer of int64[8] */
    pint64u_x4 pBuffer_x4 = (pint64u_x4)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb8 buffers */
    pint64u_x4 k0_mb4      = pBuffer_x4;
    pint64u_x4 rr_mb4      = k0_mb4 + 1;
    pint64u_x4 inout_mb4   = rr_mb4 + len52;
    pint64u_x4 n_mb4       = inout_mb4 + len52;
    pint64u_x4 work_buffer = n_mb4 + len52;

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(len52, 10));
    ifma_BNU_to_mb4(n_mb4, n_pa, rsaBitlen);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4[0], n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, rsaBitlen);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, rsaBitlen);

    /* exponentiation */
    m->expfunc65537(inout_mb4,
                    (const int64u(*)[4])inout_mb4,
                    (const int64u(*)[4])n_mb4,
                    (const int64u(*)[4])rr_mb4,
                    k0_mb4[0],
                    (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, rsaBitlen);
}

/*
// private key
*/
void ifma_cp_rsa_prv2_layer_mb4(const int8u* const from_pa[4],
                                int8u* const to_pa[4],
                                const int64u* const d_pa[4],
                                const int64u* const n_pa[4],
                                int rsaBitlen,
                                const mbx_RSA_Method* m,
                                int8u* pBuffer)

{
    int len52 = NUMBER_OF_DIGITS(rsaBitlen, DIGIT_SIZE);
    int len64 = NUMBER_OF_DIGITS(rsaBitlen, 64);

    /* 64-byte aligned buffer of int64[4] */
    pint64u_x4 pBuffer_x4 = (pint64u_x4)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb4 buffers */
    pint64u_x4 k0_mb4      = pBuffer_x4;
    pint64u_x4 d_mb4       = k0_mb4 + 1;
    pint64u_x4 rr_mb4      = d_mb4 + len64;
    pint64u_x4 inout_mb4   = rr_mb4 + len52;
    pint64u_x4 n_mb4       = inout_mb4 + len52;
    pint64u_x4 work_buffer = n_mb4 + len52;

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(len52, 10));
    ifma_BNU_to_mb4(n_mb4, n_pa, rsaBitlen);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4[0], n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, rsaBitlen);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, rsaBitlen);

    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy_mb4(d_mb4, d_pa, rsaBitlen);

    /* exponentiation */
    m->expfun(inout_mb4,
              (const int64u(*)[4])inout_mb4,
              (const int64u(*)[4])d_mb4,
              (const int64u(*)[4])n_mb4,
              (const int64u(*)[4])rr_mb4,
              k0_mb4[0],
              (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, rsaBitlen);

    /* clear exponents */
    zero_mb4(d_mb4, len64);
}

/*
// private key (ctr)
*/
void ifma_cp_rsa_prv5_layer_mb4(const int8u* const from_pa[4],
                                int8u* const to_pa[4],
                                const int64u* const p_pa[4],
                                const int64u* const q_pa[4],
                                const int64u* const dp_pa[4],
                                const int64u* const dq_pa[4],
                                const int64u* const iq_pa[4],
                                int rsaBitlen,
                                const mbx_RSA_Method* m,
                                int8u* pBuffer)

{
    int factorBitlen = rsaBitlen / 2;
    int len52        = NUMBER_OF_DIGITS(factorBitlen, DIGIT_SIZE);
    int len64        = NUMBER_OF_DIGITS(factorBitlen, 64);

    /* 64-byte aligned buffer of int64[4] */
    pint64u_x4 pBuffer_x4 = (pint64u_x4)IFMA_ALIGNED_PTR(pBuffer, 64);

    /* allocate mb4 buffers */
    pint64u_x4 k0_mb4      = pBuffer_x4;
    pint64u_x4 p_mb4       = k0_mb4 + 1;
    pint64u_x4 q_mb4       = p_mb4 + len52;
    pint64u_x4 d_mb4       = q_mb4 + len52;
    pint64u_x4 rr_mb4      = d_mb4 + len64;
    pint64u_x4 xp_mb4      = rr_mb4 + len52;
    pint64u_x4 xq_mb4      = xp_mb4 + len52;
    pint64u_x4 inp_mb4     = xq_mb4 + len52;
    pint64u_x4 work_buffer = inp_mb4 + len52 * 2;

    /* convert input to ifma fmt */
    zero_mb4(inp_mb4, len52 * 2);
    ifma_HexStr4_to_mb4(inp_mb4, from_pa, rsaBitlen);

    /*
   // q exponentiation
   */

    /* convert modulus to ifma fmt */
    ifma_BNU_to_mb4(q_mb4, q_pa, factorBitlen);
    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4[0], q_mb4[0]);
    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, q_mb4, factorBitlen);
    /* xq = x mod q */
    m->amred52x(xq_mb4, (const int64u(*)[4])inp_mb4, (const int64u(*)[4])q_mb4, k0_mb4[0]);
    m->ammul52x((int64u*)xq_mb4, (int64u*)xq_mb4, (int64u*)rr_mb4, (int64u*)q_mb4, k0_mb4[0]);
    m->modsub52x(xq_mb4,
                 (const int64u(*)[4])xq_mb4,
                 (const int64u(*)[4])q_mb4,
                 (const int64u(*)[4])q_mb4); // ??
    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy_mb4(d_mb4, dq_pa, factorBitlen);

    m->expfun(xq_mb4,
              (const int64u(*)[4])xq_mb4,
              (const int64u(*)[4])d_mb4,
              (const int64u(*)[4])q_mb4,
              (const int64u(*)[4])rr_mb4,
              k0_mb4[0],
              (int64u(*)[4])work_buffer);

    /*
   // p exponentiation
   */

    /* convert modulus to ifma fmt */
    ifma_BNU_to_mb4(p_mb4, p_pa, factorBitlen);
    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4[0], p_mb4[0]);
    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, p_mb4, factorBitlen);
    /* xq = x mod q */
    m->amred52x(xp_mb4, (const int64u(*)[4])inp_mb4, (const int64u(*)[4])p_mb4, k0_mb4[0]);
    m->ammul52x((int64u*)xp_mb4, (int64u*)xp_mb4, (int64u*)rr_mb4, (int64u*)p_mb4, k0_mb4[0]);
    m->modsub52x(xp_mb4,
                 (const int64u(*)[4])xp_mb4,
                 (const int64u(*)[4])p_mb4,
                 (const int64u(*)[4])p_mb4); // ??
    /* re-arrange exps to ifma */
    ifma_BNU_transpose_copy_mb4(d_mb4, dp_pa, factorBitlen);

    m->expfun(xp_mb4,
              (const int64u(*)[4])xp_mb4,
              (const int64u(*)[4])d_mb4,
              (const int64u(*)[4])p_mb4,
              (const int64u(*)[4])rr_mb4,
              k0_mb4[0],
              (int64u(*)[4])work_buffer);

    /*
   // crt recombination
   */

    /* xp = (xp-xq) mod p */
    m->modsub52x(inp_mb4,
                 (const int64u(*)[4])xq_mb4,
                 (const int64u(*)[4])p_mb4,
                 (const int64u(*)[4])p_mb4); /* for specific case p<q */
    m->modsub52x(
        xp_mb4, (const int64u(*)[4])xp_mb4, (const int64u(*)[4])inp_mb4, (const int64u(*)[4])p_mb4);

    /* xp = (xp*coef) mod p */
    ifma_BNU_to_mb4(inp_mb4, iq_pa, factorBitlen); /* coef */
    m->ammul52x((int64u*)xp_mb4,
                (int64u*)xp_mb4,
                (int64u*)rr_mb4,
                (int64u*)p_mb4,
                k0_mb4[0]); /* -> mont domain */
    m->ammul52x(
        (int64u*)xp_mb4, (int64u*)xp_mb4, (int64u*)inp_mb4, (int64u*)p_mb4, k0_mb4[0]); /* mmul */
    m->modsub52x(xp_mb4,
                 (const int64u(*)[4])xp_mb4,
                 (const int64u(*)[4])p_mb4,
                 (const int64u(*)[4])p_mb4); /* correction */

    /* xp = (xp*q + xq) */
    zero_mb4(inp_mb4, len52 * 2);
    copy_mb4(inp_mb4, (const int64u(*)[4])xq_mb4, len52);
    m->mla52x(inp_mb4, (const int64u(*)[4])xp_mb4, (const int64u(*)[4])q_mb4);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inp_mb4, rsaBitlen);

    /* clear exponents, p, q */
    zero_mb4(d_mb4, len64);
    zero_mb4(q_mb4, len52);
    zero_mb4(p_mb4, len52);
}

#endif /* #if (_MBX >= _MBX_K1) */
