/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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
#include <internal/sm4/sm4_gcm_mb.h>

#if (_MBX >= _MBX_K1)

/*
// This function performs GHASH multiplication:
// Multiplication operation for the binary Galois (finite) field of 2^128 elements.
//
// Details about this operation can be found in NIST SP 800-38D
//
// This code is a port of GCM part of Intel(R) IPSec AES-GCM code
// Code modified to work with multi-buffer approach
*/

void sm4_gcm_ghash_mul_single_block_mb16(__m512i* data_blocks[], __m512i* hashkeys[])
{
    __m512i T1_0, T2_0, T3_0;
    __m512i T1_1, T2_1, T3_1;
    __m512i T1_2, T2_2, T3_2;
    __m512i T1_3, T2_3, T3_3;

    T1_0 = clmul(*(hashkeys[0]), *(data_blocks[0]), 0x11); // T1 = a1*b1
    T1_1 = clmul(*(hashkeys[1]), *(data_blocks[1]), 0x11);
    T1_2 = clmul(*(hashkeys[2]), *(data_blocks[2]), 0x11);
    T1_3 = clmul(*(hashkeys[3]), *(data_blocks[3]), 0x11);

    T2_0 = clmul(*(hashkeys[0]), *(data_blocks[0]), 0x00); // T1 = a0*b0
    T2_1 = clmul(*(hashkeys[1]), *(data_blocks[1]), 0x00);
    T2_2 = clmul(*(hashkeys[2]), *(data_blocks[2]), 0x00);
    T2_3 = clmul(*(hashkeys[3]), *(data_blocks[3]), 0x00);

    T3_0 = clmul(*(hashkeys[0]), *(data_blocks[0]), 0x01); // T3 = a1*b0
    T3_1 = clmul(*(hashkeys[1]), *(data_blocks[1]), 0x01);
    T3_2 = clmul(*(hashkeys[2]), *(data_blocks[2]), 0x01);
    T3_3 = clmul(*(hashkeys[3]), *(data_blocks[3]), 0x01);

    *(data_blocks[0]) = clmul(*(hashkeys[0]), *(data_blocks[0]), 0x10); // T3 = a0*b1
    *(data_blocks[1]) = clmul(*(hashkeys[1]), *(data_blocks[1]), 0x10);
    *(data_blocks[2]) = clmul(*(hashkeys[2]), *(data_blocks[2]), 0x10);
    *(data_blocks[3]) = clmul(*(hashkeys[3]), *(data_blocks[3]), 0x10);

    *(data_blocks[0]) = xor(*(data_blocks[0]), T3_0);
    *(data_blocks[1]) = xor(*(data_blocks[1]), T3_1);
    *(data_blocks[2]) = xor(*(data_blocks[2]), T3_2);
    *(data_blocks[3]) = xor(*(data_blocks[3]), T3_3);

    T3_0 = bsrli_epi128(*(data_blocks[0]), 8);
    T3_1 = bsrli_epi128(*(data_blocks[1]), 8);
    T3_2 = bsrli_epi128(*(data_blocks[2]), 8);
    T3_3 = bsrli_epi128(*(data_blocks[3]), 8);

    *(data_blocks[0]) = bslli_epi128(*(data_blocks[0]), 8);
    *(data_blocks[1]) = bslli_epi128(*(data_blocks[1]), 8);
    *(data_blocks[2]) = bslli_epi128(*(data_blocks[2]), 8);
    *(data_blocks[3]) = bslli_epi128(*(data_blocks[3]), 8);

    T1_0 = xor(T1_0, T3_0);
    T1_1 = xor(T1_1, T3_1);
    T1_2 = xor(T1_2, T3_2);
    T1_3 = xor(T1_3, T3_3);

    *(data_blocks[0]) = xor(*(data_blocks[0]), T2_0);
    *(data_blocks[1]) = xor(*(data_blocks[1]), T2_1);
    *(data_blocks[2]) = xor(*(data_blocks[2]), T2_2);
    *(data_blocks[3]) = xor(*(data_blocks[3]), T2_3);

    /* first phase of the reduction */

    T2_0 = clmul(M512(gcm_poly2), *(data_blocks[0]), 0x01);
    T2_1 = clmul(M512(gcm_poly2), *(data_blocks[1]), 0x01);
    T2_2 = clmul(M512(gcm_poly2), *(data_blocks[2]), 0x01);
    T2_3 = clmul(M512(gcm_poly2), *(data_blocks[3]), 0x01);

    T2_0 = bslli_epi128(T2_0, 8);
    T2_1 = bslli_epi128(T2_1, 8);
    T2_2 = bslli_epi128(T2_2, 8);
    T2_3 = bslli_epi128(T2_3, 8);

    *(data_blocks[0]) = xor(*(data_blocks[0]), T2_0);
    *(data_blocks[1]) = xor(*(data_blocks[1]), T2_1);
    *(data_blocks[2]) = xor(*(data_blocks[2]), T2_2);
    *(data_blocks[3]) = xor(*(data_blocks[3]), T2_3);

    /* second phase of the reduction */

    T2_0 = clmul(M512(gcm_poly2), *(data_blocks[0]), 0x00);
    T2_1 = clmul(M512(gcm_poly2), *(data_blocks[1]), 0x00);
    T2_2 = clmul(M512(gcm_poly2), *(data_blocks[2]), 0x00);
    T2_3 = clmul(M512(gcm_poly2), *(data_blocks[3]), 0x00);

    T2_0 = bsrli_epi128(T2_0, 4);
    T2_1 = bsrli_epi128(T2_1, 4);
    T2_2 = bsrli_epi128(T2_2, 4);
    T2_3 = bsrli_epi128(T2_3, 4);

    *(data_blocks[0]) = clmul(M512(gcm_poly2), *(data_blocks[0]), 0x10);
    *(data_blocks[1]) = clmul(M512(gcm_poly2), *(data_blocks[1]), 0x10);
    *(data_blocks[2]) = clmul(M512(gcm_poly2), *(data_blocks[2]), 0x10);
    *(data_blocks[3]) = clmul(M512(gcm_poly2), *(data_blocks[3]), 0x10);

    *(data_blocks[0]) = bslli_epi128(*(data_blocks[0]), 4);
    *(data_blocks[1]) = bslli_epi128(*(data_blocks[1]), 4);
    *(data_blocks[2]) = bslli_epi128(*(data_blocks[2]), 4);
    *(data_blocks[3]) = bslli_epi128(*(data_blocks[3]), 4);

    *(data_blocks[0]) = xor(*(data_blocks[0]), T2_0);
    *(data_blocks[1]) = xor(*(data_blocks[1]), T2_1);
    *(data_blocks[2]) = xor(*(data_blocks[2]), T2_2);
    *(data_blocks[3]) = xor(*(data_blocks[3]), T2_3);

    *(data_blocks[0]) = xor(*(data_blocks[0]), T1_0);
    *(data_blocks[1]) = xor(*(data_blocks[1]), T1_1);
    *(data_blocks[2]) = xor(*(data_blocks[2]), T1_2);
    *(data_blocks[3]) = xor(*(data_blocks[3]), T1_3);
}

#endif /* #if (_MBX>=_MBX_K1) */
