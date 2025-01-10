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

#include <internal/sm3/sm3_mb8.h>

#if (_MBX >= _MBX_K1)

/* Boolean functions (0<=nr<16) */
#define FF1(X, Y, Z) (_mm256_xor_si256(_mm256_xor_si256(X, Y), Z))
#define GG1(X, Y, Z) (_mm256_xor_si256(_mm256_xor_si256(X, Y), Z))
/* Boolean functions (16<=nr<64)  */
#define FF2(X, Y, Z)                                                                  \
    (_mm256_or_si256(_mm256_or_si256(_mm256_and_si256(X, Y), _mm256_and_si256(X, Z)), \
                     _mm256_and_si256(Y, Z)))
#define GG2(X, Y, Z) (_mm256_or_si256(_mm256_and_si256(X, Y), _mm256_andnot_si256(X, Z)))

/* P0 permutation: */
#define P0(X) \
    (_mm256_xor_si256(_mm256_xor_si256(X, _mm256_rol_epi32(X, 9)), _mm256_rol_epi32(X, 17)))
/* P1 permutation: */
#define P1(X) \
    (_mm256_xor_si256(_mm256_xor_si256(X, _mm256_rol_epi32(X, 15)), _mm256_rol_epi32(X, 23)))

/* Update W */
#define WUPDATE(nr, W)                                                                     \
    (_mm256_xor_si256(                                                                     \
        _mm256_xor_si256(                                                                  \
            P1(_mm256_xor_si256(_mm256_xor_si256((W)[((nr)-16) & 15], (W)[((nr)-9) & 15]), \
                                _mm256_rol_epi32((W)[((nr)-3) & 15], 15))),                \
            _mm256_rol_epi32((W)[((nr)-13) & 15], 7)),                                     \
        (W)[((nr)-6) & 15]))

// SM3 steps
/* (0<=nr<16) */
#define STEP1_SM3(nr, A, B, C, D, E, F, G, H, Tj, W)                                                \
    {                                                                                               \
        __m256i SS1 =                                                                               \
            _mm256_rol_epi32(_mm256_add_epi32(_mm256_add_epi32(_mm256_rol_epi32(A, 12), E),         \
                                              _mm256_set1_epi32((int)(Tj))),                        \
                             7);                                                                    \
        __m256i SS2    = _mm256_xor_si256(SS1, _mm256_rol_epi32(A, 12));                            \
        __m256i TT1    = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF1(A, B, C), D), SS2), \
                                       _mm256_xor_si256((W)[(nr) & 15], (W)[((nr) + 4) & 15]));  \
        __m256i TT2    = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG1(E, F, G), H), SS1), \
                                       (W)[(nr) & 15]);                                          \
        (D)            = _mm256_loadu_si256((void*)&(C));                                           \
        (C)            = _mm256_rol_epi32((B), 9);                                                  \
        (B)            = _mm256_loadu_si256((void*)&(A));                                           \
        (A)            = _mm256_loadu_si256((void*)&TT1);                                           \
        (H)            = _mm256_loadu_si256((void*)&(G));                                           \
        (G)            = _mm256_rol_epi32(F, 19);                                                   \
        (F)            = _mm256_loadu_si256((void*)&(E));                                           \
        (E)            = P0(TT2);                                                                   \
        (W)[(nr) & 15] = WUPDATE(nr, (W));                                                          \
    }

/* (16<=nr<64)  */
#define STEP2_SM3(nr, A, B, C, D, E, F, G, H, Tj, W)                                                \
    {                                                                                               \
        __m256i SS1 =                                                                               \
            _mm256_rol_epi32(_mm256_add_epi32(_mm256_add_epi32(_mm256_rol_epi32(A, 12), E),         \
                                              _mm256_set1_epi32((int)(Tj))),                        \
                             7);                                                                    \
        __m256i SS2    = _mm256_xor_si256(SS1, _mm256_rol_epi32(A, 12));                            \
        __m256i TT1    = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF2(A, B, C), D), SS2), \
                                       _mm256_xor_si256((W)[(nr) & 15], (W)[((nr) + 4) & 15]));  \
        __m256i TT2    = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG2(E, F, G), H), SS1), \
                                       (W)[(nr) & 15]);                                          \
        (D)            = _mm256_loadu_si256((void*)&(C));                                           \
        (C)            = _mm256_rol_epi32((B), 9);                                                  \
        (B)            = _mm256_loadu_si256((void*)&(A));                                           \
        (A)            = _mm256_loadu_si256((void*)&TT1);                                           \
        (H)            = _mm256_loadu_si256((void*)&(G));                                           \
        (G)            = _mm256_rol_epi32((F), 19);                                                 \
        (F)            = _mm256_loadu_si256((void*)&(E));                                           \
        (E)            = P0(TT2);                                                                   \
        (W)[(nr) & 15] = WUPDATE(nr, (W));                                                          \
    }


void sm3_avx512_mb8(int32u hash_pa[][8], const int8u* const msg_pa[8], int len[8])
{
    int i;

    __ALIGN64 int32u* loc_data[SM3_NUM_BUFFERS8];

    __m256i W[16];
    int32u* p_W[16] = { (int32u*)&W[0],  (int32u*)&W[1],  (int32u*)&W[2],  (int32u*)&W[3],
                        (int32u*)&W[4],  (int32u*)&W[5],  (int32u*)&W[6],  (int32u*)&W[7],
                        (int32u*)&W[8],  (int32u*)&W[9],  (int32u*)&W[10], (int32u*)&W[11],
                        (int32u*)&W[12], (int32u*)&W[13], (int32u*)&W[14], (int32u*)&W[15] };

    __m256i Vi[8];
    __m256i A, B, C, D, E, F, G, H;

    /* Allocate memory to handle numBuffers < 16, set data in not valid buffers to zero */
    __m512i zero_buffer = _mm512_setzero_si512();

    /* Load processing mask */
    __mmask8 mb_mask = _mm256_cmp_epi32_mask(
        _mm256_loadu_si256((__m256i*)len), _mm256_setzero_si256(), _MM_CMPINT_NE);

    /* Load data and set the data to zero in not valid buffers */
    __m256i loc_len_m256 = _mm256_loadu_si256((__m256i*)len);
    /* We need the address of the zero_buffer to form the fully valid array of pointers loc_src */
    _mm512_storeu_si512(
        loc_data,
        _mm512_mask_loadu_epi64(_mm512_set1_epi64((long long)&zero_buffer), mb_mask, msg_pa));

    /* Load hash value */
    A = _mm256_loadu_si256((__m256i*)hash_pa);
    B = _mm256_loadu_si256((__m256i*)(hash_pa + 1));
    C = _mm256_loadu_si256((__m256i*)(hash_pa + 2));
    D = _mm256_loadu_si256((__m256i*)(hash_pa + 3));
    E = _mm256_loadu_si256((__m256i*)(hash_pa + 4));
    F = _mm256_loadu_si256((__m256i*)(hash_pa + 5));
    G = _mm256_loadu_si256((__m256i*)(hash_pa + 6));
    H = _mm256_loadu_si256((__m256i*)(hash_pa + 7));

    /* Loop over the message */
    while (mb_mask) {
        /* Transpose the message data */
        TRANSPOSE_8X16_I32(p_W, (const int32u**)loc_data, 0xFFFF);

        /* Init W (remember about endian) */
        for (i = 0; i < 16; i++) {
            W[i] = SIMD_ENDIANNESS32(W[i]);
        }

        /* Store previous hash for xor operation V(i+1) = ABCDEFGH XOR V(i) */
        Vi[0] = _mm256_loadu_si256((void*)&A);
        Vi[1] = _mm256_loadu_si256((void*)&B);
        Vi[2] = _mm256_loadu_si256((void*)&C);
        Vi[3] = _mm256_loadu_si256((void*)&D);
        Vi[4] = _mm256_loadu_si256((void*)&E);
        Vi[5] = _mm256_loadu_si256((void*)&F);
        Vi[6] = _mm256_loadu_si256((void*)&G);
        Vi[7] = _mm256_loadu_si256((void*)&H);

        /* Compression function */
        {
            STEP1_SM3(0, A, B, C, D, E, F, G, H, tj_calculated[0], W);
            STEP1_SM3(1, A, B, C, D, E, F, G, H, tj_calculated[1], W);
            STEP1_SM3(2, A, B, C, D, E, F, G, H, tj_calculated[2], W);
            STEP1_SM3(3, A, B, C, D, E, F, G, H, tj_calculated[3], W);
            STEP1_SM3(4, A, B, C, D, E, F, G, H, tj_calculated[4], W);
            STEP1_SM3(5, A, B, C, D, E, F, G, H, tj_calculated[5], W);
            STEP1_SM3(6, A, B, C, D, E, F, G, H, tj_calculated[6], W);
            STEP1_SM3(7, A, B, C, D, E, F, G, H, tj_calculated[7], W);

            STEP1_SM3(8, A, B, C, D, E, F, G, H, tj_calculated[8], W);
            STEP1_SM3(9, A, B, C, D, E, F, G, H, tj_calculated[9], W);
            STEP1_SM3(10, A, B, C, D, E, F, G, H, tj_calculated[10], W);
            STEP1_SM3(11, A, B, C, D, E, F, G, H, tj_calculated[11], W);
            STEP1_SM3(12, A, B, C, D, E, F, G, H, tj_calculated[12], W);
            STEP1_SM3(13, A, B, C, D, E, F, G, H, tj_calculated[13], W);
            STEP1_SM3(14, A, B, C, D, E, F, G, H, tj_calculated[14], W);
            STEP1_SM3(15, A, B, C, D, E, F, G, H, tj_calculated[15], W);

            STEP2_SM3(16, A, B, C, D, E, F, G, H, tj_calculated[16], W);
            STEP2_SM3(17, A, B, C, D, E, F, G, H, tj_calculated[17], W);
            STEP2_SM3(18, A, B, C, D, E, F, G, H, tj_calculated[18], W);
            STEP2_SM3(19, A, B, C, D, E, F, G, H, tj_calculated[19], W);
            STEP2_SM3(20, A, B, C, D, E, F, G, H, tj_calculated[20], W);
            STEP2_SM3(21, A, B, C, D, E, F, G, H, tj_calculated[21], W);
            STEP2_SM3(22, A, B, C, D, E, F, G, H, tj_calculated[22], W);
            STEP2_SM3(23, A, B, C, D, E, F, G, H, tj_calculated[23], W);

            STEP2_SM3(24, A, B, C, D, E, F, G, H, tj_calculated[24], W);
            STEP2_SM3(25, A, B, C, D, E, F, G, H, tj_calculated[25], W);
            STEP2_SM3(26, A, B, C, D, E, F, G, H, tj_calculated[26], W);
            STEP2_SM3(27, A, B, C, D, E, F, G, H, tj_calculated[27], W);
            STEP2_SM3(28, A, B, C, D, E, F, G, H, tj_calculated[28], W);
            STEP2_SM3(29, A, B, C, D, E, F, G, H, tj_calculated[29], W);
            STEP2_SM3(30, A, B, C, D, E, F, G, H, tj_calculated[30], W);
            STEP2_SM3(31, A, B, C, D, E, F, G, H, tj_calculated[31], W);

            STEP2_SM3(32, A, B, C, D, E, F, G, H, tj_calculated[32], W);
            STEP2_SM3(33, A, B, C, D, E, F, G, H, tj_calculated[33], W);
            STEP2_SM3(34, A, B, C, D, E, F, G, H, tj_calculated[34], W);
            STEP2_SM3(35, A, B, C, D, E, F, G, H, tj_calculated[35], W);
            STEP2_SM3(36, A, B, C, D, E, F, G, H, tj_calculated[36], W);
            STEP2_SM3(37, A, B, C, D, E, F, G, H, tj_calculated[37], W);
            STEP2_SM3(38, A, B, C, D, E, F, G, H, tj_calculated[38], W);
            STEP2_SM3(39, A, B, C, D, E, F, G, H, tj_calculated[39], W);

            STEP2_SM3(40, A, B, C, D, E, F, G, H, tj_calculated[40], W);
            STEP2_SM3(41, A, B, C, D, E, F, G, H, tj_calculated[41], W);
            STEP2_SM3(42, A, B, C, D, E, F, G, H, tj_calculated[42], W);
            STEP2_SM3(43, A, B, C, D, E, F, G, H, tj_calculated[43], W);
            STEP2_SM3(44, A, B, C, D, E, F, G, H, tj_calculated[44], W);
            STEP2_SM3(45, A, B, C, D, E, F, G, H, tj_calculated[45], W);
            STEP2_SM3(46, A, B, C, D, E, F, G, H, tj_calculated[46], W);
            STEP2_SM3(47, A, B, C, D, E, F, G, H, tj_calculated[47], W);

            STEP2_SM3(48, A, B, C, D, E, F, G, H, tj_calculated[16], W);
            STEP2_SM3(49, A, B, C, D, E, F, G, H, tj_calculated[17], W);
            STEP2_SM3(50, A, B, C, D, E, F, G, H, tj_calculated[18], W);
            STEP2_SM3(51, A, B, C, D, E, F, G, H, tj_calculated[19], W);
            STEP2_SM3(52, A, B, C, D, E, F, G, H, tj_calculated[20], W);
            STEP2_SM3(53, A, B, C, D, E, F, G, H, tj_calculated[21], W);
            STEP2_SM3(54, A, B, C, D, E, F, G, H, tj_calculated[22], W);
            STEP2_SM3(55, A, B, C, D, E, F, G, H, tj_calculated[23], W);

            STEP2_SM3(56, A, B, C, D, E, F, G, H, tj_calculated[24], W);
            STEP2_SM3(57, A, B, C, D, E, F, G, H, tj_calculated[25], W);
            STEP2_SM3(58, A, B, C, D, E, F, G, H, tj_calculated[26], W);
            STEP2_SM3(59, A, B, C, D, E, F, G, H, tj_calculated[27], W);
            STEP2_SM3(60, A, B, C, D, E, F, G, H, tj_calculated[28], W);
            STEP2_SM3(61, A, B, C, D, E, F, G, H, tj_calculated[29], W);
            STEP2_SM3(62, A, B, C, D, E, F, G, H, tj_calculated[30], W);
            STEP2_SM3(63, A, B, C, D, E, F, G, H, tj_calculated[31], W);
        }

        A = _mm256_mask_xor_epi32(Vi[0], mb_mask, A, Vi[0]);
        B = _mm256_mask_xor_epi32(Vi[1], mb_mask, B, Vi[1]);
        C = _mm256_mask_xor_epi32(Vi[2], mb_mask, C, Vi[2]);
        D = _mm256_mask_xor_epi32(Vi[3], mb_mask, D, Vi[3]);
        E = _mm256_mask_xor_epi32(Vi[4], mb_mask, E, Vi[4]);
        F = _mm256_mask_xor_epi32(Vi[5], mb_mask, F, Vi[5]);
        G = _mm256_mask_xor_epi32(Vi[6], mb_mask, G, Vi[6]);
        H = _mm256_mask_xor_epi32(Vi[7], mb_mask, H, Vi[7]);

        _mm256_storeu_si256((__m256i*)hash_pa, A);
        _mm256_storeu_si256((__m256i*)(hash_pa + 1), B);
        _mm256_storeu_si256((__m256i*)(hash_pa + 2), C);
        _mm256_storeu_si256((__m256i*)(hash_pa + 3), D);
        _mm256_storeu_si256((__m256i*)(hash_pa + 4), E);
        _mm256_storeu_si256((__m256i*)(hash_pa + 5), F);
        _mm256_storeu_si256((__m256i*)(hash_pa + 6), G);
        _mm256_storeu_si256((__m256i*)(hash_pa + 7), H);

        /* Update pointers to data, local  lengths and mask */
        _mm512_storeu_si512(loc_data,
                            _mm512_mask_add_epi64(zero_buffer,
                                                  (__mmask8)mb_mask,
                                                  _mm512_loadu_si512(loc_data),
                                                  _mm512_set1_epi64(SM3_MSG_BLOCK_SIZE)));
        loc_len_m256 = _mm256_mask_sub_epi32(
            _mm256_setzero_si256(), mb_mask, loc_len_m256, _mm256_set1_epi32(SM3_MSG_BLOCK_SIZE));
        mb_mask = _mm256_cmp_epi32_mask(loc_len_m256, _mm256_setzero_si256(), _MM_CMPINT_NE);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
