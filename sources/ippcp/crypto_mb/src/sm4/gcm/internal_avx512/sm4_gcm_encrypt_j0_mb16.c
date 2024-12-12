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

#include <internal/sm4/sm4_gcm_mb.h>

#if (_MBX >= _MBX_K1)

/*
// This function encrypts J0 to use it for tag computation
// Encrypted J0 value XOR'ed with accumulated GHASH value in function sm4_gcm_get_tag_mb16
*/

void sm4_encrypt_j0_mb16(SM4_GCM_CTX_mb16* p_context)
{
    const mbx_sm4_key_schedule* key_sched =
        (const mbx_sm4_key_schedule*)SM4_GCM_CONTEXT_KEY(context);

    __m512i j0_blocks[4];
    __m128i* j0        = SM4_GCM_CONTEXT_J0(p_context);
    int tagRearrange[] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };

    const int8u* pa_inp[SM4_LINES];

    for (int i = 0; i < SM4_LINES; i++) {
        pa_inp[i] = (unsigned char*)(j0 + tagRearrange[i]);
    }

    TRANSPOSE_16x4_I32_EPI32(
        &j0_blocks[0], &j0_blocks[1], &j0_blocks[2], &j0_blocks[3], pa_inp, 0xFFFF);

    const __m512i* p_rk = (const __m512i*)key_sched;

    __m512i tmp;
    for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4) {
        SM4_FOUR_ROUNDS(j0_blocks[0], j0_blocks[1], j0_blocks[2], j0_blocks[3], tmp, p_rk, 1);
    }

    tmp          = j0_blocks[0];
    j0_blocks[0] = j0_blocks[3];
    j0_blocks[3] = tmp;
    tmp          = j0_blocks[1];
    j0_blocks[1] = j0_blocks[2];
    j0_blocks[2] = tmp;

    __m512i T1_0 = unpacklo_epi32(j0_blocks[0], j0_blocks[1]);
    __m512i T1_1 = unpackhi_epi32(j0_blocks[0], j0_blocks[1]);
    __m512i T1_2 = unpacklo_epi32(j0_blocks[2], j0_blocks[3]);
    __m512i T1_3 = unpackhi_epi32(j0_blocks[2], j0_blocks[3]);

    j0_blocks[0] = unpacklo_epi64(T1_0, T1_2);
    j0_blocks[1] = unpackhi_epi64(T1_0, T1_2);
    j0_blocks[2] = unpacklo_epi64(T1_1, T1_3);
    j0_blocks[3] = unpackhi_epi64(T1_1, T1_3);

    j0_blocks[0] = shuffle_epi8(j0_blocks[0], M512(swapBytes));
    j0_blocks[1] = shuffle_epi8(j0_blocks[1], M512(swapBytes));
    j0_blocks[2] = shuffle_epi8(j0_blocks[2], M512(swapBytes));
    j0_blocks[3] = shuffle_epi8(j0_blocks[3], M512(swapBytes));

    storeu(j0 + 0, j0_blocks[0]);
    storeu(j0 + 4, j0_blocks[1]);
    storeu(j0 + 8, j0_blocks[2]);
    storeu(j0 + 12, j0_blocks[3]);
}

#endif /* #if (_MBX>=_MBX_K1) */
