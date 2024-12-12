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

#include <internal/sm4/sm4_mb.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

mbx_status16 sm4_ofb_kernel_mb16(int8u* pa_out[SM4_LINES],
                                 const int8u* pa_inp[SM4_LINES],
                                 const int len[SM4_LINES],
                                 const int32u* key_sched[SM4_ROUNDS],
                                 __mmask16 mb_mask,
                                 int8u* pa_iv[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];

    /* Get the copy of input data lengths in bytes */
    __m512i loc_len = _mm512_loadu_si512(len);
    int* p_loc_len  = (int*)&loc_len;

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Set p_rk pointer to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    /* Check if we have any data */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);

    __m512i iv0, iv1, iv2, iv3;

    /* Load and transpose iv */
    TRANSPOSE_16x4_I32_EPI32(&iv0, &iv1, &iv2, &iv3, (const int8u**)pa_iv, tmp_mask);

    /* Main loop */
    __m512i tmp;
    while (tmp_mask) {
        for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
            SM4_FOUR_ROUNDS(iv0, iv1, iv2, iv3, tmp, p_rk, 1);

        p_rk -= SM4_ROUNDS;

        /* Change the order of blocks (Y0, Y1, Y2, Y3) = R(X32, X33, X34, X35) = (X35, X34, X33, X32) */
        tmp = iv0;
        iv0 = iv3;
        iv3 = tmp;
        tmp = iv1;
        iv1 = iv2;
        iv2 = tmp;

        /* Transpose and store encrypted blocks by bytes */
        TRANSPOSE_AND_XOR_4x16_I32_EPI8(iv0, iv1, iv2, iv3, loc_out, loc_inp, p_loc_len, tmp_mask);

        /* Update pointers to data */
        M512(loc_inp) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE));
        M512(loc_inp + 8) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

        M512(loc_out) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(SM4_BLOCK_SIZE));
        M512(loc_out + 8) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

        /* Update number of blocks left and processing mask */
        loc_len = _mm512_sub_epi32(loc_len, _mm512_set1_epi32(SM4_BLOCK_SIZE));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }

    /* Update ofb values */
    TRANSPOSE_4x16_I32_EPI32(&iv0, &iv1, &iv2, &iv3, pa_iv, tmp_mask);

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8]) & iv0, 1);
    zero_mb8((int64u(*)[8]) & iv1, 1);
    zero_mb8((int64u(*)[8]) & iv2, 1);
    zero_mb8((int64u(*)[8]) & iv3, 1);
    zero_mb8((int64u(*)[8]) & tmp, 1);

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
