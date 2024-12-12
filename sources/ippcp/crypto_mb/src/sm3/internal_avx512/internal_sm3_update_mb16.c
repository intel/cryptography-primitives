/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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

#include <crypto_mb/status.h>
#include <crypto_mb/sm3.h>

#include <internal/sm3/sm3_mb16.h>
#include <internal/common/ifma_defs.h>

#if (_MBX >= _MBX_K1)

mbx_status16 internal_avx512_sm3_update_mb16(const int8u* const msg_pa[16],
                                             int len[16],
                                             SM3_CTX_mb16* p_state)
{
    mbx_status16 status = 0;
    int i;

    __m512i loc_len = _mm512_loadu_si512(len);
    int* p_loc_len  = (int*)&loc_len;

    /* generate mask based on array with messages lengths */
    __m512i zero_buffer = _mm512_setzero_si512();
    __mmask16 mb_mask16 = _mm512_cmp_epi32_mask(loc_len, zero_buffer, _MM_CMPINT_NE);

    /* generate mask based on array with pointers to messages */
    __mmask8 mb_mask8[2];
    mb_mask8[0] = _mm512_cmp_epi64_mask(_mm512_loadu_si512(msg_pa), zero_buffer, _MM_CMPINT_NE);
    mb_mask8[1] = _mm512_cmp_epi64_mask(_mm512_loadu_si512(msg_pa + 8), zero_buffer, _MM_CMPINT_NE);

    /* don't process the data from i buffer if in msg_pa[i] == 0 or len[i] == 0 */
    mb_mask16 &= *(__mmask16*)mb_mask8;
    mb_mask8[0] = (__mmask8)mb_mask16;
    mb_mask8[1] = *((__mmask8*)&mb_mask16 + 1);

    /* handle non empty request */
    if (mb_mask16) {
        __ALIGN64 const int8u* loc_src[SM3_NUM_BUFFERS];
        /* We need the address of the zero_buffer to form the fully valid array of pointers loc_src */
        _mm512_storeu_si512((void*)loc_src,
                            _mm512_mask_loadu_epi64(
                                _mm512_set1_epi64((long long)&zero_buffer), mb_mask8[0], msg_pa));
        _mm512_storeu_si512((void*)(loc_src + 8),
                            _mm512_mask_loadu_epi64(_mm512_set1_epi64((long long)&zero_buffer),
                                                    mb_mask8[1],
                                                    msg_pa + 8));

        __m512i proc_len;
        __m512i idx = _mm512_loadu_si512(HASH_BUFFIDX(p_state));

        int* p_proc_len = (int*)&proc_len;
        int* p_idx      = (int*)&idx;

        __ALIGN64
        int64u sum_msg_len[SM3_NUM_BUFFERS] = { (int64u)p_loc_len[0],  (int64u)p_loc_len[1],
                                                (int64u)p_loc_len[2],  (int64u)p_loc_len[3],
                                                (int64u)p_loc_len[4],  (int64u)p_loc_len[5],
                                                (int64u)p_loc_len[6],  (int64u)p_loc_len[7],
                                                (int64u)p_loc_len[8],  (int64u)p_loc_len[9],
                                                (int64u)p_loc_len[10], (int64u)p_loc_len[11],
                                                (int64u)p_loc_len[12], (int64u)p_loc_len[13],
                                                (int64u)p_loc_len[14], (int64u)p_loc_len[15] };

        __ALIGN64
        int8u* p_buffer[SM3_NUM_BUFFERS] = { HASH_BUFF(p_state)[0],  HASH_BUFF(p_state)[1],
                                             HASH_BUFF(p_state)[2],  HASH_BUFF(p_state)[3],
                                             HASH_BUFF(p_state)[4],  HASH_BUFF(p_state)[5],
                                             HASH_BUFF(p_state)[6],  HASH_BUFF(p_state)[7],
                                             HASH_BUFF(p_state)[8],  HASH_BUFF(p_state)[9],
                                             HASH_BUFF(p_state)[10], HASH_BUFF(p_state)[11],
                                             HASH_BUFF(p_state)[12], HASH_BUFF(p_state)[13],
                                             HASH_BUFF(p_state)[14], HASH_BUFF(p_state)[15] };

        __mmask16 processed_mask = _mm512_cmp_epi32_mask(idx, zero_buffer, _MM_CMPINT_NE);

        __m512i sum_msg_len_m512_low  = _mm512_loadu_si512(sum_msg_len);
        __m512i sum_msg_len_m512_high = _mm512_loadu_si512(sum_msg_len + 8);
        sum_msg_len_m512_low          = _mm512_mask_add_epi64(sum_msg_len_m512_low,
                                                     mb_mask8[0],
                                                     _mm512_loadu_si512(MSG_LEN(p_state)),
                                                     sum_msg_len_m512_low);
        sum_msg_len_m512_high         = _mm512_mask_add_epi64(sum_msg_len_m512_high,
                                                      mb_mask8[1],
                                                      _mm512_loadu_si512(MSG_LEN(p_state) + 8),
                                                      sum_msg_len_m512_high);

        _mm512_storeu_si512(sum_msg_len, sum_msg_len_m512_low);
        _mm512_storeu_si512(sum_msg_len + 8, sum_msg_len_m512_high);

        __m512i loc_src_m512_low  = _mm512_loadu_si512(loc_src);
        __m512i loc_src_m512_high = _mm512_loadu_si512(loc_src + 8);

        /* if non empty internal buffer filling */
        if (processed_mask) {
            /* calculate how many bytes need to be added in the internal buffer */
            __m512i empty_bytes_buffer =
                _mm512_sub_epi32(_mm512_set1_epi32(SM3_MSG_BLOCK_SIZE), idx);
            processed_mask = _mm512_cmp_epi32_mask(
                _mm512_sub_epi32(loc_len, empty_bytes_buffer), zero_buffer, _MM_CMPINT_LT);
            proc_len = _mm512_mask_loadu_epi32(empty_bytes_buffer, processed_mask, p_loc_len);

            /* copy from valid input streams to the internal buffers as much as possible */
            for (i = 0; i < SM3_NUM_BUFFERS; i++) {
                if ((mb_mask16 >> i) & 0x1) {
                    __mmask64 mb_mask64 =
                        0xFFFFFFFFFFFFFFFF >> (SM3_MSG_BLOCK_SIZE - p_proc_len[i]);
                    _mm512_storeu_si512(
                        p_buffer[i] + p_idx[i],
                        _mm512_mask_loadu_epi8(
                            _mm512_loadu_si512(p_buffer[i] + p_idx[i]), mb_mask64, loc_src[i]));
                }
            }

            idx     = _mm512_add_epi32(idx, proc_len);
            loc_len = _mm512_sub_epi32(loc_len, proc_len);

            loc_src_m512_low = _mm512_add_epi64(
                loc_src_m512_low, _mm512_cvtepu32_epi64(_mm512_castsi512_si256(proc_len)));
            loc_src_m512_high = _mm512_add_epi64(
                loc_src_m512_high, _mm512_cvtepu32_epi64(_mm512_extracti32x8_epi32(proc_len, 1)));

            _mm512_storeu_si512((void*)loc_src, loc_src_m512_low);
            _mm512_storeu_si512((void*)(loc_src + 8), loc_src_m512_high);

            processed_mask =
                _mm512_cmp_epi32_mask(idx, _mm512_set1_epi32(SM3_MSG_BLOCK_SIZE), _MM_CMPINT_EQ);
            proc_len = _mm512_maskz_set1_epi32(processed_mask, SM3_MSG_BLOCK_SIZE);

            /* update digest if at least one buffer is full */
            if (processed_mask) {
                sm3_avx512_mb16(HASH_VALUE(p_state), (const int8u**)p_buffer, p_proc_len);
                idx = _mm512_mask_set1_epi32(
                    idx, ~_mm512_cmp_epi32_mask(proc_len, zero_buffer, _MM_CMPINT_LE), 0);
            }
        }

        /* main message part processing */
        proc_len       = _mm512_and_epi32(loc_len, _mm512_set1_epi32(-SM3_MSG_BLOCK_SIZE));
        processed_mask = _mm512_cmp_epi32_mask(proc_len, zero_buffer, _MM_CMPINT_NLT);

        if (processed_mask)
            sm3_avx512_mb16(HASH_VALUE(p_state), loc_src, p_proc_len);

        loc_len = _mm512_sub_epi32(loc_len, proc_len);

        loc_src_m512_low = _mm512_add_epi64(
            loc_src_m512_low, _mm512_cvtepu32_epi64(_mm512_castsi512_si256(proc_len)));
        loc_src_m512_high = _mm512_add_epi64(
            loc_src_m512_high, _mm512_cvtepu32_epi64(_mm512_extracti32x8_epi32(proc_len, 1)));

        _mm512_storeu_si512((void*)loc_src, loc_src_m512_low);
        _mm512_storeu_si512((void*)(loc_src + 8), loc_src_m512_high);

        processed_mask = _mm512_cmp_epi32_mask(loc_len, zero_buffer, _MM_CMPINT_NLE);

        /* store rest of message into the internal buffer */
        for (i = 0; i < SM3_NUM_BUFFERS; i++) {
            if ((processed_mask >> i) & 0x1) {
                __mmask64 mb_mask64 = ~(0xFFFFFFFFFFFFFFFF << *(p_loc_len + i));
                _mm512_storeu_si512(p_buffer[i], _mm512_maskz_loadu_epi8(mb_mask64, loc_src[i]));
            }
        }

        idx = _mm512_add_epi32(idx, loc_len);

        /* Update length of processed message */
        _mm512_storeu_si512(MSG_LEN(p_state),
                            _mm512_mask_loadu_epi64(
                                _mm512_loadu_si512(MSG_LEN(p_state)), mb_mask8[0], sum_msg_len));
        _mm512_storeu_si512(MSG_LEN(p_state) + 8,
                            _mm512_mask_loadu_epi64(_mm512_loadu_si512(MSG_LEN(p_state) + 8),
                                                    mb_mask8[1],
                                                    sum_msg_len + 8));
        _mm512_storeu_si512(
            HASH_BUFFIDX(p_state),
            _mm512_mask_loadu_epi32(_mm512_loadu_si512(HASH_BUFFIDX(p_state)), mb_mask16, p_idx));
    }
    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
