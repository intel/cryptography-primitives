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

#include <crypto_mb/status.h>
#include <crypto_mb/sm3.h>

#include <internal/sm3/sm3_mb8.h>
#include <internal/common/ifma_defs.h>

#if (_MBX >= _MBX_K1)

// Disable optimization for VS17
#if defined(_MSC_VER) && (_MSC_VER < 1920) && !defined(__INTEL_COMPILER)
#pragma optimize("", off)
#endif

mbx_status sm3_update_mb8(const int8u* const msg_pa[8], int len[8], SM3_CTX_mb8* p_state)
{
    int i;
    mbx_status status = 0;

    /* test input pointers */
    if (NULL == msg_pa || NULL == len || NULL == p_state) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    __ALIGN64 const int8u* loc_src[SM3_NUM_BUFFERS8];

    __m256i loc_len = _mm256_loadu_si256((__m256i*)len);
    int* p_loc_len  = (int*)&loc_len;

    __m512i zero_buffer = _mm512_setzero_si512();

    /* generate mask based on array with messages lengths */
    __mmask8 mb_mask = _mm256_cmp_epi32_mask(loc_len, _mm256_setzero_si256(), _MM_CMPINT_NE);

    /* generate mask based on msg_pa[]. Don't process the data from i buffer if in msg_pa[i] == 0 or len[i] == 0 */
    mb_mask &= _mm512_cmp_epi64_mask(_mm512_loadu_si512(msg_pa), zero_buffer, _MM_CMPINT_NE);

    /* handle non empty message */
    if (mb_mask) {
        /* We need the address of the zero_buffer to form the fully valid array of pointers loc_src */
        _mm512_storeu_si512(
            (void*)loc_src,
            _mm512_mask_loadu_epi64(_mm512_set1_epi64((long long)&zero_buffer), mb_mask, msg_pa));

        __m256i proc_len;
        __m256i idx = _mm256_loadu_si256((__m256i*)HASH_BUFFIDX(p_state));

        int* p_proc_len = (int*)&proc_len;
        int* p_idx      = (int*)&idx;

        __ALIGN64
        int64u sum_msg_len[SM3_NUM_BUFFERS8] = { (int64u)p_loc_len[0], (int64u)p_loc_len[1],
                                                 (int64u)p_loc_len[2], (int64u)p_loc_len[3],
                                                 (int64u)p_loc_len[4], (int64u)p_loc_len[5],
                                                 (int64u)p_loc_len[6], (int64u)p_loc_len[7] };

        __ALIGN64
        int8u* p_buffer[SM3_NUM_BUFFERS8] = { HASH_BUFF(p_state)[0], HASH_BUFF(p_state)[1],
                                              HASH_BUFF(p_state)[2], HASH_BUFF(p_state)[3],
                                              HASH_BUFF(p_state)[4], HASH_BUFF(p_state)[5],
                                              HASH_BUFF(p_state)[6], HASH_BUFF(p_state)[7] };

        __mmask8 processed_mask = _mm256_cmp_epi32_mask(idx, _mm256_setzero_si256(), _MM_CMPINT_NE);

        __m512i sum_msg_len_m512 = _mm512_loadu_si512(sum_msg_len);
        sum_msg_len_m512         = _mm512_mask_add_epi64(
            sum_msg_len_m512, mb_mask, _mm512_loadu_si512(MSG_LEN(p_state)), sum_msg_len_m512);

        _mm512_storeu_si512(sum_msg_len, sum_msg_len_m512);

        __m512i loc_src_m512 = _mm512_loadu_si512(loc_src);

        /* if non empty internal buffer filling */
        if (processed_mask) {

            __m256i tmp    = _mm256_sub_epi32(_mm256_set1_epi32(SM3_MSG_BLOCK_SIZE), idx);
            processed_mask = _mm256_cmp_epi32_mask(
                _mm256_sub_epi32(loc_len, tmp), _mm256_setzero_si256(), _MM_CMPINT_LT);

            /* p_proc_len[i] = MIN(p_loc_len[i], (SM3_MSG_BLOCK_SIZE - p_idx[i])) */
            proc_len = _mm256_mask_loadu_epi32(tmp, processed_mask, p_loc_len);

            /* copy from input stream to the internal buffer as match as possible */
            for (i = 0; i < SM3_NUM_BUFFERS8; i++) {
                /* copy from input stream to the internal buffer as match as possible */
                __mmask64 mb_mask64 = ~(0xFFFFFFFFFFFFFFFF << p_proc_len[i]);
                _mm512_storeu_si512(
                    p_buffer[i] + p_idx[i],
                    _mm512_mask_loadu_epi8(
                        _mm512_loadu_si512(p_buffer[i] + p_idx[i]), mb_mask64, loc_src[i]));
            }

            idx     = _mm256_add_epi32(idx, proc_len);
            loc_len = _mm256_sub_epi32(loc_len, proc_len);

            loc_src_m512 = _mm512_add_epi64(loc_src_m512, _mm512_cvtepu32_epi64(proc_len));

            _mm512_storeu_si512((void*)loc_src, loc_src_m512);

            processed_mask =
                _mm256_cmp_epi32_mask(idx, _mm256_set1_epi32(SM3_MSG_BLOCK_SIZE), _MM_CMPINT_EQ);
            proc_len = _mm256_mask_set1_epi32(proc_len, processed_mask, SM3_MSG_BLOCK_SIZE);

            /* update digest if at least one buffer is full */
            if (processed_mask) {
                sm3_avx512_mb8(HASH_VALUE(p_state), (const int8u**)p_buffer, p_proc_len);
                idx = _mm256_mask_set1_epi32(
                    idx,
                    ~_mm256_cmp_epi32_mask(proc_len, _mm256_setzero_si256(), 2),
                    _MM_CMPINT_EQ);
            }
        }

        /* main message part processing */
        proc_len       = _mm256_and_si256(loc_len, _mm256_set1_epi32(-SM3_MSG_BLOCK_SIZE));
        processed_mask = _mm256_cmp_epi32_mask(proc_len, _mm256_setzero_si256(), _MM_CMPINT_NLT);

        if (processed_mask)
            sm3_avx512_mb8(HASH_VALUE(p_state), loc_src, p_proc_len);

        loc_len = _mm256_sub_epi32(loc_len, proc_len);

        loc_src_m512 = _mm512_add_epi64(loc_src_m512, _mm512_cvtepu32_epi64(proc_len));
        _mm512_storeu_si512((void*)loc_src, loc_src_m512);

        processed_mask = _mm256_cmp_epi32_mask(loc_len, _mm256_setzero_si256(), _MM_CMPINT_NLE);

        /* store rest of message into the internal buffer */
        if (processed_mask) {
            for (i = 0; i < SM3_NUM_BUFFERS8; i++) {
                /* copy from input stream to the internal buffer as match as possible */
                __mmask64 mb_mask64 = ~(0xFFFFFFFFFFFFFFFF << *(p_loc_len + i));
                _mm512_storeu_si512(p_buffer[i], _mm512_maskz_loadu_epi8(mb_mask64, loc_src[i]));
            }

            idx = _mm256_maskz_add_epi32(0xFF, idx, loc_len);
        }

        /* Update length of processed message */
        _mm512_storeu_si512(
            MSG_LEN(p_state),
            _mm512_mask_loadu_epi64(_mm512_loadu_si512(MSG_LEN(p_state)), mb_mask, sum_msg_len));
        _mm512_storeu_si512(
            HASH_BUFFIDX(p_state),
            _mm512_mask_loadu_epi32(_mm512_loadu_si512(HASH_BUFFIDX(p_state)), mb_mask, p_idx));
    }

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
