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

mbx_status16 internal_avx512_sm3_mask_init_mb16(SM3_CTX_mb16* p_state, __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    __mmask8 mb_mask8[2];
    mb_mask8[0] = (__mmask8)mb_mask;
    mb_mask8[1] = *((__mmask8*)&mb_mask + 1);

    /* clear buffer index */
    _mm512_storeu_si512(
        HASH_BUFFIDX(p_state),
        _mm512_mask_set1_epi32(_mm512_loadu_si512(HASH_BUFFIDX(p_state)), mb_mask, 0));

    /* clear summary message length */
    _mm512_storeu_si512(MSG_LEN(p_state), _mm512_maskz_loadu_epi64(~mb_mask8[0], MSG_LEN(p_state)));
    _mm512_storeu_si512(MSG_LEN(p_state) + 8,
                        _mm512_maskz_loadu_epi64(~mb_mask8[1], MSG_LEN(p_state) + 8));


    /* clear buffer */
    for (int i = 0; i < SM3_NUM_BUFFERS; i++) {
        if ((mb_mask >> i) & 1)
            _mm512_storeu_si512(HASH_BUFF(p_state)[i], _mm512_setzero_si512());
    }

    /* setup initial digest in multi-buffer format */
    _mm512_storeu_si512(HASH_VALUE(p_state)[0],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[0]), mb_mask, (int)sm3_iv[0]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[1],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[1]), mb_mask, (int)sm3_iv[1]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[2],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[2]), mb_mask, (int)sm3_iv[2]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[3],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[3]), mb_mask, (int)sm3_iv[3]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[4],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[4]), mb_mask, (int)sm3_iv[4]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[5],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[5]), mb_mask, (int)sm3_iv[5]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[6],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[6]), mb_mask, (int)sm3_iv[6]));
    _mm512_storeu_si512(HASH_VALUE(p_state)[7],
                        _mm512_mask_set1_epi32(
                            _mm512_loadu_si512(HASH_VALUE(p_state)[7]), mb_mask, (int)sm3_iv[7]));

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
