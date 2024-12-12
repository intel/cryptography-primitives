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
#include <crypto_mb/sm4.h>

#include <internal/sm4/sm4_mb.h>
#include <internal/common/ifma_defs.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

/* FK[] constants */
static const int32u SM4_FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

/* CK[] constants */
static const int32u SM4_CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

#define SM4_ONE_RK(K0, K1, K2, K3, TMP, CK, OUT)                                 \
    {                                                                            \
        /* (Ki+1 ^ Ki+2 ^ Ki+3 ^ CKi) */                                         \
        (TMP) = _mm512_xor_epi32(_mm512_xor_epi32(_mm512_xor_epi32(K1, K2), K3), \
                                 _mm512_set1_epi32(CK));                         \
        /* T'(Ki+1 ^ Ki+2 ^ Ki+3 ^ CKi) */                                       \
        (TMP) = sBox512(TMP);                                                    \
        (TMP) = _mm512_xor_epi32(TMP, Lkey512(TMP));                             \
        /* Ki+4 = Ki ^ T'(Ki+1 ^ Ki+2 ^ Ki+3 ^ CKi) */                           \
        (K0) = _mm512_xor_epi32(K0, TMP);                                        \
        _mm512_storeu_si512((void*)(OUT), K0);                                   \
    }

#define SM4_FOUR_RK(K0, K1, K2, K3, TMP, CK, OUT)              \
    {                                                          \
        SM4_ONE_RK(K0, K1, K2, K3, TMP, (CK)[0], OUT);         \
        SM4_ONE_RK(K1, K2, K3, K0, TMP, (CK)[1], ((OUT) + 1)); \
        SM4_ONE_RK(K2, K3, K0, K1, TMP, (CK)[2], ((OUT) + 2)); \
        SM4_ONE_RK(K3, K0, K1, K2, TMP, (CK)[3], ((OUT) + 3)); \
    }


mbx_status16 internal_avx512_sm4_set_round_keys_mb16(int32u* key_sched[SM4_ROUNDS],
                                                     const int8u* pa_inp_key[SM4_LINES],
                                                     __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    __m512i rki         = _mm512_setzero_si512();
    __m512i z0, z1, z2, z3;

    TRANSPOSE_16x4_I32_EPI32(&z0, &z1, &z2, &z3, pa_inp_key, mb_mask);

    /* (K0, K1, K2, K3) = (MK0 ^ FK0, MK1 ^ FK1, MK2 ^ FK2, MK3 ^ FK3) */
    z0 = _mm512_xor_epi32(z0, _mm512_set1_epi32(SM4_FK[0]));
    z1 = _mm512_xor_epi32(z1, _mm512_set1_epi32(SM4_FK[1]));
    z2 = _mm512_xor_epi32(z2, _mm512_set1_epi32(SM4_FK[2]));
    z3 = _mm512_xor_epi32(z3, _mm512_set1_epi32(SM4_FK[3]));

    const int32u* pCK   = SM4_CK;
    const __m512i* p_rk = (const __m512i*)key_sched;

    int itr;
    for (itr = 0; itr < SM4_ROUNDS; itr += 4, pCK += 4, p_rk += 4)
        SM4_FOUR_RK(z0, z1, z2, z3, rki, pCK, p_rk);

    /* clear copies of sensitive data and round keys */
    zero_mb8((int64u(*)[8]) & z0, 1);
    zero_mb8((int64u(*)[8]) & z1, 1);
    zero_mb8((int64u(*)[8]) & z2, 1);
    zero_mb8((int64u(*)[8]) & z3, 1);
    zero_mb8((int64u(*)[8]) & rki, 1);

    return status;
}

mbx_status16 internal_avx512_sm4_xts_set_keys_mb16(mbx_sm4_key_schedule* key_sched1,
                                                   mbx_sm4_key_schedule* key_sched2,
                                                   const sm4_xts_key* pa_key[SM4_LINES],
                                                   __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    /* Generate round keys for key1 */
    internal_avx512_sm4_set_round_keys_mb16((int32u**)key_sched1, (const int8u**)pa_key, mb_mask);

    const sm4_key* pa_key2[SM4_LINES];

    for (int i = 0; i < SM4_LINES; i++)
        pa_key2[i] = (const sm4_key*)&((int8u*)pa_key[i])[16];

    /* Generate round keys for key2 */
    internal_avx512_sm4_set_round_keys_mb16((int32u**)key_sched2, (const int8u**)pa_key2, mb_mask);
    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
