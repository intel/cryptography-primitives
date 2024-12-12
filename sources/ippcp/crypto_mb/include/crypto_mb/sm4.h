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


#ifndef SM4_H
#define SM4_H

#include <crypto_mb/defs.h>
#include <crypto_mb/status.h>

#define SM4_LINES        (16)                         /* Max number of buffers       */
#define SM4_BLOCK_SIZE   (16)                         /* SM4 data block size (bytes) */
#define SM4_KEY_SIZE     (16)                         /* SM4 key size (bytes)        */
#define SM4_ROUNDS       (32)                         /* SM4 number of rounds        */
#define SM4_XTS_MAX_SIZE ((1 << 20) * SM4_BLOCK_SIZE) /* SM4 max buffer size (bytes) */

typedef int8u sm4_key[SM4_KEY_SIZE];
typedef int8u sm4_xts_key[SM4_KEY_SIZE * 2];
typedef int32u mbx_sm4_key_schedule[SM4_ROUNDS][SM4_LINES];

MBXAPI(mbx_status16,
       mbx_sm4_set_key_mb16,
       (mbx_sm4_key_schedule * key_sched, const sm4_key* pa_key[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_xts_set_keys_mb16,
       (mbx_sm4_key_schedule * key_sched1,
        mbx_sm4_key_schedule* key_sched2,
        const sm4_xts_key* pa_key[SM4_LINES]))

MBXAPI(mbx_status16,
       mbx_sm4_encrypt_ecb_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched))
MBXAPI(mbx_status16,
       mbx_sm4_decrypt_ecb_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched))

MBXAPI(mbx_status16,
       mbx_sm4_encrypt_cbc_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        const int8u* pa_iv[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_decrypt_cbc_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        const int8u* pa_iv[SM4_LINES]))

MBXAPI(mbx_status16,
       mbx_sm4_encrypt_ctr128_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        int8u* pa_ctr[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_decrypt_ctr128_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        int8u* pa_ctr[SM4_LINES]))

MBXAPI(mbx_status16,
       mbx_sm4_encrypt_ofb_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        int8u* pa_iv[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_decrypt_ofb_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        int8u* pa_iv[SM4_LINES]))

MBXAPI(mbx_status16,
       mbx_sm4_encrypt_cfb128_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        const int8u* pa_iv[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_decrypt_cfb128_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched,
        const int8u* pa_iv[SM4_LINES]))

MBXAPI(mbx_status16,
       mbx_sm4_xts_encrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched1,
        const mbx_sm4_key_schedule* key_sched2,
        const int8u* pa_tweak[SM4_LINES]))
MBXAPI(mbx_status16,
       mbx_sm4_xts_decrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* pa_inp[SM4_LINES],
        const int len[SM4_LINES],
        const mbx_sm4_key_schedule* key_sched1,
        const mbx_sm4_key_schedule* key_sched2,
        const int8u* pa_tweak[SM4_LINES]))

#endif /* SM4_H */
