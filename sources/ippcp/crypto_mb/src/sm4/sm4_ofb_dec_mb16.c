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

#include <crypto_mb/status.h>
#include <crypto_mb/sm4.h>

#include <internal/common/ifma_defs.h>

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_decrypt_ofb_mb16)(int8u* pa_out[SM4_LINES],
                                              const int8u* pa_inp[SM4_LINES],
                                              const int len[SM4_LINES],
                                              const mbx_sm4_key_schedule* key_sched,
                                              int8u* pa_iv[SM4_LINES])
{
    return mbx_sm4_encrypt_ofb_mb16(pa_out, pa_inp, len, key_sched, pa_iv);
}
