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

#include <internal/sm4/sm4_ccm_mb.h>

#if (_MBX >= _MBX_K1)

void sm4_ccm_set_tag_len_mb16(const int tag_len[SM4_LINES],
                              __mmask16 mb_mask,
                              SM4_CCM_CTX_mb16* p_context)
{
    int* tag_len_ctx = SM4_CCM_CONTEXT_TAG_LEN(p_context);
    unsigned i;

    for (i = 0; i < SM4_LINES; i++) {
        if (mb_mask & (1 << i)) {
            tag_len_ctx[i] = tag_len[i];
        }
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
