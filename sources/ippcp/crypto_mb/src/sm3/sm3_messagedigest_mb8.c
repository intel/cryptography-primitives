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

mbx_status sm3_msg_digest_mb8(const int8u* const msg_pa[8], int len[8], int8u* hash_pa[8])
{
    int buf_no;
    mbx_status status = 0;

    /* test input pointers */
    if (NULL == msg_pa || NULL == len || NULL == hash_pa) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    for (buf_no = 0; buf_no < SM3_NUM_BUFFERS8; buf_no++) {
        if ((len[buf_no] && !hash_pa[buf_no]) || (len[buf_no] && !msg_pa[buf_no])) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            return status;
        }
    }

    /* initialize the context of SM3 hash */
    SM3_CTX_mb8 p_state;
    sm3_init_mb8(&p_state);

    /* process main part of the message */
    status = sm3_update_mb8(msg_pa, len, &p_state);

    if (MBX_IS_ANY_OK_STS(status)) {
        /* finalize message processing */
        status = sm3_final_mb8(hash_pa, &p_state);
    }

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
