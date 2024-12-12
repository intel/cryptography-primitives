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

#ifndef EXP_H
#define EXP_H

#include <crypto_mb/defs.h>
#include <crypto_mb/status.h>

/* size of scratch buffer */
MBXAPI(int, mbx_exp_BufferSize, (int modulusBits))

/* exp operation */
MBXAPI(mbx_status,
       mbx_exp1024_mb8,
       (int64u* const out_pa[8],
        const int64u* const base_pa[8],
        const int64u* const exp_pa[8],
        int exp_bits,
        const int64u* const mod_pa[8],
        int mod_bits,
        int8u* pBuffer,
        int bufferLen))

MBXAPI(mbx_status,
       mbx_exp2048_mb8,
       (int64u* const out_pa[8],
        const int64u* const base_pa[8],
        const int64u* const exp_pa[8],
        int exp_bits,
        const int64u* const mod_pa[8],
        int mod_bits,
        int8u* pBuffer,
        int bufferLen))

MBXAPI(mbx_status,
       mbx_exp3072_mb8,
       (int64u* const out_pa[8],
        const int64u* const base_pa[8],
        const int64u* const exp_pa[8],
        int exp_bits,
        const int64u* const mod_pa[8],
        int mod_bits,
        int8u* pBuffer,
        int bufferLen))

MBXAPI(mbx_status,
       mbx_exp4096_mb8,
       (int64u* const out_pa[8],
        const int64u* const base_pa[8],
        const int64u* const exp_pa[8],
        int exp_bits,
        const int64u* const mod_pa[8],
        int mod_bits,
        int8u* pBuffer,
        int bufferLen))

MBXAPI(mbx_status,
       mbx_exp_mb8,
       (int64u* const out_pa[8],
        const int64u* const base_pa[8],
        const int64u* const exp_pa[8],
        int exp_bits,
        const int64u* const mod_pa[8],
        int mod_bits,
        int8u* pBuffer,
        int bufferLen))

#endif /* EXP_H */
