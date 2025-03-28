/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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

#ifndef IFMA_SSL_CONVERT_FUNCTIONS_H
#define IFMA_SSL_CONVERT_FUNCTIONS_H

/* Internal support functions for data conversion mb -> BUGNUM */

#ifndef BN_OPENSSL_DISABLE

#include <internal/common/ifma_defs.h>

__MBX_INLINE void reverse_inplace(int8u* inpout, int len)
{
    int midpoint = len / 2;
    for (int n = 0; n < midpoint; n++) {
        int x               = inpout[n];
        inpout[n]           = inpout[len - 1 - n];
        inpout[len - 1 - n] = x;
    }
}

__MBX_INLINE BIGNUM* BN_bnu2bn(int64u* val, int len, BIGNUM* ret)
{
    len = len * sizeof(int64u);
    reverse_inplace((int8u*)val, len);
    ret = BN_bin2bn((int8u*)val, len, ret);
    reverse_inplace((int8u*)val, len);
    return ret;
}

/*
 * Convert mb data to array of BIGNUMs
 *
 * Note: max bitLen = 521
 */
#define MAX_CONVERT_TO_BN_LEN64 (NUMBER_OF_DIGITS(521, 64))
__MBX_INLINE void MB_FUNC_NAME(ifma_to_BN_)(BIGNUM* out_bn[MB_WIDTH],
                                            const int64u inp_mb8[][MB_WIDTH],
                                            int bitLen)
{
    const int len64 = NUMBER_OF_DIGITS(bitLen, 64);

    int64u tmp[MB_WIDTH][MAX_CONVERT_TO_BN_LEN64];
    int64u* pa_tmp[MB_WIDTH];
    for (int nb = 0; nb < MB_WIDTH; nb++) {
        pa_tmp[nb] = tmp[nb];
    }

    /* convert to plain data */
    ifma_mb_to_BNU(pa_tmp, (const int64u(*)[MB_WIDTH])inp_mb8, bitLen);

    for (int nb = 0; nb < MB_WIDTH; nb++) {
        out_bn[nb] = BN_bnu2bn(tmp[nb], len64, out_bn[nb]);
    }
}

#endif /* BN_OPENSSL_DISABLE */
#endif /* IFMA_SSL_CONVERT_FUNCTIONS_H */
