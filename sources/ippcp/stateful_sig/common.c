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

#include "owndefs.h"
#include "stateful_sig/common.h"

/*
 * Generates byteSize random Ipp8u numbers using rndFunc and pRndParam parameters.
 * If rndFunc is NULL the function uses library-based solutions by default.
 *
 * Output parameters:
 *    out   resulted byteSize bytes array with random numbers
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_rand_num, (Ipp32u* out,
                                      Ipp32s byteSize,
                                      IppBitSupplier rndFunc,
                                      void* pRndParam))
/* clang-format on */
{
    int bitSize = byteSize * /*bit size of 1 byte*/ 8;
    if (rndFunc == NULL) {
        return ippsTRNGenRDSEED(out, bitSize, pRndParam);
    }
    return rndFunc((Ipp32u*)out, bitSize, pRndParam);
}
