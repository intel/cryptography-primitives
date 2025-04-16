/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#ifdef IPPCP_FIPS_MODE
#include "ippcp.h"
#include "owndefs.h"
#include "dispatcher.h"

#include "ippcp/fips_cert.h"
#include "fips_cert_internal/common.h"

#if defined(_IPP_DATA)

IPPFUN(func_fips_approved, ippcp_is_fips_approved_func, (enum FIPS_IPPCP_FUNC function))
{
    return ((int)function > 0);
}

#endif // _IPP_DATA

IPP_OWN_DEFN(int,
             ippcp_is_mem_eq,
             (const Ipp8u* p1, Ipp32u p1_byte_len, const Ipp8u* p2, Ipp32u p2_byte_len))
{
    if (p1_byte_len != p2_byte_len) {
        return 0;
    }

    while (p1_byte_len) {
        if (*p1 != *p2) {
            return 0;
        }
        ++p1;
        ++p2;

        --p1_byte_len;
    }

    return 1;
}

#endif // IPPCP_FIPS_MODE
