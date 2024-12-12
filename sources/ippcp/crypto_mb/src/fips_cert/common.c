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
#ifdef MBX_FIPS_MODE

#include <internal/fips_cert/common.h>

int mbx_is_mem_eq(const int8u* p1, int32u p1_byte_len, const int8u* p2, int32u p2_byte_len)
{
    if ((p1_byte_len != p2_byte_len) || (p1 == NULL) || (p2 == NULL)) {
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

fips_test_status mbx_selftest_map_test_status(const mbx_status returned_sts,
                                              const mbx_status expected_sts,
                                              const fips_test_status error_type)
{
    fips_test_status test_result;

    if (returned_sts == expected_sts) {
        test_result = MBX_ALGO_SELFTEST_OK;
    } else if (returned_sts == MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR)) {
        test_result = MBX_ALGO_SELFTEST_UNSUPPORTED_ISA_ERR;
    } else {
        test_result = error_type;
    }

    return test_result;
}

fips_test_status mbx_selftest_check_if_success(const mbx_status returned_sts,
                                               const fips_test_status error_type)
{
    return mbx_selftest_map_test_status(returned_sts, MBX_SET_STS_ALL(MBX_STATUS_OK), error_type);
}

#endif // MBX_FIPS_MODE
