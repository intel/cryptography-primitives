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


#include "utils.h"

size_t strlen_safe(const char* dest, size_t dmax)
{
    size_t count;

    /* check null pointer */
    if (NULL == dest) {
        return 0UL;
    }

    /* check max equal zero */
    if (0UL == dmax) {
        return 0UL;
    }

    /* check dmax > 4Kb */
    if (dmax > RSIZE_MAX_STR) {
        return 0UL;
    }

    count = 0UL;
    while (*dest && dmax) {
        ++count;
        --dmax;
        ++dest;
    }

    return count;
}
