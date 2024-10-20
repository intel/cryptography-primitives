/*************************************************************************
 * Copyright (C) 2019-2024 Intel Corporation
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

#include <internal/common/ifma_defs.h>

#if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#include <internal/rsa/avxifma_amm.h>

void ifma_amm52x30_mb4(int64u *out_mb, const int64u *inpA_mb, const int64u *inpB_mb, const int64u *inpM_mb, const int64u *k0_mb)
{
   ifma_amm52xN_mb4(out_mb, inpA_mb, inpB_mb, inpM_mb, k0_mb, 30);
}

#endif // #if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
