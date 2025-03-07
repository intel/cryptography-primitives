/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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

#ifndef IFMA_ECPRECOMP4_P256_H
#define IFMA_ECPRECOMP4_P256_H

#include <internal/ecnist/ifma_ecpoint_p256.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

#define MUL_BASEPOINT_WIN_SIZE (4)

#define BP_WIN_SIZE MUL_BASEPOINT_WIN_SIZE
#define BP_N_SLOTS  NUMBER_OF_DIGITS(P256_BITSIZE + 1, BP_WIN_SIZE)
#define BP_N_ENTRY  (1 << (BP_WIN_SIZE - 1))

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
#endif /* IFMA_ECPRECOMP4_P256_H */
