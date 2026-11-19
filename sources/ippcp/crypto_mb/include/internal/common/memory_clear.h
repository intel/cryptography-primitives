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

#ifndef IFMA_MEMORY_CLEAR_H
#define IFMA_MEMORY_CLEAR_H

#include <internal/common/ifma_defs.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

/*
 * Zeroize len bytes starting at out (zero_mb8 in the k1 build, zero_mb4 in the l9 build).
 * The stores are not removed by the compiler, also when the buffer is dead afterwards.
 *
 *   out - buffer to clear, any alignment
 *   len - number of bytes to clear, len >= 0
 */
EXTERN_C void MB_FUNC_NAME(zero_)(void* out, int len);

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */

#endif /* IFMA_MEMORY_CLEAR_H */
