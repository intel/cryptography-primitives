/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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

#ifndef INTERNAL_DEFS_H
#define INTERNAL_DEFS_H

#define _MBX_L9 1
#define _MBX_K1 2

#if defined(_L9) || (_K1)
#include "ec_nistp256_cpuspc.h"
#include "ec_nistp384_cpuspc.h"
#include "ec_nistp521_cpuspc.h"
#include "ec_sm2_cpuspc.h"
#include "ed25519_cpuspc.h"
#include "exp_cpuspc.h"
#include "rsa_cpuspc.h"
#include "sm3_cpuspc.h"
#include "sm4_ccm_cpuspc.h"
#include "sm4_cpuspc.h"
#include "sm4_gcm_cpuspc.h"
#include "x25519_cpuspc.h"
#endif

/* clang-format off */
#if defined(_MBX_MERGED_BLD)
    #if defined(_L9) /* Intel® AVX2 */
        #define OWNAPI(name) l9_##name
    #elif defined(_K1)
        #define OWNAPI(name) k1_##name
    #endif
#else /* 1CPU build */
    #define OWNAPI(name) name
#endif

#if defined(_L9) /* Intel® AVX2 */
    #define _MBX _MBX_L9
#elif defined(_K1)
    #define _MBX _MBX_K1
#endif

/* 
 * Memory consumption optimization: merged build compiles data only 
 * for a one single object(lib letter) to avoid multiple copies of the data.
 */
#if defined(_MBX_MERGED_BLD)
    /* compile data only for l9_ sources in case it has compiler's support */
    #if defined(_L9) && defined(_MBX_AVX_IFMA_SUPPORTED)
        #define _MBX_DATA 1
    /* no compiler's support  */
    #elif defined(_K1) && !defined(_MBX_AVX_IFMA_SUPPORTED)
        #define _MBX_DATA 1
    #endif /* #if defined(_L9) */
#else
    /* compile data unconditionally */
    #define _MBX_DATA 1
#endif /* #if defined(_MBX_MERGED_BLD) */
/* clang-format on */

#endif /* INTERNAL_DEFS_H */
