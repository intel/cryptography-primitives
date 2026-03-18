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

/*
//               Intel(R) Cryptography Primitives Library
//
*/

#include "owndefs.h"
#include "ippcpdefs.h"
#include "owncp.h"
#include "pcpver.h"
#include "pcpname.h"

/* clang-format off */
#if ( _IPP_ARCH == _IPP_ARCH_IA32 ) || ( _IPP_ARCH == _IPP_ARCH_LP32 )
    #if ( _IPP == _IPP_H9 )           /* Intel® Advanced Vector Extensions 2 - ia32 */
        #define CRYPTO_LIB_CPU_TYPE() "h9"
        #define CRYPTO_LIB_CPU_DESCR() "AVX2"
    #elif ( _IPP == _IPP_P8 )           /* Intel® Streaming SIMD Extensions 4.2 (Intel® SSE4.2) - ia32 */
        #define CRYPTO_LIB_CPU_TYPE() "p8"
        #define CRYPTO_LIB_CPU_DESCR() "SSE4.2"
    #else
        #define CRYPTO_LIB_CPU_TYPE() "px"
        #define CRYPTO_LIB_CPU_DESCR() "PX"
    #endif
#elif ( _IPP_ARCH == _IPP_ARCH_EM64T ) || ( _IPP_ARCH == _IPP_ARCH_LP64 )
    #if ( _IPP32E == _IPP32E_D1 )       /* Intel® Advanced Vector Extensions 10.2 - intel64 */
        #define CRYPTO_LIB_CPU_TYPE() "d1"
        #define CRYPTO_LIB_CPU_DESCR() "AVX10.2"
    #elif ( _IPP32E == _IPP32E_K1 )       /* Intel® Advanced Vector Extensions 512 (formerly Icelake) - intel64 */
        #define CRYPTO_LIB_CPU_TYPE() "k1"
        #define CRYPTO_LIB_CPU_DESCR() "AVX-512F/CD/BW/DQ/VL/SHA/VBMI/VBMI2/IFMA/GFNI/VAES/VCLMUL"
    #elif ( _IPP32E == _IPP32E_K0 )       /* Intel® Advanced Vector Extensions 512 (formerly Skylake) - intel64 */
        #define CRYPTO_LIB_CPU_TYPE() "k0"
        #define CRYPTO_LIB_CPU_DESCR() "AVX-512F/CD/BW/DQ/VL"
    #elif ( _IPP32E == _IPP32E_L9 )     /* Intel® Advanced Vector Extensions 2 - intel64 */
        #define CRYPTO_LIB_CPU_TYPE() "l9"
        #define CRYPTO_LIB_CPU_DESCR() "AVX2"
    #elif ( _IPP32E == _IPP32E_Y8 )     /* Intel® Streaming SIMD Extensions 4.2 - intel64 */
        #define CRYPTO_LIB_CPU_TYPE() "y8"
        #define CRYPTO_LIB_CPU_DESCR() "SSE4.2"
    #else
        #define CRYPTO_LIB_CPU_TYPE() "mx"
        #define CRYPTO_LIB_CPU_DESCR() "PX"
    #endif
#endif
/* clang-format on */

#define GET_LIBRARY_NAME()         \
    CRYPTO_LIB_NAME()              \
    " (" CRYPTO_LIB_CPU_TYPE() ")" \
                               " (ver: " STR_VERSION() " build: " __DATE__ ")"

static const CryptoLibraryVersion cryptoLibVer = {
    /* major, minor, patch (ex-majorBuild) */
    BASE_VERSION(),
    /* targetCpu[4] */
    CRYPTO_LIB_CPU_TYPE(),
    CRYPTO_LIB_NAME() " (" CRYPTO_LIB_CPU_TYPE() ")",
    __DATE__,          //BuildDate
    GET_LIBRARY_NAME() /* release Version */
};

IPPFUN(const CryptoLibraryVersion*, cryptoGetLibVersion, (void)) { return &cryptoLibVer; };

/* Deprecated functionality*/
static const IppLibraryVersion ippcpLibVer = {
    /* major, minor, update (ex-majorBuild) */
    BASE_VERSION(),
#if defined IPP_REVISION
    IPP_REVISION,
#else
    0,
#endif             /* IPP_REVISION */
    CRYPTO_LIB_CPU_TYPE(),
    "ippCP " CRYPTO_LIB_CPU_DESCR() " (" CRYPTO_LIB_CPU_TYPE() ")",
    STR_VERSION(), /* release Version */
    __DATE__       //BuildDate
};

IPPFUN(const IppLibraryVersion*, ippcpGetLibVersion, (void)) { return &ippcpLibVer; };

/*////////////////////////// End of file "pcpver.c" ////////////////////////// */
