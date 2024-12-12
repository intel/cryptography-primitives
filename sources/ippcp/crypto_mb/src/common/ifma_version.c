/*************************************************************************
* Copyright (C) 2019 Intel Corporation
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
#include <crypto_mb/version.h>

#define MBX_LIB_VERSION() MBX_VER_MAJOR, MBX_VER_MINOR, MBX_VER_PATCH
#define MBX_LIB_BUILD()   __DATE__

#define STR2(x) #x
#define STR(x)  STR2(x)

#if (_MBX >= _MBX_K1)
/* Intel® Advanced Vector Extensions 512 (Intel® AVX-512) (formerly Icelake) - intel64 */
#define MBX_LIB_CPU_TYPE() "k1"
#else
/* Intel® Advanced Vector Extensions 2 (Intel® AVX2) - intel64 */
#define MBX_LIB_CPU_TYPE() "l9"
#endif

/* clang-format off */
#define MBX_STR_VERSION()  MBX_LIB_NAME() " (" MBX_LIB_CPU_TYPE() ")"                                      \
                           " (ver: " STR(MBX_VER_MAJOR) "." STR(MBX_VER_MINOR) "." STR(MBX_VER_PATCH) " (" \
                           STR(MBX_INTERFACE_VERSION_MAJOR)"."STR(MBX_INTERFACE_VERSION_MINOR)")"          \
                           " build: " MBX_LIB_BUILD()")"
/* clang-format on */

/* version info */
static const mbxVersion mbxLibVer = {
    MBX_LIB_VERSION(),                          /* major, minor, patch */
    MBX_LIB_CPU_TYPE(),                         /* target CPU          */
    MBX_LIB_NAME() " (" MBX_LIB_CPU_TYPE() ")", /* lib name            */
    MBX_LIB_BUILD(),                            /* build date          */
    MBX_STR_VERSION()                           /* version str         */
};

DLL_PUBLIC
const mbxVersion* OWNAPI(mbx_getversion)(void) { return &mbxLibVer; }
