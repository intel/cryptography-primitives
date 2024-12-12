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

#ifndef VERSION_H
#define VERSION_H

#include <crypto_mb/defs.h>

/* crypto_mb name & version */
#define MBX_LIB_NAME() "crypto_mb"
#define MBX_VER_MAJOR  1
#define MBX_VER_MINOR  1
#define MBX_VER_PATCH  0

/* major interface version */
#define MBX_INTERFACE_VERSION_MAJOR 12
/* minor interface version */
#define MBX_INTERFACE_VERSION_MINOR 1

typedef struct {
    int major;              /* e.g. 1               */
    int minor;              /* e.g. 2               */
    int patch;              /* e.g. 3               */
    char targetCpu[4];      /* corresponding to Intel® processor        */
    const char* name;       /* e,g. "crypto_mb"                         */
    const char* buildDate;  /* e.g. "Oct 28 2019"                       */
    const char* strVersion; /* e.g. "crypto_mb (ver 1.2.3 Oct 28 2019)" */
} mbxVersion;

MBXAPI(const mbxVersion*, mbx_getversion, (void))

#endif /* VERSION_H */
