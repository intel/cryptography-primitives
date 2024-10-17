/*************************************************************************
* Copyright (C) 2001 Intel Corporation
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
//              Intel® Cryptography Primitives Library
//
//              Purpose: Describes the base Intel® Cryptography Primitives Library version
//
*/


#include "ippcpversion.h"
#ifndef BASE_VERSION
#define BASE_VERSION() CRYPTO_LIB_VERSION_MAJOR,CRYPTO_LIB_VERSION_MINOR,CRYPTO_LIB_VERSION_PATCH
#endif

#define STR2(x)           #x
#define STR(x)       STR2(x)

#ifndef STR_BASE_VERSION
#define STR_BASE_VERSION() STR(CRYPTO_LIB_VERSION_MAJOR) "," STR(CRYPTO_LIB_VERSION_MINOR) ", " STR(CRYPTO_LIB_VERSION_PATCH)
#endif

#ifndef STR_VERSION
 #ifdef IPP_REVISION
  #define STR_VERSION() CRYPTO_LIB_VERSION_STR " (r" STR( IPP_REVISION ) ")"
 #else
  #define STR_VERSION() CRYPTO_LIB_VERSION_STR
 #endif
#endif


/* ////////////////////////////// End of file /////////////////////////////// */
