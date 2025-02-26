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

/*
//
//              Intel® Cryptography Primitives Library
//
//              Purpose: Describes the Intel® Cryptography Primitives Library version
//
*/


#if !defined( CRYPTOLIBVERSION_H__ )
#define CRYPTOLIBVERSION_H__

#define CRYPTO_LIB_VERSION_MAJOR  1
#define CRYPTO_LIB_VERSION_MINOR  1
#define CRYPTO_LIB_VERSION_PATCH 0

// Major interface version
#define CRYPTO_LIB_INTERFACE_VERSION_MAJOR 12
// Minor interface version
#define CRYPTO_LIB_INTERFACE_VERSION_MINOR 1

#define CRYPTO_LIB_VERSION_STR  STR(CRYPTO_LIB_VERSION_MAJOR) "." STR(CRYPTO_LIB_VERSION_MINOR) "." STR(CRYPTO_LIB_VERSION_PATCH) \
                                " (" STR(CRYPTO_LIB_INTERFACE_VERSION_MAJOR) "." STR(CRYPTO_LIB_INTERFACE_VERSION_MINOR) ")"

#endif /* CRYPTOLIBVERSION_H__ */
