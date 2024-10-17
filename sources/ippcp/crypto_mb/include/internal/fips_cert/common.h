/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#ifdef MBX_FIPS_MODE

#ifndef MBX_FIPS_CERT_COMMON_H
#define MBX_FIPS_CERT_COMMON_H

#include <crypto_mb/defs.h>

#ifndef BN_OPENSSL_DISABLE
    #include <openssl/bn.h>
#endif

#define MBX_LANES (8)

#define MBX_NISTP256_DATA_BYTE_LEN (32)
#define MBX_NISTP384_DATA_BYTE_LEN (48)
#define MBX_NISTP521_DATA_BYTE_LEN (66)
#define MBX_ED25519_DATA_BYTE_LEN  (32)
#define MBX_X25519_DATA_BYTE_LEN   (32)

#define MBX_RSA_PUB_EXP_BYTE_LEN (3)

#define MBX_RSA1K_DATA_BIT_LEN (1024)
#define MBX_RSA2K_DATA_BIT_LEN (2048)
#define MBX_RSA3K_DATA_BIT_LEN (3072)
#define MBX_RSA4K_DATA_BIT_LEN (4096)

#define MBX_RSA1K_DATA_BYTE_LEN ( (MBX_RSA1K_DATA_BIT_LEN) >> 3 )
#define MBX_RSA2K_DATA_BYTE_LEN ( (MBX_RSA2K_DATA_BIT_LEN) >> 3 )
#define MBX_RSA3K_DATA_BYTE_LEN ( (MBX_RSA3K_DATA_BIT_LEN) >> 3 )
#define MBX_RSA4K_DATA_BYTE_LEN ( (MBX_RSA4K_DATA_BIT_LEN) >> 3 )

/**
 * \brief
 *
 *  Comparison of two byte arrays.
 *
 *  Compares byte arrays, returns 1 if arrays are equal, 0 otherwise.
 * 
 *  NOTE: This function should not be used for a secure memory comparison (i.e. constant time).
 *
 * \param[in] p1 pointer to first byte array
 * \param[in] p1_byte_len length of first array in bytes
 * \param[in] p2 pointer to second byte array
 * \param[in] p2_byte_len length of second array in bytes
 * 
 */
int mbx_is_mem_eq(const int8u *p1, int32u p1_byte_len, const int8u *p2, int32u p2_byte_len);

#endif // MBX_FIPS_CERT_COMMON_H
#endif // MBX_FIPS_MODE
