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

/*!
  *
  *  \file
  *
  *  \brief AES Galois Counter mode of operation (GCM) example
  *
  *  This example demonstrates usage of AES block cipher with 128-bit key
  *  run with GCM mode of operation. Decryption scheme.
  *
  *  The GCM mode of operation is implemented according to the
  *  "NIST Special Publication 800-38D: Recommendation for Block Cipher Modes of
  *  Operation: Galois/Counter Mode (GCM) and GMAC" document:
  *
  *  https://csrc.nist.gov/pubs/sp/800/38/d/final
  *
  */

#include <cstring>

#include "ippcp.h"
#include "examples_common.h"

/*! Key size in bytes */
static const int KEY_SIZE = 16;

/*! Message size in bytes */
static const int MSG_LEN = 60;

/*! Initialization vector size in bytes */
static const int IV_LEN = 12;

/*! Tag size in bytes */
static const int TAG_LEN = 16;

/*! Additional authenticated data size in bytes */
static const int AAD_LEN = 20;

/*! 128-bit secret key */
static Ipp8u key128[KEY_SIZE] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};

/*! Initialization vector */
static const Ipp8u iv[IV_LEN] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
    0xde,0xca,0xf8,0x88
};

/*! Plain text */
static Ipp8u plainText[MSG_LEN] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
    0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
    0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
    0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
    0xba,0x63,0x7b,0x39
};

/*! Cipher text */
static Ipp8u cipherText[MSG_LEN] = {
    0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,
    0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
    0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,
    0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
    0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,
    0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
    0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,
    0x3d,0x58,0xe0,0x91
};

/*! Tag */
static const Ipp8u tag[TAG_LEN] = {
    0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,
    0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
};

/*! Additional authenticated data */
static const Ipp8u aad[AAD_LEN] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};

/*! Main function  */
int main(void)
{
    /* Size of AES-GCM context structure. It will be set up in ippsAES_GCMGetSize(). */
    int AESGCMSize = 0;

    /* Output plain text */
    Ipp8u pOutPlainText[MSG_LEN] = {};
    /* Output tag */
    Ipp8u pOutTag[TAG_LEN]        = {};

    /* Pointer to AES-GCM context structure */
    IppsAES_GCMState* pAESGCMState = 0;

    /* Internal function status */
    IppStatus status = ippStsNoErr;

    do {
        /* 1. Get size needed for AES-GCM context structure */
        status = ippsAES_GCMGetSize(&AESGCMSize);
        if (!checkStatus("ippsAES_GCMGetSize", ippStsNoErr, status))
            return status;

        /* 2. Allocate memory for AES-GCM context structure */
        pAESGCMState = (IppsAES_GCMState*)(new Ipp8u[AESGCMSize]);
        if (NULL == pAESGCMState) {
            printf("ERROR: Cannot allocate memory (%d bytes) for AES-GCM state\n", AESGCMSize);
            return -1;
        }

        /* 3. Initialize AES-GCM context */
        status = ippsAES_GCMInit(key128, KEY_SIZE, pAESGCMState, AESGCMSize);
        if (!checkStatus("ippsAES_GCMInit", ippStsNoErr, status))
            break;

        /* 4. Decryption setup */
        status = ippsAES_GCMStart(iv, IV_LEN, aad, AAD_LEN, pAESGCMState);
        if (!checkStatus("ippsAES_GCMStart", ippStsNoErr, status))
            break;

        /* 5.Decryption */
        status = ippsAES_GCMDecrypt(cipherText, pOutPlainText, MSG_LEN, pAESGCMState);
        if (!checkStatus("ippsAES_GCMDecrypt", ippStsNoErr, status))
            break;

        /* 6. Get tag */
        status = ippsAES_GCMGetTag(pOutTag, TAG_LEN, pAESGCMState);
        if (!checkStatus("ippsAES_GCMGetTag", ippStsNoErr, status))
            break;

        /* Compare output to known answer */
        if (0 != memcmp(pOutTag, tag, TAG_LEN)) {
            printf("ERROR: Output tag and reference tag do not match\n");
            break;
        }
        if (0 != memcmp(pOutPlainText, plainText, MSG_LEN)) {
            printf("ERROR: Decrypted and plain text do not match\n");
            break;
        }
    } while (0);

    /* 7. Remove secret and release resources */
    ippsAES_GCMReset(pAESGCMState);
    if (pAESGCMState) 
        delete [] (Ipp8u*)pAESGCMState;

    PRINT_EXAMPLE_STATUS("ippsAES_GCMDecrypt", "AES-GCM 128 Decryption", !status)

    return status;
}
