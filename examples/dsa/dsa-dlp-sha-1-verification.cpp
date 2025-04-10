/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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
  *  \brief DSA-DLP verification scheme example
  * 
  *  This example demonstrates message verification according to
  *  DSA-DLP scheme with (L = 1024, N = 160) DSA parameters and SHA-1 hash function.
  *
  *  The DSA-DLP scheme is implemented according : Digital Signature Standard (DSS) (FIPS PUB 186-4) (July 2013)
  *  
  *  available at:
  *
  *  http://dx.doi.org/10.6028/NIST.FIPS.186-4.
  *
  */

#include <string.h>

#include "bignum.h"
#include "examples_common.h"
#include "ippcp.h"

/*! Parameters DSA-DLP scheme */
static const int L_BIT = 1024;
static const int N_BIT = 160;

/*! Message size in bytes */
static const int MSG_LEN_BYTE = 6;

/*! Message text */
static Ipp8u MSG[MSG_LEN_BYTE] = { 0x31, 0x32, 0x33, 0x34, 0x30, 0x30 };

/*! The generator of the multiplicative subgroup */
static const BigNumber G("0x"
                         "0835AA8C358BBF01A1846D1206323FABE408B0E98789FCC6239DA14D4B3F86C2"
                         "76A8F48AA85A59507E620AD1BC745F0F1CBF63EC98C229C2610D77C634D1642E"
                         "404354771655B2D5662F7A45227178CE3430AF0F6B3BB94B52F7F51E97BAD659"
                         "B1BA0684E208BE624C28D82FB1162F18DD9DCE45216461654CF3374624D15A8D");

/*! The modulus p */
static const BigNumber P("0x"
                         "B34CE9C1E78294D3258473842005D2A48C8C566CFCA8F84C0606F2529B59A6D3"
                         "8AAE071B53BB2167EAA4FC3B01FE176E787E481B6037AAC62CBC3D089799536A"
                         "869FA8CDFEA1E8B1FD2D1CD3A30350859A2CD6B3EC2F9BFBB68BB11B4BBE2ADA"
                         "A18D64A93639543AE5E16293E311C0CF8C8D6E180DF05D08C2FD2D93D570751F");

/*! The order of the generator g */
static const BigNumber Q("0xB90B38BA0A50A43EC6898D3F9B68049777F489B1");

/*! The public key value */
static const BigNumber Y("0x"
                         "173931DDA31EFF32F24B383091BF77EACDC6EFD557624911D8E9B9DEBF0F256D"
                         "0CFFAC5567B33F6EAAE9D3275BBED7EF9F5F94C4003C959E49A1ED3F58C31B21"
                         "BACCC0ED8840B46145F121B8906D072129BAE01F071947997E8EF760D2D9EA21"
                         "D08A5EB7E89390B21A85664713C549E25FEDA6E9E6C31970866BDFBC8FA981F6");

/*! R digital signature component */
static const BigNumber sigR("0xAA6A258FBF7D90E15614676D377DF8B10E38DB4A");

/*! S digital signature component */
static const BigNumber sigS("0x496D5220B5F67D3532D1F991203BC3523B964C3B");

int main(void)
{
    /*! Internal function status */
    IppStatus status = ippStsNoErr;

    /* Pointer to DSA DLP context structure */
    IppsDLPState* pDL = NULL;

    /* Result verification DSA DLP */
    IppDLResult result = ippDLValid;

    /* Size of DSA-DLP context structure. It will be set up in ippsDLPGetSize(). */
    int DLSize = 0;

    /* Digest size */
    const int digestSizeBit  = IPP_SHA1_DIGEST_BITSIZE;
    const int digestSizeByte = digestSizeBit / 8;
    /* Pointer to the SHA-1 hash method */
    const IppsHashMethod* hashMethod = ippsHashMethod_SHA1();

    /*! Algorithm */
    do {
        /* 1. Create a digest by message */
        /*! Buffer create digest */
        Ipp8u md[digestSizeByte] = {};

        /*! Create digest by message */
        status = ippsHashMessage_rmf(MSG, MSG_LEN_BYTE, md, hashMethod);
        /*! Check status create digest */
        if (ippStsNoErr != status)
            break;

        /*! 
         * (!) Allocate BigNumber container for the shrank message digest.
         *     Note, the DSA algorithm uses only leftmost |minSizeDigestBit| bits of the original message digest
         */
        const int minSizeDigestBit = IPP_MIN(N_BIT, digestSizeBit);
        BigNumber digest(NULL, bitSizeInWords(minSizeDigestBit));

        /*! Set digest to BigNumber */
        status = ippsSetOctString_BN(md, bitSizeInBytes(minSizeDigestBit), digest);
        if (ippStsNoErr != status)
            break;

        /* 2. Get size needed for DSA DLP context structure */
        status = ippsDLPGetSize(L_BIT, N_BIT, &DLSize);
        if (ippStsNoErr != status)
            break;

        /* 3. Allocate memory for DSA DLP context structure */
        pDL = (IppsDLPState*)(new Ipp8u[DLSize]);
        if (NULL == pDL) {
            printf("ERROR: Cannot allocate memory (%d bytes) for DSA DLP context\n", DLSize);
            return -1;
        }

        /* 4. Initialize DSA DLP context */
        status = ippsDLPInit(L_BIT, N_BIT, pDL);
        if (ippStsNoErr != status)
            break;

        /* 5. Set DL Domain Parameters */
        status = ippsDLPSet(P, Q, G, pDL);
        if (ippStsNoErr != status)
            break;

        /* 6. Set up Key Pair into the DL context */
        status = ippsDLPSetKeyPair(NULL, /* optional Private Key Set */
                                   Y,
                                   pDL);
        if (ippStsNoErr != status)
            break;

        /* 7. Verify Signature DSA DLP */
        status = ippsDLPVerifyDSA(digest, sigR, sigS, &result, pDL);
        if (ippStsNoErr != status)
            break;
        if (ippDLValid != result)
            status = ippStsErr;

    } while (0); /* end Algorithm */

    /* 8. Remove secret and release resources */
    if (NULL != pDL)
        delete[] (Ipp8u*)pDL;

    PRINT_EXAMPLE_STATUS("ippsDLPVerifyDSA",
                         "DSA-DLP Verification Hash Method Message SHA-1",
                         ippStsNoErr == status);

    return status;
}
