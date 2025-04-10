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
  *  DSA-DLP scheme with (L = 3072, N = 256) DSA parameters and SHA-256 hash function.
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
static const int L_BIT = 3072;
static const int N_BIT = 256;

/*! Message size in bytes */
static const int MSG_LEN_BYTE = 6;

/*! Message text */
static Ipp8u MSG[MSG_LEN_BYTE] = { 0x31, 0x32, 0x33, 0x34, 0x30, 0x30 };

/*! The generator of the multiplicative subgroup */
static const BigNumber G("0x"
                         "6DEA4B8C3FE3AB91E3229FB14C1CFA822915769AF161405F48B7FADFE1EC5D9F"
                         "EC4EF0CFBB2233FFDDFA5A554CFC68C6BC6A0BA30CEF6F51309294E622B58D4F"
                         "ACE00AE9669D9172B15696839ED332AFD906E3F427D85A9AF73562B845BE53A3"
                         "713C0219402A4C208E9B6A6873235E0BC20442E70AB69EDD46E8F3F7D58CB35E"
                         "A3690C673F54CD37377725739F00EBE2B3B53BDAF89DDAC74012F8486BD3F521"
                         "7579B4A303F61BCCC98931FABA969C8C2A27ACB04BC21201EDF9A7F6B42E10F7"
                         "5DD23C3AB073D7290D173EBE6CB1919607BFE2BF0D829A609D8D3CDA7044FF8D"
                         "FBBD463E68C9403A45834EC547A7D4FD5ABC68C5997CDC397120698F879356E0"
                         "E74B62FE1A2938A5D1B486B53A5E0CB875E23A2E834EA563A4A9D4BE44045877"
                         "DF020C30E22E55603F63D74ED2CAFDE18180EC294A7CE263D56EB280562687F6"
                         "1F898F3C7D2B37D7F00250A43CA989DE16FA1AAB7D83E0DBF6AA66EDC36AD79E"
                         "ECFE2F91CFAB6285BA10AE713126F69326540C461E44E45BDF076E4ED8D3E924");

/*! The modulus p */
static const BigNumber P("0x"
                         "DCD2F71FBA7AEB46AEEA858AB76F2102FA97A953ABCE9D791AA269F0161733AC"
                         "3DF25F5C9DB3448F82846E355E23089614046D42B030298D94F5365D942CBB54"
                         "90E40A1D5E6E577CC646A807F049A1FB42B97A9E64EFA1AA9EF93BB3C7120DDB"
                         "F9C403E580431F1789127F0A64EA7B036EF12D07F02103655D63DDDA3C44AD32"
                         "8F727C1D060FC92E3616976CF11BF1FEEFFF033490D98929252B585CD92C081A"
                         "FCC71DAE6341AE8DD05E62AE297AD2B00560EC94F1F64482816E3AF052FC1DAF"
                         "F0A9BF52034012594D4246036D040FA5E741E693E36B064BEDB224EA1F7C6C86"
                         "171CA8FCFAC98C5DB6E34DAD307C5BFDECE4E578F0E18FCAAEE9D5B330ED69A7"
                         "2D8FDDF878A58A57914247825AE6ED1CB8A6B241EA694B77F843EEE40F1BE90F"
                         "26B26154813647D1E1AF01254CF21CFDD2E9EBA7E431BD8DB6164D05A3D3AE93"
                         "71AF5D0D39A3A9B9F07BA61233C77A6BFC273515FB844DB8FAFD69B559CE844C"
                         "7A3D686EA4991D9FE74CAD560489F3C1DBB4FD171EA8AE7874E302207C02A7B1");

/*! The order of the generator g */
static const BigNumber Q("0xF870D35CA9F84E6ACAD808D6AC35B13EE4073F26EA84FEFE08C4D9A565754037");

/*! The public key value */
static const BigNumber Y("0x"
                         "7E0062E6F32ECAB1EFFA38391B71A523221D6E97A61F55238F0A623CC42980B9"
                         "87FB22EC6138E8D1C0D36C05D059CA0CA3F1A526A5F67B216341ABCD04105BB8"
                         "EFC9E479C2532F9DEA6CDDFB4F57DE5B9D6964E3D314EB89693A3D57F82B9FF9"
                         "3E0E0D11D72FA4F1BD82BB2B20F1B59547AFF7711DB319D7D06E6964BEB294E4"
                         "4D34C2A21C7AC7CDAC5E91F2F6D183042AFC3644B09837FA2225A074CEB65D49"
                         "9F73CEE04C705C82BB912F97D765D5F9C8CB442019E7DAC1E1CCCCEE990335EA"
                         "3B8C837583595CD4F83169D4787FE4675386D604E8E205B977C7AB2369504282"
                         "54E3B836BD00296257238D22BDA16A722E405DF82029E3384931FB0E4903C3F8"
                         "771FB15708D4CB3238E7B2A68131BE518A08D6EFD483A01537A432046DCBD1FF"
                         "A5FF831E0257B292012D5E1A44C6E32019A6B3AE176A67EDAF12EB27E68FA60A"
                         "05AF4E5448D606C392B4A672B44298B1775A16B9440B131EB0D91CA3FDE1A1E5"
                         "28B5FFFC31FFDF1449169C2F4ABD96809A75FB6C85AE845940C45D5AF8334057");

/*! R digital signature component */
static const BigNumber sigR("0x8C7F9B7F5D53A4D3877185D2EF69B2B3AB16321D996940C2EFCBEF01C0B598B4");

/*! S digital signature component */
static const BigNumber sigS("0x33708B0FD4109873550D02340918EC93E5383D471C9D0A322AA76C2872783CBA");

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
    const int digestSizeBit  = IPP_SHA256_DIGEST_BITSIZE;
    const int digestSizeByte = digestSizeBit / 8;
    /* Pointer to the SHA-256 hash method */
    const IppsHashMethod* hashMethod = ippsHashMethod_SHA256();

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
                         "DSA-DLP Verification Hash Method Message SHA-256",
                         ippStsNoErr == status);

    return status;
}
