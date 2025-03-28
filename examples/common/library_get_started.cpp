/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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
  *  \brief Get Started example
  *
  *  This example demonstrates usage of cryptoGetLibVersion and ippcpGetCpuFeatures functions work
  *
  */

#include <stdio.h>

#include "ippcp.h"
#include "examples_common.h"

int main(int argc, char* argv[])
{
    const CryptoLibraryVersion* lib;
    IppStatus status;
    Ipp64u mask, emask;

    /*! Get Intel(R) Cryptography Primitives Library version info */
    lib = cryptoGetLibVersion();
    printf("%s\n", lib->strVersion);

    /*! Get CPU features and features enabled with selected library level */
    status = ippcpGetCpuFeatures(&mask);
    if (ippStsNoErr == status) {
        emask = ippcpGetEnabledCpuFeatures();
        printf("Features supported by CPU\tby Intel(R) Cryptography Primitives Library\n");
        printf("-----------------------------------------\n");
        printf("  ippCPUID_MMX        = ");
        printf("%c\t%c\t", (mask & ippCPUID_MMX) ? 'Y' : 'N', (emask & ippCPUID_MMX) ? 'Y' : 'N');
        printf("Intel(R) Architecture MMX technology supported\n");
        printf("  ippCPUID_SSE        = ");
        printf("%c\t%c\t", (mask & ippCPUID_SSE) ? 'Y' : 'N', (emask & ippCPUID_SSE) ? 'Y' : 'N');
        printf("Intel(R) Streaming SIMD Extensions (Intel(R) SSE)\n");
        printf("  ippCPUID_SSE2       = ");
        printf("%c\t%c\t", (mask & ippCPUID_SSE2) ? 'Y' : 'N', (emask & ippCPUID_SSE2) ? 'Y' : 'N');
        printf("Intel(R) Streaming SIMD Extensions 2 (Intel(R) SSE2)\n");
        printf("  ippCPUID_SSE3       = ");
        printf("%c\t%c\t", (mask & ippCPUID_SSE3) ? 'Y' : 'N', (emask & ippCPUID_SSE3) ? 'Y' : 'N');
        printf("Intel(R) Streaming SIMD Extensions 3 (Intel(R) SSE3)\n");
        printf("  ippCPUID_SSSE3      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_SSSE3) ? 'Y' : 'N', (emask & ippCPUID_SSSE3) ? 'Y' : 'N');
        printf("Supplemental Streaming SIMD Extensions 3 (SSSE3)\n");
        printf("  ippCPUID_MOVBE      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_MOVBE) ? 'Y' : 'N', (emask & ippCPUID_MOVBE) ? 'Y' : 'N');
        printf("The processor supports MOVBE instruction\n");
        printf("  ippCPUID_SSE41      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_SSE41) ? 'Y' : 'N', (emask & ippCPUID_SSE41) ? 'Y' : 'N');
        printf("Intel(R) Streaming SIMD Extensions 4.1 (Intel(R) SSE4.1)\n");
        printf("  ippCPUID_SSE42      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_SSE42) ? 'Y' : 'N', (emask & ippCPUID_SSE42) ? 'Y' : 'N');
        printf("Intel(R) Streaming SIMD Extensions 4.2 (Intel(R) SSE4.2)\n");
        printf("  ippCPUID_AVX        = ");
        printf("%c\t%c\t", (mask & ippCPUID_AVX) ? 'Y' : 'N', (emask & ippCPUID_AVX) ? 'Y' : 'N');
        printf("Intel(R) Advanced Vector Extensions (Intel(R) AVX) instruction set\n");
        printf("  ippAVX_ENABLEDBYOS  = ");
        printf("%c\t%c\t",
               (mask & ippAVX_ENABLEDBYOS) ? 'Y' : 'N',
               (emask & ippAVX_ENABLEDBYOS) ? 'Y' : 'N');
        printf("The operating system supports Intel(R) AVX\n");
        printf("  ippCPUID_AES        = ");
        printf("%c\t%c\t", (mask & ippCPUID_AES) ? 'Y' : 'N', (emask & ippCPUID_AES) ? 'Y' : 'N');
        printf("Intel(R) Advanced Encryption Standard New Instructions (Intel(R) AES-NI)\n");
        printf("  ippCPUID_SHA        = ");
        printf("%c\t%c\t", (mask & ippCPUID_SHA) ? 'Y' : 'N', (emask & ippCPUID_SHA) ? 'Y' : 'N');
        printf("Intel(R) Secure Hash Algorithm - New Instructions (Intel(R) SHA-NI)\n");
        printf("  ippCPUID_CLMUL      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_CLMUL) ? 'Y' : 'N', (emask & ippCPUID_CLMUL) ? 'Y' : 'N');
        printf("PCLMULQDQ instruction\n");
        printf("  ippCPUID_RDRAND     = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_RDRAND) ? 'Y' : 'N',
               (emask & ippCPUID_RDRAND) ? 'Y' : 'N');
        printf("Read Random Number instructions\n");
        printf("  ippCPUID_F16C       = ");
        printf("%c\t%c\t", (mask & ippCPUID_F16C) ? 'Y' : 'N', (emask & ippCPUID_F16C) ? 'Y' : 'N');
        printf("Float16 instructions\n");
        printf("  ippCPUID_AVX2       = ");
        printf("%c\t%c\t", (mask & ippCPUID_AVX2) ? 'Y' : 'N', (emask & ippCPUID_AVX2) ? 'Y' : 'N');
        printf("Intel(R) Advanced Vector Extensions 2 (Intel(R) AVX2) instruction set\n");
        printf("  ippCPUID_AVX512F    = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_AVX512F) ? 'Y' : 'N',
               (emask & ippCPUID_AVX512F) ? 'Y' : 'N');
        printf("Intel(R) Advanced Vector Extensions 3.1 instruction set\n");
        printf("  ippCPUID_AVX512CD   = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_AVX512CD) ? 'Y' : 'N',
               (emask & ippCPUID_AVX512CD) ? 'Y' : 'N');
        printf("Intel(R) Advanced Vector Extensions CD (Conflict Detection) instruction set\n");
        printf("  ippCPUID_AVX512ER   = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_AVX512ER) ? 'Y' : 'N',
               (emask & ippCPUID_AVX512ER) ? 'Y' : 'N');
        printf("Intel(R) Advanced Vector Extensions ER instruction set\n");
        printf("  ippCPUID_ADCOX      = ");
        printf(
            "%c\t%c\t", (mask & ippCPUID_ADCOX) ? 'Y' : 'N', (emask & ippCPUID_ADCOX) ? 'Y' : 'N');
        printf("ADCX and ADOX instructions\n");
        printf("  ippCPUID_RDSEED     = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_RDSEED) ? 'Y' : 'N',
               (emask & ippCPUID_RDSEED) ? 'Y' : 'N');
        printf("The RDSEED instruction\n");
        printf("  ippCPUID_PREFETCHW  = ");
        printf("%c\t%c\t",
               (mask & ippCPUID_PREFETCHW) ? 'Y' : 'N',
               (emask & ippCPUID_PREFETCHW) ? 'Y' : 'N');
        printf("The PREFETCHW instruction\n");
        printf("  ippCPUID_KNC        = ");
        printf("%c\t%c\t", (mask & ippCPUID_KNC) ? 'Y' : 'N', (emask & ippCPUID_KNC) ? 'Y' : 'N');
        printf("Intel(R) Xeon Phi™ coprocessor instruction set\n");
    }

    PRINT_EXAMPLE_STATUS("ippcpGetCpuFeatures", "Demonstration of cryptoGetLibVersion and ippcpGetCpuFeatures functions work", ippStsNoErr == status);
    return status;
}
