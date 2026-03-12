/*************************************************************************
* Copyright (C) 2009 Intel Corporation
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

//
// Intel® Cryptography Primitives Library
//

#ifndef __DISPATCHER_H__
#define __DISPATCHER_H__

#if defined(__cplusplus)
extern "C" {
#endif

/*
  Intel® Cryptography Primitives Library and CPU features mask fitness. Implemented only for IA32 and Intel64 (emt)
*/

#if defined(_ARCH_IA32)
#define PX_FM (ippCPUID_MMX | ippCPUID_SSE)
/* clang-format off */
#define P8_FM (PX_FM | ippCPUID_SSE2 | ippCPUID_SSE3 | ippCPUID_SSSE3 | ippCPUID_MOVBE | ippCPUID_SSE41 | ippCPUID_SSE42 | ippCPUID_AES | ippCPUID_CLMUL | ippCPUID_SHA)
#define H9_FM (P8_FM | ippCPUID_AVX | ippAVX_ENABLEDBYOS | ippCPUID_RDRAND | ippCPUID_F16C | ippCPUID_AVX2 | ippCPUID_ADCOX | ippCPUID_RDSEED | ippCPUID_PREFETCHW)
/* clang-format on */
#elif defined(_ARCH_EM64T)

#define PX_FM (ippCPUID_MMX | ippCPUID_SSE | ippCPUID_SSE2)
/* clang-format off */
#define Y8_FM (PX_FM | ippCPUID_SSE3 | ippCPUID_SSSE3 | ippCPUID_MOVBE | ippCPUID_SSE41 | ippCPUID_SSE42 | ippCPUID_AES | ippCPUID_CLMUL | ippCPUID_SHA)
#define E9_FM (Y8_FM | ippCPUID_AVX | ippAVX_ENABLEDBYOS | ippCPUID_RDRAND | ippCPUID_F16C)
#define L9_FM (E9_FM | ippCPUID_MOVBE | ippCPUID_AVX2 | ippCPUID_ADCOX | ippCPUID_RDSEED | ippCPUID_PREFETCHW)
#define K0_FM (L9_FM | ippCPUID_AVX512F | ippCPUID_AVX512CD | ippCPUID_AVX512VL | ippCPUID_AVX512BW | ippCPUID_AVX512DQ | ippAVX512_ENABLEDBYOS)
/* clang-format on */

#else
#error undefined architecture
#endif

#define PX_MSK    (0)
#define MMX_MSK   (ippCPUID_MMX)
#define SSE_MSK   (MMX_MSK | ippCPUID_SSE)
#define SSE2_MSK  (SSE_MSK | ippCPUID_SSE2)
#define SSE3_MSK  (SSE2_MSK | ippCPUID_SSE3)
#define SSSE3_MSK (SSE3_MSK | ippCPUID_SSSE3)
#define ATOM_MSK  (SSE3_MSK | ippCPUID_SSSE3 | ippCPUID_MOVBE)
#define SSE41_MSK (SSSE3_MSK | ippCPUID_SSE41)
#define SSE42_MSK (SSE41_MSK | ippCPUID_SSE42)
#define AVX_MSK   (SSE42_MSK | ippCPUID_AVX)
#define AVX2_MSK  (AVX_MSK | ippCPUID_AVX2)
/* clang-format off */
#define AVX3X_MSK (AVX2_MSK | ippCPUID_AVX512F | ippCPUID_AVX512CD | ippCPUID_AVX512VL | ippCPUID_AVX512BW | ippCPUID_AVX512DQ)
#define AVX3M_MSK (AVX2_MSK | ippCPUID_AVX512F | ippCPUID_AVX512CD | ippCPUID_AVX512PF | ippCPUID_AVX512ER)
#define AVX3I_MSK (AVX3X_MSK | ippCPUID_SHA | ippCPUID_AVX512VBMI | ippCPUID_AVX512VBMI2 | ippCPUID_AVX512IFMA | ippCPUID_AVX512GFNI | ippCPUID_AVX512VAES | ippCPUID_AVX512VCLMUL)
/* clang-format on */
#if defined(_ARCH_IA32)
enum lib_enum { LIB_P8 = 0, LIB_H9 = 1, LIB_NOMORE };
#define LIB_PX LIB_P8
#elif defined(_ARCH_EM64T)
enum lib_enum { LIB_Y8 = 0, LIB_L9 = 1, LIB_K0 = 2, LIB_K1 = 3, LIB_NOMORE };
#define LIB_PX LIB_Y8
#else
#error "lib_enum isn't defined!"
#endif

#if defined(_ARCH_IA32)
#define LIB_MMX   LIB_P8
#define LIB_SSE42 LIB_P8
#define LIB_AVX2  LIB_H9

/* no ia32 library for Intel® Xeon® Phi(TM) processor (formerly Knight Landing) */
#define LIB_AVX3M LIB_H9
#define LIB_AVX3X LIB_H9 /* no ia32 library for Intel® Xeon® processor (formerly Skylake) */
#define LIB_AVX3I LIB_H9 /* no ia32 library for Intel® Xeon® processor (formerly Icelake) */
#elif defined(_ARCH_EM64T)
#define LIB_MMX   LIB_Y8
#define LIB_SSE42 LIB_Y8
#define LIB_AVX   LIB_E9
#define LIB_AVX2  LIB_L9
#define LIB_AVX3X LIB_K0
#define LIB_AVX3I LIB_K1
#endif

//gres: #if defined( _IPP_DYNAMIC )
#if defined(_PCS)
#if defined(_ARCH_IA32)

/* Describe Intel CPUs and libraries */
typedef enum { CPU_P8 = 0, CPU_H9, CPU_NOMORE } cpu_enum;
typedef enum { DLL_P8 = 0, DLL_H9, DLL_NOMORE } dll_enum;

/* New cpu can use some libraries for old cpu */
/* clang-format off */
static const dll_enum dllUsage[][DLL_NOMORE + 1] = {
         /*  DLL_H9, DLL_P8, DLL_NOMORE */
/*CPU_P8*/ {         DLL_P8, DLL_NOMORE },
/*CPU_H9*/ { DLL_H9, DLL_P8, DLL_NOMORE }
};
/* clang-format on */

#elif defined(_ARCH_EM64T)
/* Describe Intel CPUs and libraries */
typedef enum { CPU_Y8 = 0, CPU_L9, CPU_K0, CPU_K1, CPU_NOMORE } cpu_enum;
typedef enum { DLL_Y8 = 0, DLL_L9, DLL_K0, DLL_K1, DLL_NOMORE } dll_enum;

/* New cpu can use some libraries for old cpu */
/* clang-format off */
static const dll_enum dllUsage[][DLL_NOMORE + 1] = {
/*           DLL_K1, DLL_K0, DLL_L9, DLL_Y8,  DLL_NOMORE */
/*CPU_Y8*/ {                          DLL_Y8,  DLL_NOMORE },
/*CPU_L9*/ {                  DLL_L9, DLL_Y8,  DLL_NOMORE },
/*CPU_K0*/ {         DLL_K0,  DLL_L9, DLL_Y8,  DLL_NOMORE },
/*CPU_K1*/ { DLL_K1, DLL_K0,  DLL_L9, DLL_Y8,  DLL_NOMORE }
};
/* clang-format on */

#endif

#if defined(_PCS)

/* Names of the Intel libraries which can be loaded */
#if defined(WIN32)
static const _TCHAR* dllNames[DLL_NOMORE] = { _T(IPP_LIB_PREFIX()) _T("p8")
                                                                   _T(".dll"),
                                              _T(IPP_LIB_PREFIX()) _T("h9")
                                                                   _T(".dll") };
#elif defined(LINUX32)
static const _TCHAR* dllNames[DLL_NOMORE] = { _T("lib") _T(IPP_LIB_PREFIX()) _T("p8.so"),
                                              _T("lib") _T(IPP_LIB_PREFIX()) _T("h9.so") };
#elif defined(WIN32E)
static const _TCHAR* dllNames[DLL_NOMORE] = { _T(IPP_LIB_PREFIX()) _T("y8")
                                                                   _T(".dll"),
                                              _T(IPP_LIB_PREFIX()) _T("l9")
                                                                   _T(".dll"),
                                              _T(IPP_LIB_PREFIX()) _T("k0")
                                                                   _T(".dll"),
                                              _T(IPP_LIB_PREFIX()) _T("k1")
                                                                   _T(".dll") };
#elif defined(LINUX32E)
static const _TCHAR* dllNames[DLL_NOMORE] = { _T("lib") _T(IPP_LIB_PREFIX()) _T("y8.so"),
                                              _T("lib") _T(IPP_LIB_PREFIX()) _T("l9.so"),
                                              _T("lib") _T(IPP_LIB_PREFIX()) _T("k0.so"),
                                              _T("lib") _T(IPP_LIB_PREFIX()) _T("k1.so") };
#endif

#endif /* _PCS */

#else  /*_IPP_DYNAMIC */


#endif


#if defined(__cplusplus)
}
#endif

#endif /* __DISPATCHER_H__ */
