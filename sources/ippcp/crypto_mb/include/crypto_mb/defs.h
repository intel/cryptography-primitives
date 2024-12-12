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

#ifndef DEFS_H
#define DEFS_H

/* externals */
#undef EXTERN_C

/* clang-format off */
#ifdef __cplusplus
    #define EXTERN_C extern "C"
#else
    #define EXTERN_C
#endif

#if !defined(MBXAPI)
    #define MBXAPI(type, name, arg) EXTERN_C type MBX_CALL name arg;
#endif

#if defined(_MSC_VER)
    #define MBX_CDECL __cdecl
#elif ((defined(__INTEL_COMPILER) || defined(__INTEL_LLVM_COMPILER) || defined(__GNUC__) || \
       defined(__clang__)) && defined(_ARCH_IA32))
    #define MBX_CDECL __attribute((cdecl))
#else
    #define MBX_CDECL
#endif

#if defined(_WIN32) || defined(_WIN64)
    #define MBX_STDCALL __stdcall
    #define MBX_CALL    MBX_STDCALL
#else
    #define MBX_STDCALL
    #define MBX_CALL MBX_CDECL
#endif

/* data types */
typedef unsigned char int8u;
typedef unsigned short int16u;
typedef unsigned int int32u;
typedef unsigned long long int64u;

#ifndef NULL
    #define NULL ((void*)0)
#endif

/* alignment & inline */
#if defined(__GNUC__)
   #if !defined(__ALIGN64)
      #define __ALIGN64 __attribute__((aligned(64)))
   #endif

   #if !defined(__MBX_INLINE)
      #define __MBX_INLINE static __inline__ __attribute__((always_inline))
   #endif

   #if !defined(__NOINLINE)
      #define __NOINLINE __attribute__((noinline))
   #endif
#else /* __GNUC__ */
   #if !defined(__ALIGN64)
      #define __ALIGN64 __declspec(align(64))
   #endif

   #if !defined(__MBX_INLINE)
      #define __MBX_INLINE static __forceinline
   #endif

   #if !defined(__NOINLINE)
      #define __NOINLINE __declspec(noinline)
   #endif
#endif /* __GNUC__ */

#if !defined(MBX_ZEROING_FUNC_ATTRIBUTES)
    #if defined(_MSC_VER) && !defined(__clang__)
        #define MBX_ZEROING_FUNC_ATTRIBUTES __declspec(noinline)
    #elif defined(__GNUC__) && !defined(__clang__)
        #define MBX_ZEROING_FUNC_ATTRIBUTES __attribute__((noinline))
    #elif defined(__clang__) || defined(__INTEL_LLVM_COMPILER)
        #define MBX_ZEROING_FUNC_ATTRIBUTES __attribute__((noinline)) __attribute((optnone))
    #else
        #define MBX_ZEROING_FUNC_ATTRIBUTES
    #endif
#endif /* MBX_ZEROING_FUNC_ATTRIBUTES */
/* clang-format on */

#define MBX_UNREFERENCED_PARAMETER(p) (void)(p)

#endif /* DEFS_H */
