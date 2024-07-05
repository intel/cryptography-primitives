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

#ifndef INTERNAL_DEFS_H
#define INTERNAL_DEFS_H

/* externals */
#undef EXTERN_C

#ifdef __cplusplus
   #define EXTERN_C extern "C"
#else
   #define EXTERN_C
#endif

#if !defined( MBXAPI )
   #define MBXAPI( type,name,arg ) EXTERN_C type MBX_CALL name arg;
#endif

#if defined (_MSC_VER)
  #define MBX_CDECL    __cdecl
#elif (defined (__INTEL_COMPILER) || defined (__INTEL_LLVM_COMPILER) || defined (__GNUC__ ) || defined (__clang__)) && defined (_ARCH_IA32)
  #define MBX_CDECL    __attribute((cdecl))
#else
  #define MBX_CDECL
#endif

#if defined( _WIN32 ) || defined( _WIN64 )
  #define MBX_STDCALL  __stdcall
  #define MBX_CALL     MBX_STDCALL
#else
  #define MBX_STDCALL
  #define MBX_CALL     MBX_CDECL
#endif

#define _MBX_L9 512
#define _MBX_K1 4096

#if defined( _L9 ) || (_K1)
   #include "ec_nistp256_cpuspc.h"
   #include "ec_nistp384_cpuspc.h"
   #include "ec_nistp521_cpuspc.h"
   #include "ec_sm2_cpuspc.h"
   #include "ed25519_cpuspc.h"
   #include "exp_cpuspc.h"
   #include "rsa_cpuspc.h"
   #include "sm3_cpuspc.h"
   #include "sm4_ccm_cpuspc.h"
   #include "sm4_cpuspc.h"
   #include "sm4_gcm_cpuspc.h"
   #include "x25519_cpuspc.h"
#endif

#if defined( _L9 ) /* Intel® AVX2 */
   #define OWNAPI(name) l9_##name
   #define _MBX _MBX_L9
#elif defined( _K1 )
   #define OWNAPI(name) k1_##name
   #define _MBX _MBX_K1
#endif

#endif /* INTERNAL_DEFS_H */
