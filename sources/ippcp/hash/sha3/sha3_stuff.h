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

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     SHA3 Family General Functionality
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcptool.h"
#include "hash/pcphash.h"

#if !defined(_SHA3_STUFF_H)
#define _SHA3_STUFF_H

#define KECCAK_ROUNDS 24

#define cp_keccak_kernel OWNAPI(cp_keccak_kernel)
IPP_OWN_DECL(void, cp_keccak_kernel, (Ipp64u state[25]))

#define cpUpdateSHA3 OWNAPI(cpUpdateSHA3)
IPP_OWN_DECL(void, cpUpdateSHA3, (void* uniHash, const Ipp8u* mblk, int mlen, const void* pParam))

#define cp_sha3_hashInit OWNAPI(cp_sha3_hashInit)
IPP_OWN_DECL(void, cp_sha3_hashInit, (void* pHash))

#define cp_sha3_hashOctString OWNAPI(cp_sha3_hashOctString)
IPP_OWN_DECL(void, cp_sha3_hashOctString, (Ipp8u * pMD, void* pHashVal, const int hashSize))

#if (_IPP32E >= _IPP32E_K0)
/* Single-buffer SHA3 and SHAKE kernels optimized with AVX512VL: K0+ only */

// Hash message
#define cp_SHA3_SHAKE256_HashMessage OWNAPI(cp_SHA3_SHAKE256_HashMessage)
IPP_OWN_DECL(void,
             cp_SHA3_SHAKE256_HashMessage,
             (Ipp8u * output, Ipp64u outlen, const Ipp8u* input, Ipp64u inplen))

// Absorb (Update)
#define cp_SHA3_224_Absorb OWNAPI(cp_SHA3_224_Absorb)
IPP_OWN_DECL(void, cp_SHA3_224_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))
#define cp_SHA3_256_Absorb OWNAPI(cp_SHA3_256_Absorb)
IPP_OWN_DECL(void, cp_SHA3_256_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))
#define cp_SHA3_384_Absorb OWNAPI(cp_SHA3_384_Absorb)
IPP_OWN_DECL(void, cp_SHA3_384_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))
#define cp_SHA3_512_Absorb OWNAPI(cp_SHA3_512_Absorb)
IPP_OWN_DECL(void, cp_SHA3_512_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))
#define cp_SHA3_SHAKE128_Absorb OWNAPI(cp_SHA3_SHAKE128_Absorb)
IPP_OWN_DECL(void, cp_SHA3_SHAKE128_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))
#define cp_SHA3_SHAKE256_Absorb OWNAPI(cp_SHA3_SHAKE256_Absorb)
IPP_OWN_DECL(void, cp_SHA3_SHAKE256_Absorb, (void* state, const Ipp8u* input, Ipp64u inlen))

#endif /* #if (_IPP32E >= _IPP32E_K0) */

#if (_IPP32E >= _IPP32E_L9)
/* Multi-buffer SHAKE128/SHAKE256: 4-way AVX512VL asm on K0+, 4-way AVX2 on L9.
   Both expose the same MB4 API over a caller-owned Ipp8u[STATE_x4_SIZE] buffer.
   The two paths lay that buffer out differently, so its size is ISA-dependent:
     K0+ (asm): 4 x 25 keccak words + one 8-byte capacity slot.
     L9  (AVX2): 25 x __m256i state + 4 x SHAKE128_RATE block scratch + counters. */
#if (_IPP32E == _IPP32E_L9)
#define STATE_x4_SIZE (25 * 32 + 4 * 168 + 64)
#else
#define STATE_x4_SIZE (((25 * 4) + 1) * 8)
#endif

typedef struct {
    /** Internal state. */
    Ipp8u* ctx;
} cpSHA3_SHAKE128Ctx_mb4;

typedef struct {
    /** Internal state. */
    Ipp8u* ctx;
} cpSHA3_SHAKE256Ctx_mb4;

// Init
#define cp_SHA3_SHAKE128_InitMB4 OWNAPI(cp_SHA3_SHAKE128_InitMB4)
IPP_OWN_DECL(void, cp_SHA3_SHAKE128_InitMB4, (cpSHA3_SHAKE128Ctx_mb4 * state))
#define cp_SHA3_SHAKE256_InitMB4 OWNAPI(cp_SHA3_SHAKE256_InitMB4)
IPP_OWN_DECL(void, cp_SHA3_SHAKE256_InitMB4, (cpSHA3_SHAKE256Ctx_mb4 * state))


// Absorb (Update)
#define cp_SHA3_SHAKE128_AbsorbMB4 OWNAPI(cp_SHA3_SHAKE128_AbsorbMB4)
IPP_OWN_DECL(void,
             cp_SHA3_SHAKE128_AbsorbMB4,
             (cpSHA3_SHAKE128Ctx_mb4 * state,
              const Ipp8u* in0,
              const Ipp8u* in1,
              const Ipp8u* in2,
              const Ipp8u* in3,
              Ipp64u inlen))
#define cp_SHA3_SHAKE256_AbsorbMB4 OWNAPI(cp_SHA3_SHAKE256_AbsorbMB4)
IPP_OWN_DECL(void,
             cp_SHA3_SHAKE256_AbsorbMB4,
             (cpSHA3_SHAKE256Ctx_mb4 * state,
              const Ipp8u* in0,
              const Ipp8u* in1,
              const Ipp8u* in2,
              const Ipp8u* in3,
              Ipp64u inlen))

// Finalize
#define cp_SHA3_SHAKE128_FinalizeMB4 OWNAPI(cp_SHA3_SHAKE128_FinalizeMB4)
IPP_OWN_DECL(void, cp_SHA3_SHAKE128_FinalizeMB4, (cpSHA3_SHAKE128Ctx_mb4 * state))
#define cp_SHA3_SHAKE256_FinalizeMB4 OWNAPI(cp_SHA3_SHAKE256_FinalizeMB4)
IPP_OWN_DECL(void, cp_SHA3_SHAKE256_FinalizeMB4, (cpSHA3_SHAKE256Ctx_mb4 * state))

// Squeeze
#define cp_SHA3_SHAKE128_SqueezeMB4 OWNAPI(cp_SHA3_SHAKE128_SqueezeMB4)
IPP_OWN_DECL(void,
             cp_SHA3_SHAKE128_SqueezeMB4,
             (Ipp8u * out0,
              Ipp8u* out1,
              Ipp8u* out2,
              Ipp8u* out3,
              Ipp64u outlen,
              cpSHA3_SHAKE128Ctx_mb4* state))
#define cp_SHA3_SHAKE256_SqueezeMB4 OWNAPI(cp_SHA3_SHAKE256_SqueezeMB4)
IPP_OWN_DECL(void,
             cp_SHA3_SHAKE256_SqueezeMB4,
             (Ipp8u * out0,
              Ipp8u* out1,
              Ipp8u* out2,
              Ipp8u* out3,
              Ipp64u outlen,
              cpSHA3_SHAKE256Ctx_mb4* state))
#endif /* #if (_IPP32E >= _IPP32E_L9) */

#endif /* #if !defined(_SHA3_STUFF_H) */
