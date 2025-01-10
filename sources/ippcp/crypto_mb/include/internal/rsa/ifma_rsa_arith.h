/*************************************************************************
 * Copyright (C) 2019-2024 Intel Corporation
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

#ifndef IFMA_RSA_ARITH_H
#define IFMA_RSA_ARITH_H

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#endif

#include <crypto_mb/status.h>
#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>

typedef int64u int64u_x8[8];     // alias   of 8-term vector of int64u each
typedef int64u (*pint64u_x8)[8]; // pointer to 8-term vector of int64u each
typedef int64u int64u_x4[4];     // alias   of 4-term vector of int64u each
typedef int64u (*pint64u_x4)[4]; // pointer to 4-term vector of int64u each

/* fixed size of RSA */
#define RSA_1K (1024)
#define RSA_2K (2 * RSA_1K)
#define RSA_3K (3 * RSA_1K)
#define RSA_4K (4 * RSA_1K)

#ifndef NUMBER_OF_DIGITS
#define NUMBER_OF_DIGITS(bitsize, digsize) (((bitsize) + (digsize)-1) / (digsize))
#endif
#define MULTIPLE_OF(x, factor) ((x) + (((factor) - ((x) % (factor))) % (factor)))

#define redLen2K ((RSA_1K + (DIGIT_SIZE - 1)) / DIGIT_SIZE)       // 20
#define redLen3K (((RSA_3K / 2) + (DIGIT_SIZE - 1)) / DIGIT_SIZE) // 30
#define redLen4K ((RSA_2K + (DIGIT_SIZE - 1)) / DIGIT_SIZE)       // 40

#if (_MBX >= _MBX_K1)

// ============ Multi-Buffer required functions ============
EXTERN_C void ifma_extract_amm52x20_mb8(int64u* out_mb8,
                                        const int64u* inpA_mb8,
                                        int64u MulTbl[][redLen2K][8],
                                        const int64u Idx[8],
                                        const int64u* inpM_mb8,
                                        const int64u* k0_mb8);

// Multiplication
EXTERN_C void ifma_amm52x10_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);
EXTERN_C void ifma_amm52x20_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);
EXTERN_C void ifma_amm52x60_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);
EXTERN_C void ifma_amm52x40_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);
EXTERN_C void ifma_amm52x30_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);
EXTERN_C void ifma_amm52x79_mb8(int64u* out_mb8,
                                const int64u* inpA_mb8,
                                const int64u* inpB_mb8,
                                const int64u* inpM_mb8,
                                const int64u* k0_mb8);

// New functions for almost half montgomery
EXTERN_C void ifma_ahmm52x20_mb8(int64u* out_mb8,
                                 const int64u* inpA_mb8,
                                 const int64u* inpB_mb8,
                                 const int64u* inpBx_mb8,
                                 const int64u* inpM_mb8,
                                 const int64u* k0_mb8);
EXTERN_C void ifma_ahmr52x20_mb8(int64u* out_mb,
                                 const int64u* inpA_mb,
                                 int64u* inpM_mb,
                                 const int64u* k0_mb);

// Diagonal sqr
EXTERN_C void AMS52x10_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);
EXTERN_C void AMS5x52x10_diagonal_mb8(int64u* out_mb8,
                                      const int64u* inpA_mb8,
                                      const int64u* inpM_mb8,
                                      const int64u* k0_mb8);

EXTERN_C void AMS52x20_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);
EXTERN_C void AMS4x52x20_diagonal_stitched_with_extract_mb8(int64u* out_mb8,
                                                            U64* mulb,
                                                            U64* mulbx,
                                                            const int64u* inpA_mb8,
                                                            const int64u* inpM_mb8,
                                                            const int64u* k0_mb8,
                                                            int64u MulTbl[][redLen2K][8],
                                                            int64u MulTblx[][redLen2K][8],
                                                            const int64u Idx[8]);
EXTERN_C void AMS5x52x20_diagonal_mb8(int64u* out_mb8,
                                      const int64u* inpA_mb8,
                                      const int64u* inpM_mb8,
                                      const int64u* k0_mb8);

EXTERN_C void AMS52x40_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);
EXTERN_C void AMS5x52x40_diagonal_mb8(int64u* out_mb8,
                                      const int64u* inpA_mb8,
                                      const int64u* inpM_mb8,
                                      const int64u* k0_mb8);

EXTERN_C void AMS52x30_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);
EXTERN_C void AMS52x60_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);
EXTERN_C void AMS52x79_diagonal_mb8(int64u* out_mb8,
                                    const int64u* inpA_mb8,
                                    const int64u* inpM_mb8,
                                    const int64u* k0_mb8);

// clear/copy mb8 buffer
EXTERN_C void zero_mb8(int64u (*redOut)[8], int len);
EXTERN_C void copy_mb8(int64u out[][8], const int64u inp[][8], int len);

// other 2^52 radix arith functions
EXTERN_C void ifma_montFactor52_mb8(int64u k0_mb8[8], const int64u m0_mb8[8]);

EXTERN_C void ifma_modsub52x10_mb8(int64u res[][8],
                                   const int64u inpA[][8],
                                   const int64u inpB[][8],
                                   const int64u inpM[][8]);
EXTERN_C void ifma_modsub52x20_mb8(int64u res[][8],
                                   const int64u inpA[][8],
                                   const int64u inpB[][8],
                                   const int64u inpM[][8]);
EXTERN_C void ifma_modsub52x30_mb8(int64u res[][8],
                                   const int64u inpA[][8],
                                   const int64u inpB[][8],
                                   const int64u inpM[][8]);
EXTERN_C void ifma_modsub52x40_mb8(int64u res[][8],
                                   const int64u inpA[][8],
                                   const int64u inpB[][8],
                                   const int64u inpM[][8]);

EXTERN_C void ifma_addmul52x10_mb8(int64u res[][8], const int64u inpA[][8], const int64u inpB[][8]);
EXTERN_C void ifma_addmul52x20_mb8(int64u res[][8], const int64u inpA[][8], const int64u inpB[][8]);
EXTERN_C void ifma_addmul52x30_mb8(int64u res[][8], const int64u inpA[][8], const int64u inpB[][8]);
EXTERN_C void ifma_addmul52x40_mb8(int64u res[][8], const int64u inpA[][8], const int64u inpB[][8]);

EXTERN_C void ifma_amred52x10_mb8(int64u res[][8],
                                  const int64u inpA[][8],
                                  const int64u inpM[][8],
                                  const int64u k0[8]);
EXTERN_C void ifma_amred52x20_mb8(int64u res[][8],
                                  const int64u inpA[][8],
                                  const int64u inpM[][8],
                                  const int64u k0[8]);
EXTERN_C void ifma_amred52x30_mb8(int64u res[][8],
                                  const int64u inpA[][8],
                                  const int64u inpM[][8],
                                  const int64u k0[8]);
EXTERN_C void ifma_amred52x40_mb8(int64u res[][8],
                                  const int64u inpA[][8],
                                  const int64u inpM[][8],
                                  const int64u k0[8]);

EXTERN_C void ifma_mreduce52x_mb8(int64u pX[][8], int nsX, int64u pM[][8], int nsM);
EXTERN_C void ifma_montRR52x_mb8(int64u pRR[][8], int64u pM[][8], int convBitLen);

// exponentiations
EXTERN_C void EXP52x10_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

EXTERN_C void EXP52x20_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

EXTERN_C void EXP52x40_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

EXTERN_C void EXP52x60_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

EXTERN_C void EXP52x30_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

EXTERN_C void EXP52x79_mb8(int64u out[][8],
                           const int64u base[][8],
                           const int64u exponent[][8],
                           const int64u modulus[][8],
                           const int64u toMont[][8],
                           const int64u k0_mb8[8],
                           int64u work_buffer[][8]);

// exponentiations (fixed short exponent ==65537)
EXTERN_C void EXP52x20_pub65537_mb8(int64u out[][8],
                                    const int64u base[][8],
                                    const int64u modulus[][8],
                                    const int64u toMont[][8],
                                    const int64u k0[8],
                                    int64u work_buffer[][8]);


EXTERN_C void EXP52x40_pub65537_mb8(int64u out[][8],
                                    const int64u base[][8],
                                    const int64u modulus[][8],
                                    const int64u toMont[][8],
                                    const int64u k0[8],
                                    int64u work_buffer[][8]);

EXTERN_C void EXP52x60_pub65537_mb8(int64u out[][8],
                                    const int64u base[][8],
                                    const int64u modulus[][8],
                                    const int64u toMont[][8],
                                    const int64u k0[8],
                                    int64u work_buffer[][8]);

EXTERN_C void EXP52x79_pub65537_mb8(int64u out[][8],
                                    const int64u base[][8],
                                    const int64u modulus[][8],
                                    const int64u toMont[][8],
                                    const int64u k0[8],
                                    int64u work_buffer[][8]);


mbx_status MB_FUNC_NAME(internal_avx512_x25519_)(int8u* const pa_shared_key[8],
                                                 const int8u* const pa_private_key[8],
                                                 const int8u* const pa_public_key[8]);

mbx_status MB_FUNC_NAME(internal_avx512_x25519_public_key_)(int8u* const pa_public_key[8],
                                                            const int8u* const pa_private_key[8]);

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

// ============ Multi-Buffer required functions ============
EXTERN_C void ifma_extract_amm52x20_mb4(int64u* out_mb4,
                                        const int64u* inpA_mb4,
                                        int64u MulTbl[][redLen2K][4],
                                        const int64u Idx[4],
                                        const int64u* inpM_mb4,
                                        const int64u* k0_mb4);

// Multiplication
EXTERN_C void ifma_amm52x10_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);
EXTERN_C void ifma_amm52x20_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);
EXTERN_C void ifma_amm52x60_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);
EXTERN_C void ifma_amm52x40_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);
EXTERN_C void ifma_amm52x30_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);
EXTERN_C void ifma_amm52x79_mb4(int64u* out_mb4,
                                const int64u* inpA_mb4,
                                const int64u* inpB_mb4,
                                const int64u* inpM_mb4,
                                const int64u* k0_mb4);

// New functions for almost half montgomery
EXTERN_C void ifma_ahmm52x20_mb4(int64u* out_mb4,
                                 const int64u* inpA_mb4,
                                 const int64u* inpB_mb4,
                                 const int64u* inpBx_mb4,
                                 const int64u* inpM_mb4,
                                 const int64u* k0_mb4);
EXTERN_C void ifma_ahmm52x30_mb4(int64u* out_mb4,
                                 const int64u* inpA_mb4,
                                 const int64u* inpB_mb4,
                                 const int64u* inpBx_mb4,
                                 const int64u* inpM_mb4,
                                 const int64u* k0_mb4);
EXTERN_C void ifma_ahmm52x40_mb4(int64u* out_mb4,
                                 const int64u* inpA_mb4,
                                 const int64u* inpB_mb4,
                                 const int64u* inpBx_mb4,
                                 const int64u* inpM_mb4,
                                 const int64u* k0_mb4);

EXTERN_C void ifma_ahmr52x20_mb4(int64u* out_mb,
                                 const int64u* inpA_mb,
                                 const int64u* inpM_mb,
                                 const int64u* k0_mb);
EXTERN_C void ifma_ahmr52x30_mb4(int64u* out_mb,
                                 const int64u* inpA_mb,
                                 const int64u* inpM_mb,
                                 const int64u* k0_mb);
EXTERN_C void ifma_ahmr52x40_mb4(int64u* out_mb,
                                 const int64u* inpA_mb,
                                 const int64u* inpM_mb,
                                 const int64u* k0_mb);

// Diagonal sqr
EXTERN_C void AMS52x10_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);
EXTERN_C void AMS52x20_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);
EXTERN_C void AMS52x30_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);
EXTERN_C void AMS52x40_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);
EXTERN_C void AMS52x60_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);
EXTERN_C void AMS52x79_diagonal_mb4(int64u* out_mb4,
                                    const int64u* inpA_mb4,
                                    const int64u* inpM_mb4,
                                    const int64u* k0_mb4);

EXTERN_C void AMS4x52x20_diagonal_stitched_with_extract_mb4(int64u* out_mb4,
                                                            U64* mulb,
                                                            U64* mulbx,
                                                            const int64u* inpA_mb4,
                                                            const int64u* inpM_mb4,
                                                            const int64u* k0_mb4,
                                                            int64u MulTbl[][redLen2K][4],
                                                            int64u MulTblx[][redLen2K][4],
                                                            const __m256i idx);
EXTERN_C void AMS4x52x30_diagonal_stitched_with_extract_mb4(int64u* out_mb4,
                                                            U64* mulb,
                                                            U64* mulbx,
                                                            const int64u* inpA_mb4,
                                                            const int64u* inpM_mb4,
                                                            const int64u* k0_mb4,
                                                            int64u MulTbl[][redLen3K][4],
                                                            int64u MulTblx[][redLen3K][4],
                                                            const __m256i idx);
EXTERN_C void AMS4x52x40_diagonal_stitched_with_extract_mb4(int64u* out_mb4,
                                                            U64* mulb,
                                                            U64* mulbx,
                                                            const int64u* inpA_mb4,
                                                            const int64u* inpM_mb4,
                                                            const int64u* k0_mb4,
                                                            int64u MulTbl[][redLen4K][4],
                                                            int64u MulTblx[][redLen4K][4],
                                                            const __m256i idx);

EXTERN_C void AMS5x52x10_diagonal_mb4(int64u* out_mb4,
                                      const int64u* inpA_mb4,
                                      const int64u* inpM_mb4,
                                      const int64u* k0_mb4);
EXTERN_C void AMS5x52x20_diagonal_mb4(int64u* out_mb4,
                                      const int64u* inpA_mb4,
                                      const int64u* inpM_mb4,
                                      const int64u* k0_mb4);
EXTERN_C void AMS5x52x40_diagonal_mb4(int64u* out_mb4,
                                      const int64u* inpA_mb4,
                                      const int64u* inpM_mb4,
                                      const int64u* k0_mb4);

// clear/copy mb8 buffer
EXTERN_C void zero_mb4(void* redOut, int len);
EXTERN_C void copy_mb4(int64u out[][4], const int64u inp[][4], int len);

// other 2^52 radix arith functions
EXTERN_C void ifma_montFactor52_mb4(int64u k0_mb4[4], const int64u m0_mb4[4]);

EXTERN_C void ifma_modsub52x10_mb4(int64u res[][4],
                                   const int64u inpA[][4],
                                   const int64u inpB[][4],
                                   const int64u inpM[][4]);
EXTERN_C void ifma_modsub52x20_mb4(int64u res[][4],
                                   const int64u inpA[][4],
                                   const int64u inpB[][4],
                                   const int64u inpM[][4]);
EXTERN_C void ifma_modsub52x30_mb4(int64u res[][4],
                                   const int64u inpA[][4],
                                   const int64u inpB[][4],
                                   const int64u inpM[][4]);
EXTERN_C void ifma_modsub52x40_mb4(int64u res[][4],
                                   const int64u inpA[][4],
                                   const int64u inpB[][4],
                                   const int64u inpM[][4]);

EXTERN_C void ifma_addmul52x10_mb4(int64u res[][4], const int64u inpA[][4], const int64u inpB[][4]);
EXTERN_C void ifma_addmul52x20_mb4(int64u res[][4], const int64u inpA[][4], const int64u inpB[][4]);
EXTERN_C void ifma_addmul52x30_mb4(int64u res[][4], const int64u inpA[][4], const int64u inpB[][4]);
EXTERN_C void ifma_addmul52x40_mb4(int64u res[][4], const int64u inpA[][4], const int64u inpB[][4]);

EXTERN_C void ifma_amred52x10_mb4(int64u res[][4],
                                  const int64u inpA[][4],
                                  const int64u inpM[][4],
                                  const int64u k0[4]);
EXTERN_C void ifma_amred52x20_mb4(int64u res[][4],
                                  const int64u inpA[][4],
                                  const int64u inpM[][4],
                                  const int64u k0[4]);
EXTERN_C void ifma_amred52x30_mb4(int64u res[][4],
                                  const int64u inpA[][4],
                                  const int64u inpM[][4],
                                  const int64u k0[4]);
EXTERN_C void ifma_amred52x40_mb4(int64u res[][4],
                                  const int64u inpA[][4],
                                  const int64u inpM[][4],
                                  const int64u k0[4]);

EXTERN_C void ifma_mreduce52x_mb4(int64u pX[][4], int nsX, int64u pM[][4], int nsM);
EXTERN_C void ifma_montRR52x_mb4(int64u pRR[][4], int64u pM[][4], int convBitLen);

// exponentiations
EXTERN_C void EXP52x10_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

EXTERN_C void EXP52x20_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

EXTERN_C void EXP52x40_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

EXTERN_C void EXP52x60_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

EXTERN_C void EXP52x30_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

EXTERN_C void EXP52x79_mb4(int64u out[][4],
                           const int64u base[][4],
                           const int64u exponent[][4],
                           const int64u modulus[][4],
                           const int64u toMont[][4],
                           const int64u k0_mb4[4],
                           int64u work_buffer[][4]);

// exponentiations (fixed short exponent ==65537)
EXTERN_C void EXP52x20_pub65537_mb4(int64u out[][4],
                                    const int64u base[][4],
                                    const int64u modulus[][4],
                                    const int64u toMont[][4],
                                    const int64u k0[4],
                                    int64u work_buffer[][4]);


EXTERN_C void EXP52x40_pub65537_mb4(int64u out[][4],
                                    const int64u base[][4],
                                    const int64u modulus[][4],
                                    const int64u toMont[][4],
                                    const int64u k0[4],
                                    int64u work_buffer[][4]);

EXTERN_C void EXP52x60_pub65537_mb4(int64u out[][4],
                                    const int64u base[][4],
                                    const int64u modulus[][4],
                                    const int64u toMont[][4],
                                    const int64u k0[4],
                                    int64u work_buffer[][4]);

EXTERN_C void EXP52x79_pub65537_mb4(int64u out[][4],
                                    const int64u base[][4],
                                    const int64u modulus[][4],
                                    const int64u toMont[][4],
                                    const int64u k0[4],
                                    int64u work_buffer[][4]);


mbx_status MB_FUNC_NAME(internal_avx512_x25519_)(int8u* const pa_shared_key[4],
                                                 const int8u* const pa_private_key[4],
                                                 const int8u* const pa_public_key[4]);

mbx_status MB_FUNC_NAME(internal_avx512_x25519_public_key_)(int8u* const pa_public_key[4],
                                                            const int8u* const pa_private_key[4]);

EXTERN_C void ifma_normalize_52xN_mb4(void* out_mb4, const void* in_mb4, const int N);
EXTERN_C void ifma_normalize_clear_52xN_mb4(void* out_mb4, const void* in_mb4, const int N);
EXTERN_C void ifma_normalize_ams_52xN_mb4(void* out_mb4, const void* in_mb4, const int N);

#endif /* #if (_MBX >= _MBX_K1) */

#endif /* _IFMA_INTERNAL_H_ */
