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

#ifndef _IPPCP_ML_KEM_H_
#define _IPPCP_ML_KEM_H_

#include "owndefs.h"
#include "pcptool.h"

typedef struct {
    Ipp8u* pStorageData;   // pointer to the actual memory (placed in the working buffers)
    Ipp64s bytesCapacity;  // bytesize of the storage for current operation
    Ipp64s bytesUsed;      // number of used bytes in the storage for current operation
    Ipp64s keyGenCapacity; // total bytesize of the storage for keyGen operation
    Ipp64s encapsCapacity; // total bytesize of the storage for encaps operation
    Ipp64s decapsCapacity; // total bytesize of the storage for decaps operation
} _cpMLKEMStorage;

#define POLY_VALUE_T Ipp16s
#define STORAGE_T    _cpMLKEMStorage

#include "stateless_pqc/common.h"

typedef struct {
    Ipp16u n;
    Ipp16u q;
    Ipp8u k;
    Ipp8u eta1;
    Ipp8u eta2;
    Ipp16u d_u;
    Ipp8u d_v;
} _cpMLKEMParams;

struct _cpMLKEMState {
    _cpMLKEMParams params;   // ML KEM parameters
    Ipp32u idCtx;            // state's Id
    _cpMLKEMStorage storage; // management of the temporary data storage(variables, hash states)
    Ipp16u* pA;              // pointer to pre-calculated A matrix, stored at the end of the state
    /* Extra memory is allocated right after the state by ippsMLKEM_GetSize()
       to store data useful for the algorithm's optimization */
};

/*
 * Stuff enumerator used to conditionally apply NTT transformation
 * to a generated vector
 */
typedef enum { nttTransform, noNttTransform } nttTransformFlag;

/*
 * Stuff enumerator used in cp_matrixAGen() to conditionally generate
 * transposed matrix A
 */
typedef enum { matrixAOrigin, matrixATransposed } matrixAGenType;

/* State ID set\check helpers */
#define CP_ML_KEM_SET_ID(pCtx)   ((pCtx)->idCtx = (Ipp32u)idCtxMLKEM ^ (Ipp32u)IPP_UINT_PTR(pCtx))
#define CP_ML_KEM_VALID_ID(pCtx) ((((pCtx)->idCtx) ^ (Ipp32u)IPP_UINT_PTR(pCtx)) == idCtxMLKEM)

/* ML-KEM constants */
#define CP_ML_KEM_Q            (3329)
#define CP_ML_KEM_N            CP_ML_N
#define CP_ML_KEM_ETA2         (2)
#define CP_ML_KEM_ETA_MAX      (3)
#define CP_RAND_DATA_BYTES     (32)
#define CP_SHARED_SECRET_BYTES (32)

#define CP_ML_KEM_ALIGNMENT CP_ML_ALIGNMENT

#define CP_ML_KEM_NUM_BUFFERS (4)

/* Matrix A access helper */
#define CP_MATRIX_A_GET_I_J(MATRIX_I_J, IDX_I, IDX_J) \
    (&(MATRIX_I_J)[(IDX_I) * mlkemCtx->params.k + (IDX_J)])

// Memory optimized implementation is only used for the old platforms
#ifndef CP_ML_KEM_MEMORY_OPTIMIZED
#if (_IPP32E >= _IPP32E_K0)
#define CP_ML_KEM_MEMORY_OPTIMIZED (0)
#else
#define CP_ML_KEM_MEMORY_OPTIMIZED (1)
#endif /* #if (_IPP32E >= _IPP32E_K0) */
#endif /* #ifndef CP_ML_KEM_MEMORY_OPTIMIZED */

//-------------------------------//
//      Internal data types
//-------------------------------//

/* Polynomial of 256 elements of Ipp16s */
typedef IppPoly Ipp16sPoly;

//-------------------------------//
//        Stuff functions
//-------------------------------//

#define CP_ML_KEM_MONT_R          (65536)
#define CP_ML_KEM_MONT_QINV_MOD_R (62209) // q^(-1) mod R
#define CP_ML_KEM_MONT_R2_MOD_Q   (1353)

IPPCP_INLINE Ipp16s cp_MontReduce(Ipp32s x)
{
    Ipp16s m = (Ipp16s)((Ipp32u)x * (Ipp32u)CP_ML_KEM_MONT_QINV_MOD_R);
    Ipp16s t = (x - (Ipp32s)m * CP_ML_KEM_Q) >> 16;
    return t;
}

// Convert to Montgomery domain: a -> a*R mod q
IPPCP_INLINE void cp_vecToMont(Ipp16sPoly* vec)
{
    for (int i = 0; i < 256; i++) {
        vec->values[i] = cp_MontReduce((Ipp32s)vec->values[i] * CP_ML_KEM_MONT_R2_MOD_Q);
    }
}

/*
// Barrett reduction for fixed n = CP_ML_KEM_Q
//   res = x mod n, where bitsize(x) <= 2*k and bitsize(n) <= k.
//
//   Let k >= ceil(log2(n)) = 13, and base b = 2
//   Pre-computed mu = floor(b^(2*k)/n) = floor(2^26/3329) = 20158
//   1. t = floor(x*mu/b^(2*k))
//   2. t = floor(x*mu/b^(2*k)) * n
//   3. res = x - floor(x*mu/b^(2*k)) * n
//   4. if res >= n then res -= n
//   5. return res
//
// Input:  number to be reduced of maximum size 25 bits
// Output: number in Z_{q}, q = 3329
//
//  Before Barrett processing, input value x is mapped the to the positive values, after which
//      min x = (-(3328*3328)-3328) + (CP_ML_KEM_Q * CP_ML_KEM_Q) -> 3329 (12 bits)
//      max x = (3328*3328+3328) + (CP_ML_KEM_Q * CP_ML_KEM_Q) -> 22161153 (25 bits)
//
*/

#define CP_ML_KEM_BARRETT_K (13)
// b^(2*k) = 2^26
#define CP_ML_KEM_BARRETT_B_POW_2xK ((Ipp32s)1 << (2 * CP_ML_KEM_BARRETT_K))
// Pre-computed mu = floor(b^(2*k)/n)
#define CP_ML_KEM_BARRETT_MU ((Ipp64s)(CP_ML_KEM_BARRETT_B_POW_2xK / CP_ML_KEM_Q))

IPPCP_INLINE Ipp16s cp_mlkemBarrettReduce(Ipp32s x)
{
    // Map x to the positive values
    x += CP_ML_KEM_Q * CP_ML_KEM_Q;

    // 1. t = floor((mu*x)/2^26)
    Ipp32s t = (Ipp32s)((CP_ML_KEM_BARRETT_MU * (Ipp64s)x) >> (2 * CP_ML_KEM_BARRETT_K));
    // 2. t = floor((mu*x)/2^26) * n
    t = t * CP_ML_KEM_Q;
    // 3. res = x - floor((mu*x)/2^26)*n
    Ipp16s res = (Ipp16s)(x - t);
    // 4. if res >= n then res -= n
    res -= CP_ML_KEM_Q;
    res += (res >> 15) & CP_ML_KEM_Q;

    return res;
}

// Barrett reduction with fixed n = CP_ML_KEM_Q for the whole polynomial
IPPCP_INLINE void cp_mlkemPolyBarrettReduce(Ipp16sPoly* vec)
{
    for (int i = 0; i < 256; i++) {
        vec->values[i] = cp_mlkemBarrettReduce((Ipp32s)vec->values[i]);
    }
}

/*
 * Formula 2.3: Adds/Subtracts polynomials f and g and place the result in h.
 *
 * Input:  f, g - polynomials Z_{q}^{256}.
 * Output: h    - polynomial Z_{q}^{256}.
 *
 * Note: the coefficients of the resulting polynomial are reduced:
 *          h[i] = f[i] +/- g[i] (mod CP_ML_KEM_Q)
 */
IPPCP_INLINE void cp_polyAdd(const Ipp16sPoly* f, const Ipp16sPoly* g, Ipp16sPoly* h)
{
    for (Ipp32u i = 0; i < 256; i++) {
        h->values[i] = cp_mlkemBarrettReduce((Ipp32s)(f->values[i] + g->values[i]));
    }
}
IPPCP_INLINE void cp_polySub(const Ipp16sPoly* f, const Ipp16sPoly* g, Ipp16sPoly* h)
{
    for (Ipp32u i = 0; i < 256; i++) {
        h->values[i] = cp_mlkemBarrettReduce((Ipp32s)(f->values[i] - g->values[i]));
    }
}

//-------------------------------//
// Kernel functions declaration
//-------------------------------//
#define cp_Compress OWNAPI(cp_Compress)
IPP_OWN_DECL(IppStatus, cp_Compress, (Ipp16u * out, const Ipp16s in, const Ipp16u d))
#define cp_Decompress OWNAPI(cp_Decompress)
IPP_OWN_DECL(IppStatus, cp_Decompress, (Ipp16u * out, const Ipp16s in, const Ipp16u d))

#define cp_byteEncode OWNAPI(cp_byteEncode)
IPP_OWN_DECL(IppStatus, cp_byteEncode, (Ipp8u * B, const Ipp16u d, const Ipp16sPoly* pPolyF))
#define cp_byteDecode OWNAPI(cp_byteDecode)
IPP_OWN_DECL(IppStatus,
             cp_byteDecode,
             (Ipp16sPoly * pPolyF, const Ipp16u d, const Ipp8u* B, const int bByteSize))

#define cp_samplePolyCBD OWNAPI(cp_samplePolyCBD)
IPP_OWN_DECL(IppStatus, cp_samplePolyCBD, (Ipp16sPoly * pPoly, const Ipp8u* pSeed, const Ipp8u eta))
/* clang-format off */
#define cp_matrixAGen OWNAPI(cp_matrixAGen)
IPP_OWN_DECL(IppStatus, cp_matrixAGen,
            (Ipp16sPoly* matrixA, Ipp8u rho_j_i[34], matrixAGenType matrixType, IppsMLKEMState* mlkemCtx))
/* clang-format on */

#define cp_NTT OWNAPI(cp_NTT)
IPP_OWN_DECL(void, cp_NTT, (Ipp16sPoly * f))
#define cp_inverseNTT OWNAPI(cp_inverseNTT)
IPP_OWN_DECL(void, cp_inverseNTT, (Ipp16sPoly * f))

#define cp_multiplyNTT OWNAPI(cp_multiplyNTT)
IPP_OWN_DECL(void, cp_multiplyNTT, (const Ipp16sPoly* f, const Ipp16sPoly* g, Ipp16sPoly* h))

#define cp_polyGen OWNAPI(cp_polyGen)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_polyGen, (Ipp16sPoly* pOutPoly,
                                     Ipp8u inr_N[CP_RAND_DATA_BYTES + 1],
                                     Ipp8u* N,
                                     const Ipp8u eta,
                                     IppsMLKEMState* mlkemCtx,
                                     nttTransformFlag transformFlag))
/* clang-format on */

#define cp_polyVecGen OWNAPI(cp_polyVecGen)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_polyVecGen, (Ipp16sPoly* pOutPolyVec,
                                        Ipp8u inr_N[CP_RAND_DATA_BYTES + 1],
                                        Ipp8u* N,
                                        const Ipp8u eta,
                                        IppsMLKEMState* mlkemCtx,
                                        nttTransformFlag transformFlag))
/* clang-format on */

//------------------------------------------//
// Level 1(internal) and 2(K-PKE) functions
//------------------------------------------//

#define cp_MLKEMdecaps_internal OWNAPI(cp_MLKEMdecaps_internal)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_MLKEMdecaps_internal,
            (Ipp8u K[32], const Ipp8u* ciphertext, const Ipp8u* inpDecKey, IppsMLKEMState* mlkemCtx))
#define cp_MLKEMencaps_internal OWNAPI(cp_MLKEMencaps_internal)
IPP_OWN_DECL(IppStatus, cp_MLKEMencaps_internal, (Ipp8u K[32],
                                                  Ipp8u* ciphertext,
                                                  const Ipp8u* inpEncKey,
                                                  const Ipp8u m[32],
                                                  IppsMLKEMState* mlkemCtx))
#define cp_MLKEMkeyGen_internal OWNAPI(cp_MLKEMkeyGen_internal)
IPP_OWN_DECL(IppStatus, cp_MLKEMkeyGen_internal, (Ipp8u * outEncKey,
                                                  Ipp8u* outDecKey,
                                                  const Ipp8u d_k[33],
                                                  const Ipp8u z[32],
                                                  IppsMLKEMState* mlkemCtx))

#define cp_KPKE_Encrypt OWNAPI(cp_KPKE_Encrypt)
IPP_OWN_DECL(IppStatus, cp_KPKE_Encrypt, (Ipp8u * ciphertext,
                                          const Ipp8u* inpEncKey,
                                          const Ipp8u m[32],
                                          Ipp8u r_N[33],
                                          IppsMLKEMState* mlkemCtx))
#define cp_KPKE_Decrypt OWNAPI(cp_KPKE_Decrypt)
IPP_OWN_DECL(IppStatus, cp_KPKE_Decrypt,
            (Ipp8u * message, const Ipp8u* pPKE_DecKey, const Ipp8u* ciphertext, IppsMLKEMState* mlkemCtx))
#define cp_KPKE_KeyGen OWNAPI(cp_KPKE_KeyGen)
IPP_OWN_DECL(IppStatus, cp_KPKE_KeyGen,
            (Ipp8u * outEncKey, Ipp8u* outDecKey, const Ipp8u d_k[33], IppsMLKEMState* mlkemCtx))
/* clang-format on */

#endif // #ifndef _IPPCP_ML_KEM_H_
