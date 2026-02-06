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

#ifndef _IPPCP_ML_COMMON_H_
#define _IPPCP_ML_COMMON_H_

#include "owndefs.h"
#include "pcptool.h"

/* Common ML-KEM and ML-DSA constants */
#define CP_ML_N            (256)
#define CP_RAND_DATA_BYTES (32)

#define CP_ML_ALIGNMENT ((int)sizeof(void*))

#ifndef CP_ML_MEMORY_OPTIMIZATION
#if (_IPP32E >= _IPP32E_K0)
#define CP_ML_MEMORY_OPTIMIZATION (0)
#else
#define CP_ML_MEMORY_OPTIMIZATION (1)
#endif /* #if (_IPP32E >= _IPP32E_K0) */
#endif /* #ifndef CP_ML_MEMORY_OPTIMIZATION */

//-------------------------------//
//      Internal data types
//-------------------------------//

/* Polynomial of CP_ML_N elements */
typedef struct {
    POLY_VALUE_T values[CP_ML_N];
} IppPoly;

//-------------------------------//
//        Stuff functions
//-------------------------------//

/*
 * Memory allocation primitive working with STORAGE_T structure.
 * Input: storage     - pointer to STORAGE_T structure
 *        bytesNeeded - number of bytes needed for allocation
 * Output: pointer to allocated memory or NULL if not enough space
 */
IPPCP_INLINE Ipp8u* cp_mlStorageAllocate(STORAGE_T* storage, Ipp32s bytesNeeded)
{
    if (storage->bytesCapacity - storage->bytesUsed < bytesNeeded) {
        return NULL; // Not enough space
    }
    Ipp8u* pOutMemory = storage->pStorageData + storage->bytesUsed;
    storage->bytesUsed += bytesNeeded;
    return pOutMemory;
}

/*
 * Memory release primitive working with STORAGE_T structure, zeroizes the released buffer.
 * Input:  storage      - pointer to STORAGE_T structure
 *         bytesRelease - number of bytes to release
 * Output: ippStsNoErr if release is successful, ippStsMemAllocErr if release size is incorrect
 */
IPPCP_INLINE IppStatus cp_mlStorageRelease(STORAGE_T* storage, Ipp32s bytesRelease)
{
    if (bytesRelease > storage->bytesUsed) {
        return ippStsMemAllocErr; // Not correct release size
    }

    // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX <- bytesCapacity
    // XXXXXXXXXXXXXXXXXXXXXXXXXXX                 <- bytesUsed
    //                    00000000                 <- bytesRelease
    PurgeBlock(storage->pStorageData + storage->bytesUsed - bytesRelease, (int)bytesRelease);

    storage->bytesUsed -= bytesRelease;
    CP_PREVENT_REORDER();

    // Check that the memory was released and zeroized as intended
    return (*(storage->pStorageData + storage->bytesUsed) == 0) ? ippStsNoErr : ippStsMemAllocErr;
}

/*
 * Memory release primitive working with STORAGE_T structure, zeroizes the released buffer.
 * Input:  storage - pointer to STORAGE_T structure
 *
 * Note: the operation release the whole buffer, safe to be used for an empty storage.
 */
IPPCP_INLINE IppStatus cp_mlStorageReleaseAll(STORAGE_T* storage)
{
    // Zeroize the buffer (minimum amount between bytesUsed and bytesCapacity)
    PurgeBlock(storage->pStorageData,
               IPP_MIN((int)storage->bytesUsed, (int)storage->bytesCapacity));
    storage->bytesUsed = 0;
    CP_PREVENT_REORDER();

    return (*(storage->pStorageData + storage->bytesUsed) == 0) ? ippStsNoErr : ippStsMemAllocErr;
}

#define CP_CHECK_FREE_RET(IN_RET_CONDITION, IN_STATUS, IN_P_STORAGE)     \
    {                                                                    \
        if (IN_RET_CONDITION) {                                          \
            IppStatus releaseSts = cp_mlStorageReleaseAll(IN_P_STORAGE); \
            return (IN_STATUS) | releaseSts;                             \
        }                                                                \
    }

/* Memory allocation helpers for poly and polyvec */
/* clang-format off */
#define CP_ML_ALLOCATE_ALIGNED_POLYVEC(NAME, SIZE, STORAGE)                               \
    IppPoly*(NAME) = (IppPoly*)cp_mlStorageAllocate((STORAGE),                            \
                                             (SIZE) * sizeof(IppPoly) + CP_ML_ALIGNMENT); \
    CP_CHECK_FREE_RET((NAME) == NULL, ippStsMemAllocErr, (STORAGE));                      \
    (NAME) = IPP_ALIGNED_PTR((NAME), CP_ML_ALIGNMENT);

#define CP_ML_ALLOCATE_ALIGNED_POLY(NAME, STORAGE) \
    CP_ML_ALLOCATE_ALIGNED_POLYVEC((NAME), 1, (STORAGE))
/* clang-format on */

/* Memory release helpers for poly and polyvec */
#define CP_ML_RELEASE_ALIGNED_POLYVEC(SIZE, STORAGE, STATUS) \
    (STATUS) |= cp_mlStorageRelease((STORAGE), (SIZE) * sizeof(IppPoly) + CP_ML_ALIGNMENT);

#define CP_ML_RELEASE_ALIGNED_POLY(STORAGE, STATUS) \
    CP_ML_RELEASE_ALIGNED_POLYVEC(1, (STORAGE), (STATUS))

#endif // #ifndef _IPPCP_ML_COMMON_H_
