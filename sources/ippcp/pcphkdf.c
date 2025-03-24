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

#include "owndefs.h"
#include "owncp.h"
#include "pcphmac_rmf.h"
#include "pcptool.h"

#define MAX_HKDF_HASH_SIZE MBS_HASH_MAX

// The MAX_HKDF_INFO_SIZE is a library restriction for this implementation and not from the spec.
#define MAX_HKDF_INFO_SIZE (128)

/*F*
//    Name: ippsHKDF_expand
//
// Purpose: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL
//                               ikm == NULL
//                               okm == NULL
//    ippStsLengthErr            okm_len <= 0
//                               okm_len > 255 * Hash length
//                               info_len > MAX_HKDF_INFO_SIZE
//    ippsStsNotSupportedModeErr hash method is not supported
//    ippStsNoErr                no errors
//
// Parameters:
//    ikm         pointer to the input keying material
//    ikm_len     length (bytes) of the ikm
//    okm         pointer to the output keying material
//    okm_len     length (bytes) of the okm
//    salt        optional pointer to salt
//    salt_len    length (bytes) of the salt
//    info        optional pointer to application specific information
//    info_len    length (bytes) of the info
//    pMethod     hash method
//
*F*/
IPPFUN(IppStatus,
       ippsHKDF_expand,
       (const Ipp8u* ikm,
        int ikm_len,
        Ipp8u* okm,
        int okm_len,
        const Ipp8u* salt,
        int salt_len,
        const Ipp8u* info,
        int info_len,
        const IppsHashMethod* pMethod))
{
    // test pointers
    IPP_BAD_PTR2_RET(ikm, okm);
    IPP_BAD_PTR1_RET(pMethod);

    // test outkey len
    int hash_len = pMethod->hashLen;
    IPP_BADARG_RET((okm_len <= 0), ippStsLengthErr);
    IPP_BADARG_RET((hash_len <= 0), ippStsLengthErr);
    IPP_BADARG_RET((okm_len > 255 * hash_len), ippStsLengthErr);

    // test info size
    IPP_BADARG_RET((info_len > MAX_HKDF_INFO_SIZE), ippStsLengthErr);
    IPP_BADARG_RET((info_len < 0), ippStsLengthErr);
    IPP_BADARG_RET((info_len > 0) && (info == NULL), ippStsLengthErr);
    {
        Ipp8u prk[MAX_HKDF_HASH_SIZE];
        Ipp8u tmsg[MAX_HKDF_HASH_SIZE + MAX_HKDF_INFO_SIZE + 1];
        Ipp8u zero_key[MAX_HKDF_HASH_SIZE] = { 0 };
        IppStatus sts;

        // Extract prk = hmac_hash(key=salt or zeros, msg=ikm)

        if (hash_len > MAX_HKDF_HASH_SIZE)
            return ippStsLengthErr;

        if (salt_len == 0) {
            salt     = zero_key;
            salt_len = hash_len;
        }
        sts = ippsHMACMessage_rmf(ikm, ikm_len, salt, salt_len, prk, hash_len, pMethod);
        if (ippStsNoErr != sts)
            goto exit;

        // Expand key okm = HKDF-Expand(PRK, info, L)

        // Calculate T1 = hash(info | 1)
        int tmsg_len = info_len + 1;
        CopyBlock(info, &tmsg[0], info_len);
        tmsg[info_len] = 1;
        sts = ippsHMACMessage_rmf(tmsg, tmsg_len, prk, hash_len, tmsg, hash_len, pMethod);
        if (ippStsNoErr != sts)
            goto exit;

        int okm_update_len = IPP_MIN(hash_len, okm_len);
        int okm_used       = okm_update_len;
        int okm_left       = okm_len - okm_update_len;
        CopyBlock(tmsg, okm, okm_update_len);

        // Calculate Tn = hash(T(n-1) | info | i)
        CopyBlock(info, &tmsg[hash_len], info_len);
        tmsg_len = hash_len + info_len + 1;

        for (int i = 2; okm_left > 0; i++) {
            tmsg[hash_len + info_len] = 0xff & i;
            sts = ippsHMACMessage_rmf(tmsg, tmsg_len, prk, hash_len, tmsg, hash_len, pMethod);
            if (ippStsNoErr != sts)
                goto exit;
            okm_update_len = IPP_MIN(hash_len, okm_left);
            CopyBlock(tmsg, &okm[okm_used], okm_update_len);
            okm_used += okm_update_len;
            okm_left -= okm_update_len;
        }

    exit:
        return sts;
    }
}
