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

/*F*
//    Name: ippsHKDF_extract
//
// Purpose: Extract function of MAC-based Extract-and-Expand Key Derivation Function (HKDF).
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL
//                               ikm == NULL
//                               prk == NULL
//    ippsStsNotSupportedModeErr hash method is not supported
//    ippStsLengthErr            if internal hash len from method <= 0
//    ippStsNoErr                no errors
//
// Parameters:
//    ikm         pointer to the input keying material
//    ikm_len     length (bytes) of the ikm
//    prk         pointer to the output prk, pseudorandom key
//    salt        optional pointer to salt
//    salt_len    length (bytes) of the salt
//    pMethod     hash method
//
*F*/
IPPFUN(IppStatus,
       ippsHKDF_extract,
       (const Ipp8u* ikm,
        int ikm_len,
        Ipp8u* prk,
        const Ipp8u* salt,
        int salt_len,
        const IppsHashMethod* pMethod))
{
    // test pointers
    IPP_BAD_PTR2_RET(ikm, prk);
    IPP_BAD_PTR1_RET(pMethod);

    /* SHAKE128/256 are not supported with HKDF mode*/
    IPP_BADARG_RET(cpIsSHAKEAlgID(pMethod->hashAlgId), ippStsNotSupportedModeErr);

    // test outkey len
    int hash_len = pMethod->hashLen;
    IPP_BADARG_RET((hash_len <= 0), ippStsLengthErr);

    {
        Ipp8u zero_key[MAX_HKDF_HASH_SIZE] = { 0 };
        IppStatus sts;

        // Extract prk = hmac_hash(key=salt or zeros, msg=ikm) -> PRK

        if (hash_len > MAX_HKDF_HASH_SIZE)
            return ippStsLengthErr;

        if (salt_len == 0) {
            salt     = zero_key;
            salt_len = hash_len;
        }
        sts = ippsHMACMessage_rmf(ikm, ikm_len, salt, salt_len, prk, hash_len, pMethod);
        return sts;
    }
}
