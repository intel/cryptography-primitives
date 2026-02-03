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

#define MAX_PKCS5_HASH_SIZE MBS_HASH_MAX

/*F*
//    Name: ippsPBKDF2_PKCS5v2
//
// Purpose: Password-based cryptography key derivation function PKCS5-PBKDF2
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL
//                               pass == NULL
//                               odk  == NULL
//                               salt == NULL
//    ippStsLengthErr
//                               odk_len <= 0
//                               salt_len < 8
//                               salt_len > MBS_HASH_MAX
//                               c < 1000
//    ippStsNotSupportedModeErr hash method is not supported
//    ippStsNoErr                no errors
//
// Parameters:
//    pass        pointer to the input password
//    pass_len    length of the input password in bytes
//    odk         pointer to the output derived key
//    odk_len     length of needed output derived key in bytes
//    salt        pointer to salt
//    salt_len    length of the input salt message in bytes
//    c           number of internal iterations required
//    pMethod     pointer to the hash method context
//
*F*/

IPPFUN(IppStatus,
       ippsPBKDF2_PKCS5v2,
       (const Ipp8u* pass,
        int pass_len,
        Ipp8u* odk,
        int odk_len,
        const Ipp8u* salt,
        int salt_len,
        int c,
        const IppsHashMethod* pMethod))
{

    // test pointers
    IPP_BAD_PTR1_RET(odk);
    IPP_BAD_PTR2_RET(salt, pMethod);

    IPP_BADARG_RET(odk_len <= 0, ippStsLengthErr);
    IPP_BADARG_RET(salt_len < 8, ippStsLengthErr);
    IPP_BADARG_RET(salt_len > MAX_PKCS5_HASH_SIZE, ippStsLengthErr);
    IPP_BADARG_RET(c < 1000, ippStsLengthErr);

    Ipp8u tmp_msg[MAX_PKCS5_HASH_SIZE + 4];
    IppStatus sts = ippStsNoErr;
    int hash_len  = pMethod->hashLen;

    int blocks   = 1 + ((odk_len - 1) / hash_len); // ceil(x/y) when x != 0
    int odk_used = 0;
    int odk_left = odk_len;

    for (int i = 1; i <= blocks; i++) {

        CopyBlock(salt, &tmp_msg[0], salt_len);

        tmp_msg[salt_len + 0] = (i >> 24) & 0xff;
        tmp_msg[salt_len + 1] = (i >> 16) & 0xff;
        tmp_msg[salt_len + 2] = (i >> 8) & 0xff;
        tmp_msg[salt_len + 3] = (i >> 0) & 0xff;

        sts =
            ippsHMACMessage_rmf(tmp_msg, salt_len + 4, pass, pass_len, tmp_msg, hash_len, pMethod);
        if (ippStsNoErr != sts)
            goto exit;

        int update_len = IPP_MIN(hash_len, odk_left);

        CopyBlock(tmp_msg, &odk[odk_used], update_len);

        for (int iter = 1; iter < c; iter++) {
            sts =
                ippsHMACMessage_rmf(tmp_msg, hash_len, pass, pass_len, tmp_msg, hash_len, pMethod);
            if (ippStsNoErr != sts)
                goto exit;
            XorBlock(&odk[odk_used], tmp_msg, &odk[odk_used], update_len);
        }

        odk_used += update_len;
        odk_left -= update_len;
    }

exit:
    PurgeBlock(tmp_msg, sizeof(tmp_msg));

    return sts;
}
