/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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
//               Intel(R) Cryptography Primitives Library
//
//  Contents:
//     cpBN_OneRef()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpbn.h"
#include "pcptool.h"


/*F*
//    Name: cpBN_OneRef
//
// Purpose: BN(1) and reference
//
//  Return:
//      BigNum = 1
*F*/

/* BN(1) and reference */
IPP_OWN_DEFN(IppsBigNumState*, cpBN_OneRef, (void))
{
    /* Prevents re-initialization for better multi-threaded/repeated call performance */
    static volatile int isInitialized = 0;

    static IppsBigNumStateChunk cpChunk_BN1 = {
        {idCtxUnknown, ippBigNumPOS, 1, 1, &cpChunk_BN1.value, &cpChunk_BN1.temporary},
        1,
        0
    };

    if (isInitialized) {
        CP_PREVENT_REORDER();
        return &cpChunk_BN1.bn;
    }

    BN_SET_ID(&cpChunk_BN1.bn);

    CP_PREVENT_REORDER();
    isInitialized = 1;

    return &cpChunk_BN1.bn;
}
