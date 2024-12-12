/*************************************************************************
* Copyright (C) 2021-2022 Intel Corporation
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
 * Auxiliary functions to set and copy memory
 */
__MBX_INLINE void CopyBlock(const void* pSrc, void* pDst, int numBytes)
{
    const int8u* s = (int8u*)pSrc;
    int8u* d       = (int8u*)pDst;
    int k;
    for (k = 0; k < numBytes; k++)
        d[k] = s[k];
}

__MBX_INLINE void PadBlock(int8u paddingByte, void* pDst, int numBytes)
{
    int8u* d = (int8u*)pDst;
    int k;
    for (k = 0; k < numBytes; k++)
        d[k] = paddingByte;
}
