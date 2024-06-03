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

/*
 * Represent the `in` value as the `out` array that length is `outlen`
 * !Works only for big-endian data!
 *
 * Input parameters:
 *    outlen   length of resulted array
 *    in       value that needs to be represent as an array
 * Output parameters:
 *    out      resulted array of bytes
 */

__IPPCP_INLINE void toByte(Ipp8u *out, Ipp32s outlen, Ipp32u in) {
    /* Iterate over out in decreasing order, for big-endianness. */
    for (Ipp32s i = outlen - 1; i >= 0; i--) {
        out[i] = (Ipp8u)(in & 0xff);
        in = in >> /*bitsize of 1 byte*/ 8;
    }
}
