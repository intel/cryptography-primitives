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

#ifndef _IPPCP_ZETAS_H_
#define _IPPCP_ZETAS_H_

#include "owndefs.h"

/* 
 * Precomputed values for Algorithm 11: NTT()
 *    cp_zetas_multiply_ntt[i] = zeta ^ (2 * BitReverse_7(i) + 1) mod q
 */
static const Ipp16s cp_zetas_multiply_ntt[128] = {
    17,    -17,   2761,  -2761, 583,   -583,  2649,  -2649, 1637,  -1637, 723,   -723,  2288,
    -2288, 1100,  -1100, 1409,  -1409, 2662,  -2662, 3281,  -3281, 233,   -233,  756,   -756,
    2156,  -2156, 3015,  -3015, 3050,  -3050, 1703,  -1703, 1651,  -1651, 2789,  -2789, 1789,
    -1789, 1847,  -1847, 952,   -952,  1461,  -1461, 2687,  -2687, 939,   -939,  2308,  -2308,
    2437,  -2437, 2388,  -2388, 733,   -733,  2337,  -2337, 268,   -268,  641,   -641,  1584,
    -1584, 2298,  -2298, 2037,  -2037, 3220,  -3220, 375,   -375,  2549,  -2549, 2090,  -2090,
    1645,  -1645, 1063,  -1063, 319,   -319,  2773,  -2773, 757,   -757,  2099,  -2099, 561,
    -561,  2466,  -2466, 2594,  -2594, 2804,  -2804, 1092,  -1092, 403,   -403,  1026,  -1026,
    1143,  -1143, 2150,  -2150, 2775,  -2775, 886,   -886,  1722,  -1722, 1212,  -1212, 1874,
    -1874, 1029,  -1029, 2110,  -2110, 2935,  -2935, 885,   -885,  2154,  -2154
};

/* 
 * Precomputed values for Algorithm 9 and Algorithm 11: NTT()
 *    cp_zetas_ntt[i] = zeta ^ BitReverse_7(i) mod q
 */
static const Ipp16s cp_zetas_ntt[128] = {
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,  2786, 3260, 569,  1746,
    296,  2447, 1339, 1476, 3046, 56,   2240, 1333, 1426, 2094, 535,  2882, 2393, 2879, 1974, 821,
    289,  331,  3253, 1756, 1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,  2474, 3110, 1227, 910,
    17,   2761, 583,  2649, 1637, 723,  2288, 1100, 1409, 2662, 3281, 233,  756,  2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952,  1461, 2687, 939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,  2099, 561,  2466, 2594,
    2804, 1092, 403,  1026, 1143, 2150, 2775, 886,  1722, 1212, 1874, 1029, 2110, 2935, 885,  2154
};

#endif // #ifndef _IPPCP_ZETAS_H_
