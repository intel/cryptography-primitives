/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#ifndef IPPCP_FIPS_CERT_BN_COMMON_H
#define IPPCP_FIPS_CERT_BN_COMMON_H

#include <ippcp.h>

/**
 * \brief
 *
 *  Performs initialization, sign and value setting for big number.
 *
 *  Returns ippStsNoErr if both functions returns ippStsNoErr, obtained error status otherwise.
 *
 * \param[in] pbn pointer to big number being initialized
 * \param[in] max_word_len maximum length of integer big number in 32bit size
 * \param[in] sgn sign of big number
 * \param[in] pdata pointer to integer big number
 * \param[in] data_word_len length of integer big number in 32bit size
 *
 */
__IPPCP_INLINE IppStatus ippcp_init_set_bn(IppsBigNumState *pbn, int max_word_len,
                                     IppsBigNumSGN sgn, const Ipp32u *pdata, int data_word_len)
{
  IppStatus sts;
  sts = ippsBigNumInit(max_word_len, pbn);
  if (sts != ippStsNoErr) return sts;
  sts = ippsSet_BN(sgn, data_word_len, pdata, pbn);
  return sts;
}

#endif // IPPCP_FIPS_CERT_BN_COMMON_H
