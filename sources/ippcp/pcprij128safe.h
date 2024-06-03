/*************************************************************************
* Copyright (C) 2007 Intel Corporation
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
//
//  Purpose:
//     Cryptography Primitive.
//     Internal Safe Rijndael Encrypt, Decrypt
//
//
*/

#if !defined(_PCP_RIJ_SAFE_H)
#define _PCP_RIJ_SAFE_H

#include "owncp.h"
#include "pcprijtables.h"
#include "pcpbnuimpl.h"
#include "pcpmask_ct.h"

#if defined _PCP_RIJ_SAFE_OLD
/* old version */
#define TransformByte OWNAPI(TransformByte)
    IPP_OWN_DECL (Ipp8u, TransformByte, (Ipp8u x, const Ipp8u Transformation[]))
#define TransformNative2Composite OWNAPI(TransformNative2Composite)
    IPP_OWN_DECL (void, TransformNative2Composite, (Ipp8u out[16], const Ipp8u inp[16]))
#define TransformComposite2Native OWNAPI(TransformComposite2Native)
    IPP_OWN_DECL (void, TransformComposite2Native, (Ipp8u out[16], const Ipp8u inp[16]))
#define InverseComposite OWNAPI(InverseComposite)
    IPP_OWN_DECL (Ipp8u, InverseComposite, (Ipp8u x))
#define AddRoundKey OWNAPI(AddRoundKey)
    IPP_OWN_DECL (void, AddRoundKey, (Ipp8u out[], const Ipp8u inp[], const Ipp8u pKey[]))
#endif


#if !defined _PCP_RIJ_SAFE_OLD
/* new version */
#define TransformNative2Composite OWNAPI(TransformNative2Composite)
    IPP_OWN_DECL (void, TransformNative2Composite, (Ipp8u out[16], const Ipp8u inp[16]))
#define TransformComposite2Native OWNAPI(TransformComposite2Native)
    IPP_OWN_DECL (void, TransformComposite2Native, (Ipp8u out[16], const Ipp8u inp[16]))

/* add round key operation */
__IPPCP_INLINE void AddRoundKey(Ipp8u out[16], const Ipp8u inp[16], const Ipp8u rkey[16])
{
   ((Ipp64u*)out)[0] = ((Ipp64u*)inp)[0] ^ ((Ipp64u*)rkey)[0];
   ((Ipp64u*)out)[1] = ((Ipp64u*)inp)[1] ^ ((Ipp64u*)rkey)[1];
}

/* add logs of GF(2^4) elements
// the exp table has been build matched for that implementation
*/
__IPPCP_INLINE Ipp8u AddLogGF16(Ipp8u loga, Ipp8u logb)
{
   //Ipp8u s = loga+logb;
   //return (s>2*14)? 15 : (s>14)? s-15 : s;
   Ipp8u s = loga+logb;
   Ipp8u delta = ((0xF-1)-s)>>7;
   s -= delta;
   s |= 0-(s>>7);
   return s & (0xF);
}
#endif

#define SELECTION_BITS  ((sizeof(BNU_CHUNK_T)/sizeof(Ipp8u)) -1)

__IPPCP_INLINE Ipp8u getSboxValue(Ipp8u x)
{
  BNU_CHUNK_T selection = 0;
  const Ipp8u* SboxEntry = RijEncSbox;

  Ipp32u i;
  for (i = 0; i<sizeof(RijEncSbox); i++) {
    BNU_CHUNK_T mask = cpIsEqu_ct(x, i);
    selection |= SboxEntry[i] & mask;
  }
  return (Ipp8u)(selection & 0xFF);
}

#endif /* _PCP_RIJ_SAFE_H */
