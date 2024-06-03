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
//
//  Purpose:
//     Cryptography Primitive.
//     Internal Definitions of Block Cipher Tools
//
//
*/

#if !defined(_CP_TOOL_H)
#define _CP_TOOL_H

#include "pcpmask_ct.h"

#define _NEW_COPY16_
#define _NEW_XOR16_

/* copy data block */
__IPPCP_INLINE void CopyBlock(const void* pSrc, void* pDst, cpSize numBytes)
{
   const Ipp8u* s  = (Ipp8u*)pSrc;
   Ipp8u* d  = (Ipp8u*)pDst;
   cpSize k;
   for(k=0; k<numBytes; k++ )
      d[k] = s[k];
}

__IPPCP_INLINE void CopyBlock8(const void* pSrc, void* pDst)
{
   int k;
   for(k=0; k<8; k++ )
      ((Ipp8u*)pDst)[k] = ((Ipp8u*)pSrc)[k];
}

/* Because of the incorrect inlining with ICX compiler definition of CopyBlock16 function was moved to pcptool.c */
#define CopyBlock16 OWNAPI(CopyBlock16)
IPP_OWN_DECL (void, CopyBlock16, (const void* pSrc, void* pDst))

__IPPCP_INLINE void CopyBlock24(const void* pSrc, void* pDst)
{
   int k;
   for(k=0; k<24; k++ )
      ((Ipp8u*)pDst)[k] = ((Ipp8u*)pSrc)[k];
}
__IPPCP_INLINE void CopyBlock32(const void* pSrc, void* pDst)
{
   int k;
   for(k=0; k<32; k++ )
      ((Ipp8u*)pDst)[k] = ((Ipp8u*)pSrc)[k];
}

/*
// padding data block
*/
__IPPCP_INLINE void PadBlock(Ipp8u paddingByte, void* pDst, cpSize numBytes)
{
   Ipp8u* d  = (Ipp8u*)pDst;
   cpSize k;
   for(k=0; k<numBytes; k++ )
      d[k] = paddingByte;
}

#if !((_IPP>=_IPP_W7) || (_IPP32E>=_IPP32E_M7))
__IPPCP_INLINE void PurgeBlock(void* pDst, int len)
{
   int n;
   for(n=0; n<len; n++) ((Ipp8u*)pDst)[n] = 0;
}
#else
#define PurgeBlock OWNAPI(PurgeBlock)
    IPP_OWN_DECL (void, PurgeBlock, (void* pDst, int len))
#endif

/* fill block */
__IPPCP_INLINE void FillBlock16(Ipp8u filler, const void* pSrc, void* pDst, int len)
{
   int n;
   for(n=0; n<len; n++) ((Ipp8u*)pDst)[n] = ((Ipp8u*)pSrc)[n];
   for(; n<16; n++) ((Ipp8u*)pDst)[n] = filler;
}

/* xor block */
__IPPCP_INLINE void XorBlock(const void* pSrc1, const void* pSrc2, void* pDst, int len)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k = 0; k < len; k++)
   {
        d[k] = (Ipp8u)(p1[k] ^p2[k]);
   }
}
/* Performs operation:
 *      reverse(pSrc1 `xor_len_bytes` reverse(pSrc2))
 * and stores the result in |pDst|.
 *  |len| specifies how many bytes of |pSrc1| shall be xor-ed to |pSrc2|. It must not
 *  be more than |blockSize|, and this condition should be ensured outside.
 */
__IPPCP_INLINE void XorBlockMirror(const void* pSrc1, const void* pSrc2, void* pDst, int blockSize, int len)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<len; k++)
      d[blockSize-k-1] = (Ipp8u)(p1[k] ^ p2[blockSize-k-1]);
}
__IPPCP_INLINE void XorBlock8(const void* pSrc1, const void* pSrc2, void* pDst)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<8; k++ )
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}

// Because of the incorrect inlining definition of XorBlock16 function was moved to pcptool.c
#define XorBlock16 OWNAPI(XorBlock16)
IPP_OWN_DECL (void, XorBlock16, (const void* pSrc1, const void* pSrc2, void* pDst))

__IPPCP_INLINE void XorBlock24(const void* pSrc1, const void* pSrc2, void* pDst)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<24; k++ )
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}
__IPPCP_INLINE void XorBlock32(const void* pSrc1, const void* pSrc2, void* pDst)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<32; k++ )
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}


/* compare (equivalence) */
__IPPCP_INLINE int EquBlock(const void* pSrc1, const void* pSrc2, int len)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   int k;
   int isNotEqu;
   for(k=0, isNotEqu=0; k<len; k++)
      isNotEqu |= (p1[k]^p2[k]);
   return !isNotEqu;
}


/* addition (incrementation) functions for CTR mode of diffenent block ciphers */
/* constant execution time version */
__IPPCP_INLINE void StdIncrement(Ipp8u* pCounter, int blkBitSize, int numSize)
{
   int maskPosition = (blkBitSize -numSize)/8;
   Ipp8u maskVal = (Ipp8u)( 0xFF >> (blkBitSize -numSize)%8 );

   int i;
   Ipp32u carry = 1;
   for(i=BITS2WORD8_SIZE(blkBitSize)-1; i>=0; i--) {
      int d = maskPosition - i;
      Ipp8u mask = (Ipp8u)(maskVal | cpIsMsb_ct((BNU_CHUNK_T)d));

      Ipp32u x = pCounter[i] + carry;
      Ipp8u y = pCounter[i];
      pCounter[i] = (Ipp8u)((y & ~mask) | (x & mask));

      maskVal &= cpIsMsb_ct((BNU_CHUNK_T)d);

      carry = (x>>8) & 0x1;
   }
}

/* vb */
__IPPCP_INLINE void ompStdIncrement64( void* pInitCtrVal, void* pCurrCtrVal,
                                int ctrNumBitSize, int n )
{
    int    k;
    Ipp64u cntr;
    Ipp64u temp;
    Ipp64s item;

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
        ( ( Ipp8u* )&cntr )[k] = ( ( Ipp8u* )pInitCtrVal )[7 - k];
  #else
    for( k = 0; k < 8; k++ )
        ( ( Ipp8u* )&cntr )[k] = ( ( Ipp8u* )pInitCtrVal )[k];
  #endif

    if( ctrNumBitSize == 64 )
    {
        cntr += ( Ipp64u )n;
    }
    else
    {
        Ipp64u mask = CONST_64(0xFFFFFFFFFFFFFFFF) >> ( 64 - ctrNumBitSize );
        Ipp64u save = cntr & ( ~mask );
        Ipp64u bndr = ( Ipp64u )1 << ctrNumBitSize;

        temp = cntr & mask;
        cntr = temp + ( Ipp64u )n;

        if( cntr > bndr )
        {
            item = ( Ipp64s )n - ( Ipp64s )( bndr - temp );

            while( item > 0 )
            {
                cntr  = ( Ipp64u )item;
                item -= ( Ipp64s )bndr;
            }
        }

        cntr = save | ( cntr & mask );
    }

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
        ( ( Ipp8u* )pCurrCtrVal )[7 - k] = ( ( Ipp8u* )&cntr )[k];
  #else
    for( k = 0; k < 8; k++ )
        ( ( Ipp8u* )pCurrCtrVal )[k] = ( ( Ipp8u* )&cntr )[k];
  #endif
}


/* vb */
__IPPCP_INLINE void ompStdIncrement128( void* pInitCtrVal, void* pCurrCtrVal,
                                 int ctrNumBitSize, int n )
{
    int    k;
    Ipp64u low;
    Ipp64u hgh;
    Ipp64u flag;
    Ipp64u mask = CONST_64(0xFFFFFFFFFFFFFFFF);
    Ipp64u save = 0;

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[15 - k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[7 - k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[8 + k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[k];
    }
  #endif

    if( ctrNumBitSize == 64 )
    {
        low += ( Ipp64u )n;
    }
    else if( ctrNumBitSize < 64 )
    {
        Ipp64u bndr;
        Ipp64u cntr;
        Ipp64s item;

        mask >>= ( 64 - ctrNumBitSize );
        save   = low & ( ~mask );
        cntr   = ( low & mask ) + ( Ipp64u )n;

        if( ctrNumBitSize < 31 )
        {
            bndr = ( Ipp64u )1 << ctrNumBitSize;

            if( cntr > bndr )
            {
                item = ( Ipp64s )( ( Ipp64s )n - ( ( Ipp64s )bndr -
                ( Ipp64s )( low & mask ) ) );

                while( item > 0 )
                {
                    cntr  = ( Ipp64u )item;
                    item -= ( Ipp64s )bndr;
                }
            }
        }

        low = save | ( cntr & mask );
    }
    else
    {
        flag = ( low >> 63 );

        if( ctrNumBitSize != 128 )
        {
            mask >>= ( 128 - ctrNumBitSize );
            save   = hgh & ( ~mask );
            hgh   &= mask;
        }

        low += ( Ipp64u )n;

        if( flag != ( low >> 63 ) ) hgh++;

        if( ctrNumBitSize != 128 )
        {
            hgh = save | ( hgh & mask );
        }
    }

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[15 - k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[7 - k]  = ( ( Ipp8u* )&hgh )[k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[8 + k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[k]     = ( ( Ipp8u* )&hgh )[k];
    }
  #endif
}

#if 0
/* vb */
__IPPCP_INLINE void ompStdIncrement192( void* pInitCtrVal, void* pCurrCtrVal,
                                int ctrNumBitSize, int n )
{
    int    k;
    Ipp64u low;
    Ipp64u mdl;
    Ipp64u hgh;
    Ipp64u flag;
    Ipp64u mask = CONST_64(0xFFFFFFFFFFFFFFFF);
    Ipp64u save;

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[23 - k];
        ( ( Ipp8u* )&mdl )[k] = ( ( Ipp8u* )pInitCtrVal )[15 - k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[7  - k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[16 + k];
        ( ( Ipp8u* )&mdl )[k] = ( ( Ipp8u* )pInitCtrVal )[8  + k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[k];
    }
  #endif

    if( ctrNumBitSize == 64 )
    {
        low += ( Ipp64u )n;
    }
    else if( ctrNumBitSize == 128 )
    {
        flag = ( low >> 63 );
        low += ( Ipp64u )n;
        if( flag != ( low >> 63 ) ) mdl++;
    }
    else if( ctrNumBitSize == 192 )
    {
        flag = ( low >> 63 );
        low += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;
            if( flag != ( mdl >> 63 ) ) hgh++;
        }
    }
    else if( ctrNumBitSize < 64 )
    {
        Ipp64u bndr;
        Ipp64u cntr;
        Ipp64s item;

        mask >>= ( 64 - ctrNumBitSize );
        save   = low & ( ~mask );
        cntr   = ( low & mask ) + ( Ipp64u )n;

        if( ctrNumBitSize < 31 )
        {
            bndr = ( Ipp64u )1 << ctrNumBitSize;

            if( cntr > bndr )
            {
                item = ( Ipp64s )( ( Ipp64s )n - ( ( Ipp64s )bndr -
                    ( Ipp64s )( low & mask ) ) );

                while( item > 0 )
                {
                    cntr  = ( Ipp64u )item;
                    item -= ( Ipp64s )bndr;
                }
            }
        }

        low = save | ( cntr & mask );
    }
    else if( ctrNumBitSize < 128 )
    {
        flag   = ( low >> 63 );
        mask >>= ( 128 - ctrNumBitSize );
        save   = mdl & ( ~mask );
        mdl   &= mask;
        low   += ( Ipp64u )n;
        if( flag != ( low >> 63 ) ) mdl++;
        mdl    = save | ( mdl & mask );
    }
    else
    {
        flag   = ( low >> 63 );
        mask >>= ( 192 - ctrNumBitSize );
        save   = hgh & ( ~mask );
        hgh   &= mask;
        low   += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;
            if( flag != ( mdl >> 63 ) ) hgh++;
        }

        hgh    = save | ( hgh & mask );
    }

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[23 - k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[15 - k] = ( ( Ipp8u* )&mdl )[k];
        ( ( Ipp8u* )pCurrCtrVal )[7  - k] = ( ( Ipp8u* )&hgh )[k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[16 + k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[8  + k] = ( ( Ipp8u* )&mdl )[k];
        ( ( Ipp8u* )pCurrCtrVal )[k]      = ( ( Ipp8u* )&hgh )[k];
    }
  #endif
}
#endif

#if 0
/* vb */
__IPPCP_INLINE void ompStdIncrement256( void* pInitCtrVal, void* pCurrCtrVal,
                                 int ctrNumBitSize, int n )
{
    int    k;
    Ipp64u low;
    Ipp64u mdl;
    Ipp64u mdm;
    Ipp64u hgh;
    Ipp64u flag;
    Ipp64u mask = CONST_64(0xFFFFFFFFFFFFFFFF);
    Ipp64u save;

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[31 - k];
        ( ( Ipp8u* )&mdl )[k] = ( ( Ipp8u* )pInitCtrVal )[23 - k];
        ( ( Ipp8u* )&mdm )[k] = ( ( Ipp8u* )pInitCtrVal )[15 - k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[7  - k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )&low )[k] = ( ( Ipp8u* )pInitCtrVal )[24 + k];
        ( ( Ipp8u* )&mdl )[k] = ( ( Ipp8u* )pInitCtrVal )[16 + k];
        ( ( Ipp8u* )&mdm )[k] = ( ( Ipp8u* )pInitCtrVal )[8  + k];
        ( ( Ipp8u* )&hgh )[k] = ( ( Ipp8u* )pInitCtrVal )[k];
    }
  #endif

    if( ctrNumBitSize == 64 )
    {
        low += ( Ipp64u )n;
    }
    else if( ctrNumBitSize == 128 )
    {
        flag = ( low >> 63 );
        low += ( Ipp64u )n;
        if( flag != ( low >> 63 ) ) mdl++;
    }
    else if( ctrNumBitSize == 192 )
    {
        flag = ( low >> 63 );
        low += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;
            if( flag != ( mdl >> 63 ) ) hgh++;
        }
    }
    else if( ctrNumBitSize == 256 )
    {
        flag = ( low >> 63 );
        low += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;

            if( flag != ( mdl >> 63 ) )
            {
                flag = ( mdm >> 63 );
                mdm++;
                if( flag != ( mdm >> 63 ) ) hgh++;
            }
        }
    }
    else if( ctrNumBitSize < 64 )
    {
        Ipp64u bndr;
        Ipp64u cntr;
        Ipp64s item;

        mask >>= ( 64 - ctrNumBitSize );
        save   = low & ( ~mask );
        cntr   = ( low & mask ) + ( Ipp64u )n;

        if( ctrNumBitSize < 31 )
        {
            bndr = ( Ipp64u )1 << ctrNumBitSize;

            if( cntr > bndr )
            {
                item = ( Ipp64s )( ( Ipp64s )n - ( ( Ipp64s )bndr -
                    ( Ipp64s )( low & mask ) ) );

                while( item > 0 )
                {
                    cntr  = ( Ipp64u )item;
                    item -= ( Ipp64s )bndr;
                }
            }
        }

        low = save | ( cntr & mask );
    }
    else if( ctrNumBitSize < 128 )
    {
        flag   = ( low >> 63 );
        mask >>= ( 128 - ctrNumBitSize );
        save   = mdl & ( ~mask );
        mdl   &= mask;
        low   += ( Ipp64u )n;
        if( flag != ( low >> 63 ) ) mdl++;
        mdl    = save | ( mdl & mask );
    }
    else if( ctrNumBitSize < 192 )
    {
        flag   = ( low >> 63 );
        mask >>= ( 192 - ctrNumBitSize );
        save   = mdm & ( ~mask );
        mdm   &= mask;
        low   += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;
            if( flag != ( mdl >> 63 ) ) mdm++;
        }

        mdm    = save | ( mdm & mask );
    }
    else
    {
        flag   = ( low >> 63 );
        mask >>= ( 256 - ctrNumBitSize );
        save   = hgh & ( ~mask );
        hgh   &= mask;
        low   += ( Ipp64u )n;

        if( flag != ( low >> 63 ) )
        {
            flag = ( mdl >> 63 );
            mdl++;

            if( flag != ( mdl >> 63 ) )
            {
                flag = ( mdm >> 63 );
                mdm++;
                if( flag != ( mdm >> 63 ) ) hgh++;
            }
        }

        hgh    = save | ( hgh & mask );
    }

  #if( IPP_ENDIAN == IPP_LITTLE_ENDIAN )
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[31 - k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[23 - k] = ( ( Ipp8u* )&mdl )[k];
        ( ( Ipp8u* )pCurrCtrVal )[15 - k] = ( ( Ipp8u* )&mdm )[k];
        ( ( Ipp8u* )pCurrCtrVal )[7  - k] = ( ( Ipp8u* )&hgh )[k];
    }
  #else
    for( k = 0; k < 8; k++ )
    {
        ( ( Ipp8u* )pCurrCtrVal )[24 + k] = ( ( Ipp8u* )&low )[k];
        ( ( Ipp8u* )pCurrCtrVal )[16 + k] = ( ( Ipp8u* )&mdl )[k];
        ( ( Ipp8u* )pCurrCtrVal )[8  + k] = ( ( Ipp8u* )&mdm )[k];
        ( ( Ipp8u* )pCurrCtrVal )[k]      = ( ( Ipp8u* )&hgh )[k];
    }
  #endif
}
#endif

#endif /* _CP_TOOL_H */
