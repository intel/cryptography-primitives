.. _functions-for-creation-of-cryptographic-contexts:

Functions for Creation of Cryptographic Contexts
================================================


The section presents source code for creation of some cryptographic
contexts.


Declarations
------------


Contents of the header file (xsample_cpobjs.h) declaring functions for
creation of some cryptographic contexts are presented below:


.. code-block:: cpp


   #if !defined _CPOBJS_H_
   #define _CPOBJS_H_


   //
   // create new of some ippCP 'objects'
   //
   #include "ippcp.h"
   #include <stdlib.h>


   #define BITS_2_WORDS(n) (((n)+31)>>5)
   int Bitsize2Wordsize(int nBits);


   Ipp32u* rand32(Ipp32u* pX, int size);


   IppsBigNumState* newBN(int len, const Ipp32u* pData=0);
   IppsBigNumState* newRandBN(int len);
   void deleteBN(IppsBigNumState* pBN);


   IppsPrimeState* newPrimeGen(int seedBitsize=160);
   void deletePrimeGen(IppsPrimeState* pPrime);


   IppsRSAState* newRSA(int lenN, int lenP, IppRSAKeyType type);
   void deleteRSA(IppsRSAState* pRSA);


   IppsDLPState* newDLP(int lenM, int lenL);
   void deleteDLP(IppsDLPState* pDLP);


   #endif // _CPOBJS_H_


Definitions
-----------


C++ definitions of functions creating cryptographic contexts are given
below. For the declarations to be included, see the preceding
section.


.. code-block:: cpp


   #include "xsample_cpobjs.h"


   // convert bitsize into 32-bit wordsize
   int Bitsize2Wordsize(int nBits)
   { return (nBits+31)>>5; }


   // new BN number
   IppsBigNumState* newBN(int len, const Ipp32u* pData)
   {
      int size;
      ippsBigNumGetSize(len, &size);
      IppsBigNumState* pBN = (IppsBigNumState*)( new Ipp8u [size] );
      ippsBigNumInit(len, pBN);
      if(pData)
         ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
      return pBN;
   }
   void deleteBN(IppsBigNumState* pBN)
   { delete [] (Ipp8u*)pBN; }


   // set up array of 32-bit items random
   Ipp32u* rand32(Ipp32u* pX, int size)
   {
      for(int n=0; n<size; n++)
         pX[n] = (rand()<<16) + rand();
      return pX;
   }


   IppsBigNumState* newRandBN(int len)
   {
      Ipp32u* pBuffer = new Ipp32u [len];
      IppsBigNumState* pBN = newBN(len, rand32(pBuffer,len));
      delete [] pBuffer;
      return pBN;
   }


   //
   // 'external' PRNG
   //
   IppsPRNGState* newPRNG(int seedBitsize)
   {
      int seedSize = Bitsize2Wordsize(seedBitsize);
      Ipp32u* seed = new Ipp32u [seedSize];
      Ipp32u* augm = new Ipp32u [seedSize];


      int size;
      IppsBigNumState* pTmp;
      ippsPRNGGetSize(&size);
      IppsPRNGState* pCtx = (IppsPRNGState*)( new Ipp8u [size] );
      ippsPRNGInit(seedBitsize, pCtx);


      ippsPRNGSetSeed(pTmp=newBN(seedSize,rand32(seed,seedSize)), pCtx);
      delete [] (Ipp8u*)pTmp;
      ippsPRNGSetAugment(pTmp=newBN(seedSize,rand32(augm,seedSize)),pCtx);
      delete [] (Ipp8u*)pTmp;


      delete [] seed;
      delete [] augm;
      return pCtx;
   }
   void deletePRNG(IppsPRNGState* pPRNG)
   { delete [] (Ipp8u*)pPRNG; }


   //
   // Prime Generator context
   //
   IppsPrimeState* newPrimeGen(int maxBits)
   {
      int size;
      ippsPrimeGetSize(maxBits, &size);
      IppsPrimeState* pCtx = (IppsPrimeState*)( new Ipp8u [size] );
      ippsPrimeInit(maxBits, pCtx);
      return pCtx;
   }
   void deletePrimeGen(IppsPrimeState* pPrimeG)
   { delete [] (Ipp8u*)pPrimeG; }


   //
   // RSA context
   //
   IppsRSAState* newRSA(int lenN, int lenP, IppRSAKeyType type)
   {
      int size;
      ippsRSAGetSize(lenN,lenP, type, &size);
      IppsRSAState* pCtx = (IppsRSAState*)( new Ipp8u [size] );
      ippsRSAInit(lenN,lenP, type, pCtx);
      return pCtx;
   }
   void deleteRSA(IppsRSAState* pRSA)
   { delete [] (Ipp8u*)pRSA; }


   //
   // DLP context
   //
   IppsDLPState* newDLP(int lenM, int lenL)
   {
      int size;
      ippsDLPGetSize(lenM, lenL, &size);
      IppsDLPState *pCtx= (IppsDLPState *)new Ipp8u[ size ];
      ippsDLPInit(lenM, lenL, pCtx);
      return pCtx;
   }
   void deleteDLP(IppsDLPState* pDLP)
   { delete [] (Ipp8u*)pDLP; }

