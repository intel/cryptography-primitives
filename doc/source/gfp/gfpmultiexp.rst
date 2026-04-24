.. _gfpmultiexp:


GFpMultiExp
===========


Multiplies exponents of elements of the finite field.


Syntax
------


IppStatus ippsGFpMultiExp(const IppsGFpElement\* const ppElmA[], const
IppsBigNumState\* const ppE[], int nItems, IppsGFpElement\* pElemR,
IppsGFpState\* pGF, Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     ppElmA   
     -  Pointer to the array of contexts of the finite field elements representing the base of the exponentiation.
   * -     ppE   
     -  Pointer to the array of the Big Number contexts storing the exponents.
   * -     nItems   
     -  Number of exponents.
   * -     pElemR   
     -  Pointer to the context of the resulting element of the finite field.
   * -     pGFp   
     -  Pointer to the context of the finite field.
   * -     pScratchBuffer   
     -  Pointer to the scratch buffer of size produced by *ippsGFpScratchBufferSize*.




Description
-----------


This function multiplies exponents of elements of the finite field. The
finite field is specified by the context pGFp. You can get the size of 
the scratch buffer by calling the *ippsGFpScratchBufferSize* function with *nExponents* equal to at least *nItems* to get the valid *pScratchBuffer*.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters IppsGFpState, IppsBigNumState, and IppsGFpElement does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if any of the elements of ppElmA do not belong to the finite field specified by the context pGFp.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if nItems is less than 1 or greater than 6.



