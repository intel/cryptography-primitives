.. _gfpexp:


GFpExp
======


Raises an element of the finite field to the specified power.


Syntax
------


IppStatus ippsGFpExp(const IppsGFpElement\* pA, const IppsBigNumState\*
pE, IppsGFpElement\* pR, IppsGFpState\* pGFp, Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the element of the finite field representing the base of the exponentiation.
   * -     pE   
     -  Pointer to the Big Number context storing the exponent.
   * -     pR   
     -  Pointer to the context of the resulting element of the finite field.
   * -     pGFp   
     -  Pointer to the context of the finite field.
   * -     pScratchBuffer   
     -  Pointer to the scratch buffer of size produced by *ippsGFpScratchBufferSize*.




Description
-----------


This function raises the element of the finite field to the given
non-negative power. The following pseudocode represents this operation:
``R = A``\ :sup:`E`. The finite field is specified by the context pGFp.
You can get the size of the scratch buffer by calling the function
*ippsGFpScratchBufferSize* with *nExponents* equal to at least 1.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the IppsGFpState, IppsBigNumState, and IppsGFpElement context parameters does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if pA or pR does not belong to the finite field specified by the context pGFp.



