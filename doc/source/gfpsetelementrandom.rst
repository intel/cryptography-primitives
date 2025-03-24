.. _gfpsetelementrandom:


GFpSetElementRandom
===================


Assigns a random value to an element of the finite field.


Syntax
------


IppStatus1 ippsGFpSetElementRandom(IppsGFpElement\* pR, IppsGFpState\*
pGFp, IppBitSupplier rndFunc, void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pR   
     -  Pointer to the context of the finite field element.
   * -     pGFp   
     -  Pointer to the context of the finite field.
   * -     rndFunc   
     -  Pseudorandom number generator.
   * -     pRndParam   
     -  Pointer to the context of the pseudorandom number generator.




Description
-----------


This function assigns a random value to an element of the finite field.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the pointers pR, pGFp and rndFunc is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of pGFp or pR context parameters does not match the operation.
   * -     ippStsErr   
     - Indicates an error condition in the following cases:
       
       * A call to the ``rndFunc()`` function returns a status value other than ``ippStsNoErr``.
       * The maximum length of the element stored in the context pR exceeds the maximum length of an element of the finite field specified by the context pGFp.
       
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the length of the element stored in the context pR is not equal to the length of an element of the finite field specified by the context pGFp.



