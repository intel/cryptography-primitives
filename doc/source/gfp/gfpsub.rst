.. _gfpsub:



GFpSub
======


Subtracts two elements of the finite field.


Syntax
------


IppStatus ippsGFpSub(const IppsGFpElement\* pA, const IppsGFpElement\*
pB, IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the minuend element of the finite field.
   * -     pB   
     -  Pointer to the context of the subtrahend element of the finite field.
   * -     pR   
     -  Pointer to the context of the resulting element of the finite field.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function computes the difference of the elements of the finite
field. The following pseudocode represents this operation:
``R = A - B``. The finite field is specified by the context pGFp.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if pA or pB does not belong to the finite field specified by the context pGFp.



