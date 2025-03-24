.. _gfpadd:


GFpAdd
======


Computes the sum of two elements of the finite field.


Syntax
------


IppStatus ippsGFpAdd(const IppsGFpElement\* pA, const IppsGFpElement\*
pB, IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the first element of the finite field to be added.
   * - pB   
     - Pointer to the context of the second element of the finite field to be added.
   * - pR   
     - Pointer to the context of the resulting element of the finite field.
   * - pGFp   
     - Pointer to the context of the finite field.




Description
-----------


This function computes the sum of the elements of the finite field. The
following pseudocode represents this operation: ``R = A + B``. The
finite field is specified by the pGFp context.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if either the pA or pB element does not belong to the finite field specified by the context pGFp.



