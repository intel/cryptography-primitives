.. _gfpcpyelement:


GFpCpyElement
=============


Copies one element of the finite field to another element.


Syntax
------


IppStatus ippsGFpCpyElement(const IppsGFpElement\* pA, IppsGFpElement\*
pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the finite field element being copied.
   * - pR   
     - Pointer to the context of the finite field element being changed.
   * - pGFp   
     - Pointer to the context of the finite field.




Description
-----------


This function copies one element of the finite field to another. The
finite field is specified by the context pGFp.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if the input elements do not belong to the finite field specified by the context pGFp.



