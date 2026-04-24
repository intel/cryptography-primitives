.. _gfpsqr:


GFpSqr
======


Computes the square of an element of the finite field.


Syntax
------


IppStatus ippsGFpSqr(const IppsGFpElement\* pA, IppsGFpElement\* pR,
IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the finite field element.
   * -     pR   
     -  Pointer to the context of the resulting element of the finite field.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function computes the square of a given element of the finite
field. The following pseudocode represents this operation:
``R = A``\ :sup:`2`. The finite field is specified by the context pGFp.


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
     -  Indicates an error condition if pA does not belong to the finite field specified by the context pGFp.



