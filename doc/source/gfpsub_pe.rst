.. _gfpsub_pe:



GFpSub_PE
=========


Subtracts an element of the finite field from an element of its parent
field.


Syntax
------


IppStatus ippsGFpSub_PE(const IppsGFpElement\* pA, const
IppsGFpElement\* pParentB, IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the minuend, an element of the finite field.
   * -     pParentB   
     -  Pointer to the context of the subtrahend, an element of the parent finite field.
   * -     pR   
     -  Pointer to the context of the resulting element of the finite field.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function computes the difference of the elements of the finite
field specified by the context pGFp and its ground finite field. The
following pseudocode represents this operation: ``R = A - B``.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * -     ippStsOutOfRangeErr   
     - Indicates an error condition in the following cases:
       
       * The element pA does not belong to the finite field specified by the context pGFp.
       * The element pParentB does not belong to the ground field of the finite field specified by the context pGFp.
       
   * -     ippStsBadArgErr   
     -  Indicates an error condition if the context pGFp does not specify a prime field.



