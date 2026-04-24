.. _gfpadd_pe:


GFpAdd_PE
=========


Computes the sum of an element of the finite field and an element of its
parent field.


Syntax
------


IppStatus ippsGFpAdd_PE(const IppsGFpElement\* pA, const
IppsGFpElement\* pParentB, IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the first element of the finite field to be added.
   * - pParentB   
     - Pointer to the context of the second element to be added, which is an element of the parent finite field.
   * - pR   
     - Pointer to the context of the resulting element of the finite field.
   * - pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


The function computes the sum of the elements of the finite field
specified by the context pGFp and its ground finite field. The following
pseudocode represents this operation: ``R = A + B``.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of IppsGFpState or IppsGFpElement context parameter does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition in the following cases:
       
       * the element pA does not belong to the finite field specified by the context pGFp.
       * the element pParentB does not belong to the ground field of the finite field specified by the context pGFp.
       
   * - ippStsBadArgErr   
     - Indicates an error condition if the context pGFp does not specify a prime field.



