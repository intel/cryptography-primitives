.. _gfpsqrt:


GFpSqrt
=======


Computes the square root of an element of the finite field.


Syntax
------


IppStatus ippsGFpSqrt(const IppsGFpElement\* pA, IppsGFpElement\* pR,
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


This function computes the square root of a given element of the
GF(``p``) field. The following pseudocode represents this operation:
``R ⋅ R = A``. The finite field is specified by the pGFp context.


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
   * -     ippStsBadArgErr   
     -  Indicates an error condition the finite field specified by the context pGFp is not prime.
   * -     ippStsQuadraticNonResidueErr   
     -  Indicates an error condition if pA is a square non-residue element.



