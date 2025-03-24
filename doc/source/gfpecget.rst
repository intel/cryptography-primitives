.. _gfpecget:

GFpECGet
========


Extracts the parameters of an elliptic curve over a finite field from
the context.


Syntax
------


IppStatus ippsGFpECGet(IppsGFpState*\* const ppGF, IppsGFpElement\* pA,
IppsGFpElement\* pB, const IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -  ppGF   
     - Double pointer to the context of the elliptic curve underlying finite field.
   * - pA   
     - Pointer to a copy of the coefficient ``A`` of the equation defining the elliptic curve.
   * - pB   
     - Pointer to a copy of the coefficient ``B`` of the equation defining the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function extracts parameters of the elliptic curve from the input
IppsGFpECState context. You can get any combination of the following
parameters: a reference to the underlying field and copies of the ``A``
and ``B`` coefficients. To turn off extraction of a particular parameter
of the elliptic curve, set the appropriate function parameter to NULL.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if pEC is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition in the following cases:
       
       * ``IppsGFpECState`` context parameter does not match the operation.
       * Either pA or pB is not zero and the corresponding context parameter does not match the operation.
       
   * - ippStsOutOfRangeErr   
     - Indicates an error if either pA or pB does not belong to the finite field over which the elliptic curve is initialized.



