.. _gfpecset:



GFpECSet
========


Sets up the parameters of an elliptic curve over a finite field.


Syntax
------


IppStatus ippsGFpECSet(const IppsGFpElement\* pA, const IppsGFpElement\*
pB, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the coefficient ``A`` of the equation defining the elliptic curve.
   * - pB   
     - Pointer to the coefficient ``B`` of the equation defining the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function assigns input values to the parameters of the elliptic
curve in the IppsGFpECState context, if they are supplied.


.. note::


   Only the ``pEC`` parameter is required. You can omit the other parameters
   by setting their values to NULL or zero.


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
       * pA or pB is not zero, and the corresponding context parameter does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if pA or pB does not belong to the finite field specified by the pGFp context.



