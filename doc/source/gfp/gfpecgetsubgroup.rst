.. _gfpecgetsubgroup:


GFpECGetSubgroup
================


Extracts the parameters (base point and its order) that define an
elliptic curve point subgroup.


Syntax
------


IppStatus ippsGFpECGetSubGroup(IppsGFpState*\* const ppGF,
IppsGFpElement\* pX, IppsGFpElement\* pY, IppsBigNumState\*
pOrder,IppsBigNumState\* pCofactor, const IppsGFpECState\* pEC);


Include Files
-------------


ippcp.h


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - ppGF   
     - Pointer to the context of the underlying finite field.
   * - pX, pY   
     - Pointers to the ``X`` and ``Y`` coordinates of the base point of the elliptic curve.
   * - pOrder    
     - Pointer to the big number context storing the order of the base point.
   * - pCofactor   
     - Pointer to the big number context storing the cofactor.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function extracts parameters of an elliptic curve subgroup. You can
get any combination of the following parameters: the ``X`` and ``Y``
coordinates, the order of the base point, and the value of the cofactor.
To turn off extraction of a particular parameter of the elliptic curve,
set the appropriate function parameter to NULL.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the specified pointer pEC is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition in the following cases:
       
       * ``IppsGFpECState`` context parameter does not match the operation.
       * Any of the pointers to elliptic curve parameters is not zero and the corresponding context parameter does not match the operation.
       
   * - ippStsOutOfRangeErr   
     - Indicates an error if the base point coordinates (pX, pY) do not belong to the finite field over which the elliptic curve is initialized.
   * - ippStsLengthErr   
     - Indicates an error condition in the following cases:
       
       * The size of the base point order exceeds the maximal size of the order for the given curve.
       * The bit size of the cofactor exceeds the bit size of the element of the finite field over which the elliptic curve is initialized.



