.. _modinv_bn:




ModInv_BN
=========


Computes multiplicative inverse of a positive integer big number with
respect to specified modulus.


Syntax
------


IppStatus ippsModInv_BN(IppsBigNumState\* pA, IppsBigNumState\* pM,
IppsBigNumState\* pInv);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the integer big number of IppsBigNumState.
   * -     pM   
     -  Pointer to the modulus integer of IppsBigNumState.
   * -     pInv   
     -  Pointer to the multiplicative inverse.




Description
-----------


The function uses the extended Euclidean algorithm to compute the
multiplicative inverse of a given positive integer big number pA with
respect to the modulus specified by another positive integer big number
pM, where gcd (pA, pM) = 1.


The following pseudocode represents this function:


compute pInv such that pInv\*pA = 1 modpM.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if pA is less than or equal to 0.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsBadModulusErr   
     -  Indicates an error condition if the modulus pA is greater than pM, or gcd (pA,pM) is greater than 1, or pM is less than or equal to 0.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*pInv is smaller than the length of IppsBigNumState \*pM.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.
   * -     ippStsScaleRangeErr   
     -  Indicates an error condition if pA is greater than or equal to pM




.. note::


   The size of IppsBigNumState \*pInv should not be less than the length
   of IppsBigNumState \*pM.

