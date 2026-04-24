.. _gfpsetelementoctstring:


GFpSetElementOctString
======================


Assigns a value from the input octet string to an element of the finite
field.


Syntax
------


IppStatus ippsGFpSetElementOctString(const Ipp8u\* pStr, int strSize,
IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pStr   
     -  Pointer to the octet string.
   * -     strSize   
     -  Size of the octet string buffer in bytes.
   * -     pR   
     -  Pointer to the context of the finite field element.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function assigns a value from the input octet string to an element
of the finite field.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     - Indicates an error condition in any of the following cases:
       
       * Either pR or pGFp is NULL.
       * The length of the string is greater than zero and the pointer pStr is NULL.
       
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the pGFp and pR context parameters does not match the operation.
   * -     ippStsSizeErr   
     - Indicates an error condition in any of the following cases:
       
       * strSize exceeds the length of an element of the finite field.
       * strSize ≤ 0.
       * The maximum length of the element stored in the context pR exceeds the maximum length of an element of the finite field specified by the context pGFp.
       
   * -     ippStsOutOfRangeErr   
     - Indicates an error condition in any of the following cases:
       
       * The length of the element stored in the context pR is not equal to the length of an element of the finite field specified by the context pGFp.
       * The value defined by pStr exceeds the modulus q of the basic prime finite field.



