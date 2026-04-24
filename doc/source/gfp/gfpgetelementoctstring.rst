.. _gfpgetelementoctstring:


GFpGetElementOctString
======================


Extracts an element of the finite field from the context to the output
octet string.


Syntax
------


IppStatus ippsGFpGetElementOctString(const IppsGFpElement\* pA, Ipp8u\*
pStr, int strSize, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the finite field element.
   * -     pStr   
     -  Pointer to the octet string.
   * -     strSize   
     -  Size of the octet string buffer in bytes.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function extracts the element of the finite field from the context
to the octet string. If the string length is not enough to hold the
whole finite field element, the function writes only a part of the
element.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the pGFp and pA context parameters does not match the operation.
   * -     ippStsSizeErr   
     -  Indicates an error if the length of the string is zero or negative.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the element pA does not belong to the finite field specified by the context pGFp.



