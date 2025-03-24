.. _gfpsetelement:



GFpSetElement
=============


Assigns a value to an element of the finite field.


Syntax
------


IppStatus ippsGFpSetElement(const Ipp32u\* pA, int lenA,
IppsGFpElement\* pR, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the data array storing the finite field element.
   * -     lenA   
     -  Length of the element.
   * -     pR   
     -  Pointer to the context of the finite field element being assigned.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function copies (and converts if needed) the value from the
user-defined pA buffer to the IppsGFpElement context of the finite field
element. If pR is NULL, GFpSetElement assigns zero to the element.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     - Indicates an error condition in the following cases:
       
       * Either pR or pGFp is NULL.
       * The length of the element lenA is greater than zero and the pointer pA is NULL.
       
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the pGFp andpR context parameters does not match the operation.
   * -     ippStsSizeErr   
     - Indicates an error condition in the following cases:
     
       * lenA is not equal to the length of an element of the finite field.
       * The maximum length of the element stored in the context pR exceeds the maximum length of an element of the finite field specified by the context pGFp.
       
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the value contained in pA exceeds the modulus ``q`` of the basic prime finite field.



