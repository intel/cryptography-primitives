.. _gfpelementinit:



GFpElementInit
==============


Initializes the context of an element of the finite field.


Syntax
------


IppStatus ippsGFpElementInit(const Ipp32u\* pA, int nsA,
IppsGFpElement\* pR, IppsGFpState\* pGF);


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
     -  Pointer to the context of the finite field element being initialized.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function initializes the memory buffer pR associated with the
IppsGFpElement context and sets up the specific element of the finite
field specified by the pGFp context. The initialized IppsGFpElement
context is used in all the operations with this element of the finite
field.


If the lenA parameter value equals zero, the function initializes a zero
element. If the value is less than zero, the function fails.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     - Indicates an error condition in the following cases:
       
       * lenA is not zero and any of the specified pointers is NULL.
       * lenA is zero and pR or pGFp is NULL.
       
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the pGFp context parameter does not match the operation.
   * -     ippStsSizeErr   
     -  Indicates an error condition iflenA ≤ 0.



