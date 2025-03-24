.. _gfpgetelement:


GFpGetElement
=============


Extracts an element of the finite field from the context.


Syntax
------


IppStatus ippsGFpGetElement(const IppsGFpElement\* pA, Ipp32u\* pDataA,
int lenA, IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the finite field element.
   * -     pDataA   
     -  Pointer to the data array to copy the finite field element from.
   * -     lenA   
     -  Length of the data array.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function copies the element of the finite field from the
IppsGFpElement context to the user-defined pDataA buffer. The finite
field is specified by the context pGFp.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  The input elements do not belong to the finite field specified by the context pGFp
   * -     ippStsSizeErr   
     -  The length of the data array is negative or less than the finite field element length.



