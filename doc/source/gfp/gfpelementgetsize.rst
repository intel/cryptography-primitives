.. _gfpelementgetsize:


GFpElementGetSize
=================


Gets the size of the context for an element of the finite field.


Syntax
------


IppStatus ippsGFpElementGetSize(const IppsGFpState\* pGFp, int\*
pElementSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pGFp   
     -  Pointer to the context of the finite field.
   * -     pElementSize   
     -  Pointer to the buffer size, in bytes, needed for the IppsGFpElement context.




Description
-----------


This function returns the size of the buffer associated with the
IppsGFpElement context, suitable for storing an element of the finite
field specified by the context pGFp.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the pGFp context parameter does not match the operation.



