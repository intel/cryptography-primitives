.. _gfpgetsize:

GFpGetSize
==========


Gets the size of the context of a GF(q) field.


Syntax
------


IppStatus ippsGFpGetSize(int febitSize, int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     febitSize   
     -  Size, in bytes, of the odd prime number ``q`` (modulus of GF(``q``)).
   * -     pSize   
     -  Pointer to the buffer size, in bytes, needed for the IppsGFpState context.




Description
-----------


This function returns the size of the buffer associated with the
IppsGFpState context, which you can use to store data of the finite
field GF(``q``) determined by the odd prime number ``q`` of size not
greater than febitSize bit.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsSizeErr   
     -  Indicates an error condition if febitSize is less than 2 or greater than 1024.



