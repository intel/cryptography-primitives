.. _gfpxgetsize:



GFpxGetSize
===========


Gets the size of the context of a GF(p\ :sup:`d`) field.


Syntax
------


IppStatus ippsGFpxGetSize(const IppsGFpState\* pParentGF, int degree,
int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pParentGF   
     -  Pointer to the context of the finite field GF(``p``) being extended.
   * -     degree   
     -  Degree of the extension.
   * -     pSize   
     -  Pointer to the buffer size, in bytes, needed for the IppsGFpState context.




Description
-----------


The function returns the size of the buffer associated with the
IppsGFpState context, suitable for storing data for the finite field
GF(``p``\ :sup:`d`) determined by the extension degree ``d`` supplied in
the degree parameter.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the IppsGFpState context parameter does not match the operation.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if the degree of the extension is greater than or equal to 9 or is less than 2.



