.. _bignumgetsize:


BigNumGetSize
=============


Gets the size of the IppsBigNumState context in bytes.


Syntax
------


IppStatus ippsBigNumGetSize(int length, int\* psize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - length   
     - The length of the integer big number in Ipp32u.
   * - pSize   
     - Pointer to the size, in bytes, of the buffer required for initialization.




Description
-----------


The function specifies the buffer size required to define a structured
working buffer of the context IppsBigNumState for the storage and
operations on an integer big number in bytes.


.. note::


   For security reasons, the length of the big number is restricted to
   16 kilobits.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if length is less than or equal to 0 or greater than 512.



