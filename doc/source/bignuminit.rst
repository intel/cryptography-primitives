.. _bignuminit:


BigNumInit
==========


Initializes context and partitions allocated buffer.


Syntax
------


IppStatus ippsBigNumInit(int length, IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - length   
     - Size of the big number for the context initialization.
   * - pBN   
     - Pointer to the supplied buffer used to store the initialized context IppsBigNumState.




Description
-----------


The function initializes the context IppsBigNumState using the specified
buffer space and partitions the given buffer to store and execute
arithmetic operations on an integer big number of the length size.


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



.. rubric:: Related Information

:ref:`data-security-considerations`

