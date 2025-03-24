.. _arcfourcheckkey:


ARCFourCheckKey
===============


Checks weakness of a user-defined key (deprecated).


Syntax
------


IppStatus ippsARCFourCheckKey(const Ipp8u\* pKey, int keyLen, IppBool\*
pIsWeak);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pKey   
     - Pointer to the user-defined key.
   * - keyLen   
     - Length of the user-defined key in octets.
   * - pIsWeak   
     - Pointer to the result of checking.




Description
-----------


.. note::


   This function is deprecated.


The function checks weakness of user-defined key. The function allows to
make sure that the supplied key provides sufficient security.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if keyLen <1 or keyLen >256.



