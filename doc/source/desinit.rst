.. _desinit:


DESInit
=======


Initializes user-supplied memory as the IppsDESSpec context for future
use (deprecated).


Syntax
------


IppStatus ippsDESInit(const Ipp8u\* pKey, IppsDESSpec\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pKey   
     - Pointer to the DES key.
   * - pCtx   
     - Pointer to the IppsDESSpec contextbeing initialized.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES.


This function initializes the memory pointed by pCtx as IppsDESSpec
context. In addition, the function uses the key to provide all necessary
key material for both encryption and decryption operations.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.



