.. _arcfourinit:



ARCFourInit
===========


Initializes user-supplied memory as the IppsARCFourState context for
future use (deprecated).


Syntax
------


IppStatus ippsARCFourInit(const Ipp8u\* pKey, int keyLen,
IppsARCFourState\* pCtx);


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
   * - pCtx   
     - Pointer to the IppsARCFourState context being initialized.




Description
-----------


.. note::


   This function is deprecated.


The function initializes the memory pointed by pCtx as IppsARCFourState
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
   * - ippStsLengthErr    
     - Indicates an error condition if keyLen <1 or keyLen >256.



.. rubric:: Related Information

:ref:`data-security-considerations`
