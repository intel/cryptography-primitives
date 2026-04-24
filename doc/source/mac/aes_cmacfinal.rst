.. _aes_cmacfinal:

AES_CMACFinal
=============


Completes computation of the MAC value.


Syntax
------


IppStatus ippsAES_CMACFinal(Ipp8u \*pMD, int mdLen, IppsAES_CMACState
\*pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pMD   
     - Pointer to the MAC value.
   * - mdLen   
     - Specified length of the MAC.
   * - pState   
     - Pointer to the IppsAES_CMACState context.




Description
-----------


The function completes calculation of the MAC of a message, stores the
result in the memory at the address of pMD, and prepares the context for
computation of the MAC of another message.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if mdLen is less than 1 or greater than cipher's data block length.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.



