.. _aes_cmacgettag:

AES_CMACGetTag
==============


Computes the MAC value of the processed part of the message.


Syntax
------


IppStatus ippsAES_CMACGetTag(Ipp8u\* pMD, int mdLen, const
IppsAES_CMACState \*pState);


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


The function computes the MAC value based on the current context. A call
to this function retains the possibility to update the MAC value.


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



