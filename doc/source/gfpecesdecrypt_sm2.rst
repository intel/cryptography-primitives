.. _gfpecesdecrypt_sm2:


GFpECESDecrypt_SM2
==================


Decrypts the ciphertext data buffer.


Syntax
------


IppStatus ippsGFpECESDecrypt_SM2(const Ipp8u\* pInput, Ipp8u\* pOutput,
int len, IppsECES_StateSM2\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pInput   
     - Pointer to the ciphertext data buffer.
   * - pOutput   
     - Pointer to the plaintext data buffer.
   * - len   
     - Length of the input and output buffers.
   * - pState   
     - Pointer to the buffer being initialized as the ECES context.




Description
-----------


The function decrypts the ciphertext data buffer and updates the
authentication tag. For more information on decryption and
authentication, see :term:`SM2 PKE <[SM2 PKE]>`


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr    
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsECES_StateSM2 context parameter does not match the operation.
   * - ippStsSizeErr   
     - Indicates an error condition if the len parameter has a negative value.



