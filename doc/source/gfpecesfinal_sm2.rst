.. _gfpecesfinal_sm2:


GFpECESFinal_SM2
================


Completes the ECES SM2 encryption or decryption chain.


Syntax
------


IppStatus ippsGFpECESFinal_SM2(Ipp8u\* pTag, int tagLen,
ippsECES_StateSM2\* pState);


Include Files
-------------


``ippcp.h``

Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pTag   
     - Pointer to the tag buffer.
   * - tagLen   
     - Requested length of the authentication tag.
   * - pState   
     - Pointer to the buffer being initialized as the ECES context.




Description
-----------


The function completes the Elliptic Curve Encryption Scheme (ECES) SM2
algorithm and returns the computed authentication tag.


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
     - Indicates an error condition if tagLen<0 or tagLen>32.
   * - ippStsShareKeyErr   
     - Indicates an error condition if all generated key gammas were zeros in the encryption or decryption steps.



