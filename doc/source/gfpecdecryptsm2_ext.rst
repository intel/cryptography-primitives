.. _gfpecdecryptsm2_ext:

GFpECDecryptSM2_Ext
===================

The function encrypts the input text based on the SM2 protocol.

Syntax
-------

IppStatus ippsGFpECDecryptSM2_Ext(Ipp8u * pOut, int maxOutLen, int * pOutSize, const Ipp8u * pInp, int inpLen, const IppsBigNumState * pPrvKey,                         IppsGFpECState * pEC, Ipp8u * pScratchBuffer) 

 

Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pOut 
     - Pointer output cipher text.
   * - maxOutLen   
     - Available cipher-size container. 
   * - pOutSize
     - Size of the cipher text filled in the container 
       
       * 0 - if the function ends with an error
       * other (>0) - if the function ends with OK
       
   * - pInp
     - Pointer message encrypt.
   * - inpLen
     - Message size encrypt.
   * - pPrvKey
     - Pointer to the private keys of the elliptic curve.
   * - pEC
     - Pointer to the elliptic curve context.
   * - pScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize* for the elliptic curve.


Description
-----------

The function comes with the decrypted text according to the SM2 Encrypt protocol. This implementation is based on the [GM/T 0003.4-2012 SM2] standard. 

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 2 to get the valid *pScratchBuffer*.

Return Values 
-------------

.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsContextMatchErr 
     - Indicates an error condition if the ``IppsGFpECState`` context parameter does not match the operation.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter defines an elliptic curve over an extension of the prime finite field.
   * - ippStsOutOfRangeErr
     - Indicates an error condition if the invalid input argument range - inpLen < 0 or maxOutLen is not enough for the encryption.
   * - ippStsInvalidPrivateKey
     - Indicates an error condition if the secret key is not within (0, order).

