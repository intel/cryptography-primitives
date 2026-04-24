.. _gfpecdecryptsm2_ext_decmsgsize:

GFpECDecryptSM2_Ext_DecMsgSize
==============================

Gets the buffer size of the SM2 Decrypt message text.

Syntax
-------

IppStatus ippsGFpECDecryptSM2_Ext_DecMsgSize(const IppsGFpECState * pEC, int ptMsgSize, int * pSize)

Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pEC
     - Pointer to the elliptic curve context.
   * - ptMsgSize  
     - Decrypted text size.
   * - pSize
     - Pointer to the size, in bytes, of the buffer cipher text.


Description
-----------

The function computes the size of the buffer in bytes for the message text to be used later. The pEC parameter represents a properly initialized elliptic curve using the SM2 Decrypt.

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
     - Indicates an error condition if ctMsgSize < 0. 

