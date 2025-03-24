.. _aes_ccmgettag:

AES_CCMGetTag
=============


Generates the message authentication tag in the CCM mode.


Syntax
------


IppStatus ippsAES_CCMGetTag (Ipp8u\* pTag, int tagLen, const
IppsAES_CCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pTag
     - Pointer to the authentication tag.
   * - tagLen
     - Length of the authentication tag \*pTag (in bytes).
   * - pState
     - Pointer to the IppsAES_CCMState context.




Description
-----------


The function generates and computes the authentication tag of length
tagLen bytes in the CCM mode as specified in :term:`NIST SP 800-38C <[NIST SP 800-38C]>`. The
ippsRijndael128GCMGetTag function does not stop the
encryption/decryption and authentication process.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsLengthErr
     - Indicates an error condition if tagLen is less than one or tagLen
       exceeds the tag length specified in the previous call
       to :ref:`AES_CCMTagLen <aes_ccmtaglen>`.



