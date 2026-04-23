.. _aes_gcmgettag:


AES_GCMGetTag
=============


Generates the authentication tag in the GCM mode.


Syntax
------


IppStatus ippsAES_GCMGetTag (Ipp8u\* pTag, int tagLen, const
IppsAES_GCMState\* pState);


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
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function generates and computes the authentication tag of length
tagLen according to GCM as specified in :term:`NIST SP 800-38D <[NIST SP 800-38D]>`. A
call to ippsAES_GCMGetTag does not stop the process of authenticated
encryption/decryption.


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
     - Indicates an error condition if tagLen <1 or taglen >16.



