.. _gfpecesstart_sm2:


GFpECESStart_SM2
================


Starts the ECES SM2 encryption or decryption chain.


Syntax
------


IppStatus ippsGFpECESStart_SM2(IppsECES_StateSM2\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pState
     - Pointer to the buffer being initialized as the ECES context.




Description
-----------


The function starts a chain of the
:ref:`ippsGFpECESEncrypt_SM2 <gfpecesencrypt_sm2>`
or
:ref:`ippsGFpECESDecrypt_SM2 <gfpecesdecrypt_sm2>`
function calls. In fact, the functions starts computing the
authentication tag as required in :term:`SM2 PKE <[SM2 PKE]>`.


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



