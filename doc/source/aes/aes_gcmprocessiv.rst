.. _aes_gcmprocessiv:



AES_GCMProcessIV
================


Processes an initial vector of a given length according to the GCM
specification.


Syntax
------


IppStatus ippsAES_GCMProcessIV(const Ipp8u\* pIV, int ivLen,
IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pIV
     - Pointer to the initialization vector.
   * - ivLen
     - Length of the initialization vector \*pIV (in bytes).
   * - pState
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function processes ivLen bytes of the initial vector \*pIV as
specified in :term:`NIST SP 800-38D <[NIST SP 800-38D]>`.


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
     - Indicates an error condition if the length of the initialization vector is less than or equal to zero.
   * - ippStsScaleRangeErr
     - Indicates an error condition if the accumulated initialization vector length overflows.
   * - ippStsBadArgErr
     - Indicates an error condition if the pState parameter value is not GcmInit or GcmIVProcessing. This means that the function call sequence is illegal.



