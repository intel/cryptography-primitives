.. _aes_gcmprocessaad:


AES_GCMProcessAAD
=================


Processes additional authenticated data of a given length according to
the GCM specification.


Syntax
------


IppStatus ippsAES_GCMProcessAAD(const Ipp8u\* pAAD, int ivAAD,
IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pAAD
     - Pointer to the additional authenticated data.
   * - ivAAD
     - Length of additional authenticated data \*pAAD (in bytes).
   * - pState
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function processes ivAAD bytes of additional authenticated data
\*pAAD as specified in :term:`NIST SP 800-38D <[NIST SP 800-38D]>`.


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
     - Indicates an error condition if ivAAD is less than zero.
   * - ippStsBadArgErr
     - Indicates an error condition if ivAAD is zero and pState is not GcmInit or GcmIVProcessing. This means that the function call sequence is illegal.



