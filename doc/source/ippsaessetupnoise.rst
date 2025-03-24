.. _ippsaessetupnoise:

ippsAESSetupNoise
=================

Turns on the mitigation for AES-ECB mode - the ``ippsAESDecryptECB`` and ``ippsAESEncryptECB`` processing functions.

Syntax
-------

IppStatus ippsAESSetupNoise(Ipp32u noiseLevel, IppsAESSpec* pCtx);

Include Files
-------------
``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - noiseLevel
     - The value of this parameter is directly proportional to the amount of noise to be injected.
       Increasing the noiseLevel by 1 means the delay (performance impact) is doubled.
   * - pCtx
     - Pointer to the ``IppsAESSpec`` context.



Description
-----------
``ippsAESSetupNoise`` saves noise parameters in the pCtx context structure. A user-adjustable parameter is noiseLevel, it can be varied from 0 to 4.
When the processing function is called with this context it checks the context for noiseLevel value and if it is non-zero, the function enables mitigation
mechanism: the data passed to the processing function is divided into chunks, and each chunk is followed by probabilistic noise injection.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNullPtrErr
     - Indicates an error condition if pCtx pointer is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the pCtx parameter does not match the operation.
   * - ippStsLengthErr
     - Indicates an error if noiseLevel > 4.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the Intel® AES New Instructions (Intel® AES-NI) and Vector AES Instructions (VAES) instructions are not available on the target processor.
   * - ippStsNoErr
     - Indicates no error.


Any other value indicates an error or a warning.

