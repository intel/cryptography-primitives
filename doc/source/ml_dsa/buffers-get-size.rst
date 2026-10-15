.. _ml-dsa-buffers-get-size:

API to query working buffers size
=================================

Query the size of the working buffers.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_KeyGenBufferGetSize(int* pSize, const IppsMLDSAState* pMLDSAState);
    IppStatus ippsMLDSA_SignBufferGetSize(int* pSize, const IppsMLDSAState* pMLDSAState);
    IppStatus ippsMLDSA_VerifyBufferGetSize(int* pSize, const IppsMLDSAState* pMLDSAState);
    IppStatus ippsMLDSA_Verify_Mu_BufferGetSize(int* pSize, const IppsMLDSAState* pMLDSAState);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the buffers size.
   * - pMLDSAState
     - Pointer to the initialized ML-DSA context

Description
-----------

``ippsMLDSA_KeyGenBufferGetSize`` queries the size for working buffer required for the
``ippsMLDSA_KeyGen`` function.

``ippsMLDSA_SignBufferGetSize`` queries the size for working buffer required for the
``ippsMLDSA_Sign`` function.

``ippsMLDSA_VerifyBufferGetSize`` queries the size for working buffer required for the
``ippsMLDSA_Verify`` function.

``ippsMLDSA_Verify_Mu_BufferGetSize`` queries the size for working buffer required for the
``ippsMLDSA_Verify_Mu`` function.

Allocated memory should be passed directly to the processing API.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pSize`` or ``pMLDSAState`` are ``NULL`` pointers.
   * - ippStsContextMatchErr
     - ``pMLDSAState`` was not initialized.
