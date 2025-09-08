.. _ml-kem-decaps:

ippsMLKEM_Decaps
=================

Uses the decapsulation key to produce a shared secret key from a ciphertext.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_Decaps(const Ipp8u* pDecKey, const Ipp8u* pCipherText,
                               Ipp8u* pSharedSecret, IppsMLKEMState* pMLKEMCtx,
                               Ipp8u* pScratchBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pDecKey        
     - Pointer to the decapsulation key of ``786*k + 96`` bytes.
   * - pCipherText        
     - Pointer to the ciphertext of ``32*(d_{u}*k + d_{v})`` bytes.
   * - pSharedSecret        
     - Pointer to the produced shared secret of ``32`` bytes
   * - pMLKEMCtx        
     - Pointer to the ML-KEM context.
   * - pScratchBuffer        
     - Pointer to the working buffer of size queried
       :ref:`ippsMLKEM_DecapsBufferGetSize <ml-kem-buffers-get-size>`.

Description
-----------

The function produces a shared secret using provided decapsulation key and the ciphertext. The
size of the output parameters depends on the selected scheme type and can be obtained using
:ref:`ippsMLKEM_GetInfo <ml-kem-get-info>` function.
The working buffer should be allocated with the size not less than provided by
:ref:`ippsMLKEM_DecapsBufferGetSize <ml-kem-buffers-get-size>` function.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_KEM`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Any of the input pointers is ``NULL``.
   * - ippStsContextMatchErr
     - ``pMLKEMCtx`` was not initialized.
   * - ippStsMemAllocErr 
     - An internal functional error. If this output status appears, update to the latest version
       of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
   * - ippStsOutOfRangeErr
     - An internal functional error. If this output status appears, update to the latest version
       of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
