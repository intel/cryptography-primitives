.. _ml-kem-encaps:

ippsMLKEM_Encaps
=================

Uses the encapsulation key to generate a shared secret key and an associated ciphertext.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_Encaps(const Ipp8u* pEncKey, Ipp8u* pCipherText, Ipp8u* pSharedSecret,
                               IppsMLKEMState* pMLKEMCtx, Ipp8u* pScratchBuffer,
                               IppBitSupplier rndFunc, void* pRndParam);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEncKey        
     - Pointer to the encapsulation key of ``384*k + 32`` bytes.
   * - pCipherText        
     - Pointer to the produced ciphertext of ``32*(d_{u}*k + d_{v})`` bytes.
   * - pSharedSecret
     - Pointer to the produced shared secret of ``32`` bytes
   * - pMLKEMCtx        
     - Pointer to the ML-KEM context.
   * - pScratchBuffer        
     - Pointer to the working buffer of size queried
       :ref:`ippsMLKEM_EncapsBufferGetSize <ml-kem-buffers-get-size>`.
   * - rndFunc        
     - Optional function pointer to generate random numbers, can be ``NULL``.
   * - pRndParam        
     - Optional parameters for ``rndFunc``, can be ``NULL``.

Description
-----------

The function generates a shared secret key and an associated ciphertext using the provided
encapsulation key. The size of the output parameters depends on the selected scheme type and
can be obtained using :ref:`ippsMLKEM_GetInfo <ml-kem-get-info>` function.
The working buffer should be allocated with the size not less than provided by
:ref:`ippsMLKEM_EncapsBufferGetSize <ml-kem-buffers-get-size>` function.

This function uses internally the random number generator (RNG) provided by the user through the ``rndFunc``
parameter, please see :ref:`User's Implementation of a RNG <users-implementation-of-a-pseudorandom-num-gen>`
for more information regarding creation the customer's defined RNG object. If ``rndFunc`` is ``NULL``, the internal
default random number generator based on ``RDSEED`` hardware instruction is used.

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
   * - ippStsNotSupportedModeErr
     - Unsupported ``RDSEED`` instruction.
   * - ippStsErr
     - Random bit sequence can't be generated.
   * - An error that may be returned by ``rndFunc``.
     - Problems with the user-defined random number generator.
