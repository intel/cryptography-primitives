.. _ml-kem-key-gen:

ippsMLKEM_KeyGen
=================

Generates an encapsulation key and a corresponding decapsulation key.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_KeyGen(Ipp8u* pEncKey, Ipp8u* pDecKey, IppsMLKEMState* pMLKEMCtx,
                               Ipp8u* pScratchBuffer, IppBitSupplier rndFunc, void* pRndParam);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEncKey        
     - Pointer to the produced encapsulation key of ``384*k + 32`` bytes.
   * - pDecKey        
     - Pointer to the produced decapsulation key of ``786*k + 96`` bytes.
   * - pMLKEMCtx        
     - Pointer to the ML-KEM context.
   * - pScratchBuffer        
     - Pointer to the working buffer of size queried
       :ref:`ippsMLKEM_KeyGenBufferGetSize <ml-kem-buffers-get-size>`.
   * - rndFunc        
     - Optional function pointer to generate random numbers, can be ``NULL``.
   * - pRndParam        
     - Optional parameters for ``rndFunc``, can be ``NULL``.

Description
-----------

The function generates an encapsulation key and a corresponding decapsulation key. The size of
the output parameters depends on the selected scheme type and can be obtained using
:ref:`ippsMLKEM_GetInfo <ml-kem-get-info>` function.
The working buffer should be allocated with the size not less than provided by
:ref:`ippsMLKEM_KeyGenBufferGetSize <ml-kem-buffers-get-size>` function.

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
