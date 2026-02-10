.. _ml-dsa-key-gen:

ippsMLDSA_KeyGen
=================

Generates public and private keys.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_KeyGen(Ipp8u* pPubKey,
                               Ipp8u* pPrvKey,
                               IppsMLDSAState* pMLDSAState,
                               Ipp8u* pScratchBuffer,
                               IppBitSupplier rndFunc,
                               void* pRndParam);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pPubKey
     - Pointer to the produced public key.
   * - pPrvKey
     - Pointer to the produced private key.
   * - pMLDSAState
     - Pointer to the ML-DSA state.
   * - pScratchBuffer
     - Pointer to the working buffer of size queried
       :ref:`ippsMLDSA_KeyGenBufferGetSize <ml-dsa-buffers-get-size>`.
   * - rndFunc
     - Optional function pointer to generate random numbers, can be ``NULL``.
   * - pRndParam
     - Optional parameters for ``rndFunc``, can be ``NULL``.

Description
-----------

The function generates a public key and a private key. The size of
the output parameters depends on the selected scheme type and can be obtained using
:ref:`ippsMLDSA_GetInfo <ml-dsa-get-info>` function.
The working buffer should be allocated with the size not less than provided by
:ref:`ippsMLDSA_KeyGenBufferGetSize <ml-dsa-buffers-get-size>` function.

This function internally uses the random number generator (RNG) provided by the user through the ``rndFunc``
parameter, please see :ref:`User's Implementation of a RNG <users-implementation-of-a-pseudorandom-num-gen>`
for more information on creating a customer-defined RNG object. If ``rndFunc`` is ``NULL``, an internal
default random number generator based on the ``RDSEED`` hardware instruction is used.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_DSA`` macro before including the ``ippcp.h`` header file. See
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
     - ``pMLDSAState`` was not initialized.
   * - ippStsMemAllocErr
     - An internal functional error. If this output status appears, update to the latest version
       of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
   * - ippStsNotSupportedModeErr
     - Unsupported ``RDSEED`` instruction.
   * - ippStsErr
     - Random bit sequence can't be generated.
   * - An error that may be returned by ``rndFunc``.
     - Problems with the user-defined random number generator.
