.. _lms-key-gen:

LMS Key Generation
==================

Performs the LMS private and public keys generation.

Syntax
------

.. code:: cpp

    IppStatus ippsLMSKeyGen (IppsLMSPrivateKeyState* pPrvKey,
                             IppsLMSPublicKeyState* pPubKey,
                             IppBitSupplier rndFunc,
                             void* pRndParam,
                             Ipp8u* pBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -  pPrvKey
     -  Pointer to the initialized ``IppsLMSPrivateKeyState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSPrivateKeyStateGetSize <lms-states-get-size>` function.
   * -  pPubKey
     -  Pointer to the initialized ``IppsLMSPublicKeyState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSPublicKeyStateGetSize <lms-states-get-size>` function.
   * -  rndFunc
     -  Pointer to the random number generator function that is used for private key generation.
        The function should be defined as:
        ``IppStatus rndFunc(Ipp8u* pRnd, int size, void* pRndParam)``.
        This function must be cryptographically secure.
        Security strength must be ``8*n`` bits, where ``n`` is the length of the hash function output.
        The ``size`` parameter is the size of the buffer in bytes.
        The ``pRndParam`` parameter is a pointer to the user-defined parameter.
        If ``rndFunc`` is NULL then ``TRNGenRDSEED`` is used as a random number generator.
   * -  pRndParam
     -  Pointer to the user-defined parameter for the random number generator function.
        It can be a NULL pointer.
   * -  pBuffer
     -  Pointer to the temporary buffer. Size is greater or equal to
        the value returned by
        the :ref:`ippsLMSKeyGenBufferGetSize <lms-buffer-get-size>` function.

Description
-----------

This function generates private and public LMS keys.

This function uses internally the random number generator (RNG) provided by
the user through the ``rndFunc`` parameter, please see
:ref:`User's Implementation of a RNG <users-implementation-of-a-pseudorandom-num-gen>`
for more information regarding creation the customer's defined RNG object.
If ``rndFunc`` is ``NULL``, the internal default random number generator
based on ``RDRAND`` hardware instruction is used.

``pPrvKey`` and ``pPubKey`` are output parameters.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   You need to enable the ``IPPCP_PREVIEW_LMS`` macro to use the feature.
   For more information, see :ref:`Preview Features <experimental>`.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pPrvKey`` or ``pPubKey`` or ``pBuffer`` is a NULL pointer.
   * - ippStsContextMatchErr
     - ``pPrvKey`` or ``pPubKey`` contexts are invalid.
   * - ippStsBadArgErr
     - wrong LMS or LMOTS parameters.
