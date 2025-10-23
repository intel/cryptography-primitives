.. _xmss-key-gen:

XMSS Key Generation
===================

Performs the XMSS private and public keys generation.

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSKeyGen (IppsXMSSPrivateKeyState* pPrvKey,
                              IppsXMSSPublicKeyState* pPubKey,
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

   * -     pPrvKey
     -  Pointer to the initialized ``IppsXMSSPrivateKeyState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSPrivateKeyStateGetSize``.
   * -     pPubKey
     -  Pointer to the initialized ``IppsXMSSPublicKeyState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSPublicKeyStateGetSize``.
   * -     rndFunc
     -  Pointer to the random number generator function that is used for private key generation.
        The function should be defined as:
        ``IppStatus rndFunc(Ipp8u* pRnd, int size, void* pRndParam)``.
        This function must be cryptographically secure.
        The ``size`` parameter is the size of the buffer in bytes.
        The ``pRndParam`` parameter is a pointer to the user-defined parameter.
        If ``rndFunc`` is NULL then ``ippsPRNGenRDRAND`` is used as a random number generator.
   * -     pRndParam
     -  Pointer to the user-defined parameter for the random number generator function.
        It can be a NULL pointer.
   * -     pBuffer
     -  Pointer to the temporary buffer. Size is greater or equal to
        the value returned by ``ippsXMSSKeyGenBufferGetSize``.

Description
-----------

This function generates private and public XMSS keys.

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

   This is a :ref:`Preview Feature <experimental>`.
   You need to enable the ``IPPCP_PREVIEW_XMSS`` macro to use the feature.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. All single operations executed without errors. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     ``pPrvKey`` or ``pPubKey`` or ``pBuffer`` is a NULL pointer.
   * -     ippStsBadArgErr
     -     ``pPrvKey->OIDAlgo > Max value for IppsXMSSAlgo`` or ``pPrvKey->OIDAlgo <= 0``.
