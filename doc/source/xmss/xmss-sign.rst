.. _xmss-sign:

XMSS Signature Generation
=========================

Performs the XMSS signature generation.

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSSign (const Ipp8u* pMsg,
                            const Ipp32s msgLen,
                            IppsXMSSPrivateKeyState* pPrvKey,
                            IppsXMSSSignatureState* pSign,
                            Ipp8u* pBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pMsg
     -  Pointer to the message that is signed.
   * -     msgLen
     -  Message length in bytes.
   * -     pPrvKey
     -  Pointer to the initialized ``IppsXMSSPrivateKeyState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSPrivateKeyStateGetSize``.
   * -     pSign
     -  Pointer to the ``IppsXMSSSignatureState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSSignatureStateGetSize``.
   * -     pBuffer
     -  Pointer to the temporary buffer. Size is greater or equal to
        the value returned by ``ippsXMSSSignBufferGetSize``.

Description
-----------

This function signs the message with the XMSS algorithm.

``pSign`` is an output parameter.

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
     -     Any of the input parameters is a NULL pointer.
   * -     ippStsLengthErr
     -     ``msgLen < 1`` or ``msgLen < IPP_MAX_32S - (n + 5 * n + len + key_gen_size)``,
           where ``n``, ``len`` are WOTS+ parameters`` and ``key_gen_size`` is
           the value returned by ``ippsXMSSKeyGenBufferGetSize``.
   * -     ippStsOutOfRangeErr
     -     Index of the current secret key is greater than the number of secret keys.
