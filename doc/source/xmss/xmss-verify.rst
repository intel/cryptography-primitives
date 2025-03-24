.. _xmss-verify:

XMSS Verification
=================

Performs the XMSS verification.

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSVerify (const Ipp8u* pMsg,
                              const Ipp32u msgLen,
                              const IppsXMSSSignatureState* pSign,
                              int* pIsSignValid,
                              const IppsXMSSPublicKeyState* pKey,
                              Ipp8u* pBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pMsg
     -  Pointer to the array of messages that have been signed.
   * -     msgLen
     -  Message length.
   * -     pSign
     -  Pointer to the ``IppsXMSSSignatureState`` context for each verification operation.
        Size is greater or equal to the value returned by
        the :ref:`ippsXMSSSignatureStateGetSize <xmss-sig-get-size>` function.
   * -     pIsSignValid
     -  Pointer to the verification result.
   * -     pKey
     -  Pointer to the ``IppsXMSSPublicKeyState`` context for each verification operation.
        Size is greater or equal to the value returned by
        the :ref:`ippsXMSSPublicKeyStateGetSize <xmss-pub-key-get-size>` function.
   * -     pBuffer
     -  Pointer to the temporary buffer. Size is greater or equal to
        the value returned by the :ref:`ippsXMSSBufferGetSize <xmss-buffer-get-size>` function.

Description
-----------

This function verifies the signature generated using XMSS.

``pIsSignValid`` is an output parameter.
If ``*pIsSignValid == 1`` then the XMSS signature is valid.
If ``*pIsSignValid == 0`` then the XMSS signature is not valid.

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
     -     ``msgLen < 1`` or ``msgLen < IPP_MAX_32S - (10 + len) * n``,
           where ``n``, ``len`` are WOTS+ parameters``.
