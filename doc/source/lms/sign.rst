.. _lms-sign:

LMS Signature Generation
========================

Performs the LMS signature generation.

Syntax
------

.. code:: cpp

    IppStatus ippsLMSSign (const Ipp8u* pMsg,
                           const Ipp32s msgLen,
                           IppsLMSPrivateKeyState* pPrvKey,
                           IppsLMSSignatureState* pSign,
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

   * -  pMsg
     -  Pointer to the message that is signed.
   * -  msgLen
     -  Message length in bytes.
   * -  pPrvKey
     -  Pointer to the initialized ``IppsLMSPrivateKeyState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSPrivateKeyStateGetSize <lms-states-get-size>` function.
   * -  pSign
     -  Pointer to the initialized ``IppsLMSSignatureState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSSignatureStateGetSize <lms-states-get-size>` function.
   * -  rndFunc
     -  Pointer to the random number generator function that is used for private key generation.
        The function should be defined as:
        ``IppStatus rndFunc(Ipp8u* pRnd, int size, void* pRndParam)``.
        This function must be cryptographically secure.
        The ``size`` parameter is the size of the buffer in bytes.
        The ``pRndParam`` parameter is a pointer to the user-defined parameter.
        If ``rndFunc`` is NULL then ``ippsPRNGenRDRAND`` is used as a random number generator.
   * -  pRndParam
     -  Pointer to the user-defined parameter for the random number generator function.
        It can be a NULL pointer.
   * -  pBuffer
     -  Pointer to the temporary buffer. Size is greater or equal to
        the value returned by
        the :ref:`ippsLMSSignBufferGetSize <lms-buffer-get-size>` function.

Description
-----------

This function signs the message with the LMS algorithm.

This function uses internally the random number generator (RNG) provided by
the user through the ``rndFunc`` parameter, please see
:ref:`User's Implementation of a RNG <users-implementation-of-a-pseudorandom-num-gen>`
for more information regarding creation the customer's defined RNG object.
If ``rndFunc`` is ``NULL``, the internal default random number generator
based on ``RDRAND`` hardware instruction is used.

``pSign`` is an output parameter.

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
     - Any of the input parameters is a NULL pointer.
   * - ippStsContextMatchErr
     - ``pPrvKey`` or ``pSign`` contexts are invalid.
   * - ippStsBadArgErr
     - wrong LMS or LMOTS parameters.
   * - ippStsOutOfRangeErr
     - private key will not be valid any longer after executing the function
       and new keys need to be generated again using ``ippsLMSKeyGen``.
   * - ippStsLengthErr
     - ``msgLen < 1`` or
       ``msgLen > IPP_MAX_32S - (22 + n)``,
       where ``n`` is the LM-OTS parameter.
