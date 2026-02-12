.. _hash-drbg-init:

ippsHashDRBG_Init
==================

Initializes the Hash DRBG state.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_Init(const IppsHashMethod* pHashMethod,
                                IppsHashDRBGState* pDrbgCtx);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pHashMethod
     - Pointer to the hash method (may be NULL).
   * - pDrbgCtx
     - Pointer to the ``IppsHashDRBGState`` context.
       The size is equal to the value returned by the ``ippsHashDRBG_GetSize``.

Description
-----------

The function initializes the ``IppsHashDRBGState``.
Additionally, sets security strength according to the user-selected hashing method
as shown in the :ref:`Table 1: Maximum security strengths for hash functions in bits <hash-drbg-max-sec-strength-for-hash-funcs>`.

.. note::

   If the hash method is not specified (NULL pointer is passed), SHA-256 will be set by default.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pDrbgCtx`` is a NULL pointer.
   * - ippStsNotSupportedModeErr
     - The hash algorithm is not supported.
   * - ippStsErr
     - Functions invoked inside ``ippsHashDRBG_Init`` failed with this error status code.
