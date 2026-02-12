.. _hash-drbg-get-size:

ippsHashDRBG_GetSize
=====================

Gets the size (in bytes) for the Hash DRBG state.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_GetSize(int* pSize,
                                   const IppsHashMethod* pHashMethod);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the state size.
   * - pHashMethod
     - Pointer to the hash method (may be NULL).

.. note::

   If the hash method is not specified (NULL pointer is passed), SHA-256 is used by default.

Description
-----------

Gets the size for the ``IppsHashDRBGState``.

The result is stored to ``*pSize``.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pSize`` is a NULL pointer.
   * - ippStsNotSupportedModeErr
     - The hash algorithm is not supported.
   * - ippStsErr
     - Functions invoked inside ``ippsHashDRBG_GetSize`` failed with this error status code.
