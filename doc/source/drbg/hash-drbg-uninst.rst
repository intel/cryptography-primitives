.. _hash-drbg-uninst:

ippsHashDRBG_Uninstantiate
===========================

Uninstantiates the Hash DRBG.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_Uninstantiate(IppsHashDRBGState* pDrbgCtx);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pDrbgCtx
     - Pointer to the ``IppsHashDRBGState`` context.
       Size is equal to the value returned by ``ippsHashDRBG_GetSize``.

Description
-----------

The uninstantiate function empties the internal state.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pDrbgCtx`` is a NULL pointer.
   * - ippStsContextMatchErr
     - If the DRBG identifier doesn't match.
