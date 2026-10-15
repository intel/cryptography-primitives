.. _ml-dsa-get-size:

ippsMLDSA_GetSize
=================

Queries the size of ``IppsMLDSAState``.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_GetSize(int* pSize);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the state size.

Description
-----------

The function queries the size of ``IppsMLDSAState``. Allocated memory will be used as the context
required for ML-DSA computations.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pSize`` is a ``NULL`` pointer.
