.. _ml-kem-get-size:

ippsMLKEM_GetSize
=================

Queries the size of ``IppsMLKEMState``.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_GetSize(int* pSize, IppsMLKEMParamSet schemeType);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the state size.
   * - schemeType
     - Parameter specifying the scheme type. See
       :ref:`Supported ML-KEM parameters <ml-kem-params>` for more information.

Description
-----------

The function queries the size of ``IppsMLKEMState``. Allocated memory will be used as the context
required for ML-KEM computations.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_KEM`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pSize`` is a ``NULL`` pointer.
   * - ippStsBadArgErr
     - ``schemeType`` is not supported.
