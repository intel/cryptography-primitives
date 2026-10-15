.. _ml-kem-init:

ippsMLKEM_Init
=================

Initializes ``IppsMLKEMState`` for the further ML-KEM computations.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_Init(IppsMLKEMState* pMLKEMCtx, IppsMLKEMParamSet schemeType);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pMLKEMCtx
     - Pointer to the ML-KEM state.
   * - schemeType
     - Parameter specifying the scheme type. See
       :ref:`Supported ML-KEM parameters <ml-kem-params>` for more information.

Description
-----------

The function initializes ``IppsMLKEMState`` for the further ML-KEM computations.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pMLKEMCtx`` is a ``NULL`` pointer.
   * - ippStsBadArgErr
     - ``schemeType`` is not supported.
