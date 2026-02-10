.. _ml-dsa-get-info:

ippsMLDSA_GetInfo
=================

Fills ``IppsMLDSAInfo`` structure with the sizes corresponding to the given scheme type.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_GetInfo(IppsMLDSAInfo* pInfo, IppsMLDSAParamSet schemeType);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pInfo
     - Pointer to the ML-DSA ``pInfo`` structure.
   * - schemeType
     - Parameter specifying the scheme type. See
       :ref:`Supported ML-DSA parameters <ml-dsa-params>` for more information.

Description
-----------

The function fills ``IppsMLDSAInfo`` structure with the sizes corresponding to the given scheme
type. The sizes are used to allocate memory for the public key, private key, and signature.

``IppsMLDSAInfo`` is the public data type and has the following structure:

.. code:: cpp

    typedef struct {
        int publicKeySize;
        int privateKeySize;
        int signatureSize;
    } IppsMLDSAInfo;

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_DSA`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pInfo`` is a ``NULL`` pointer.
   * - ippStsBadArgErr
     - ``schemeType`` is not supported.
