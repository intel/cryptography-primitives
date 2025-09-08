.. _ml-kem-get-info:

ippsMLKEM_GetInfo
=================

Fills ``IppsMLKEMInfo`` structure with the sizes corresponding to the given scheme type.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_GetInfo(IppsMLKEMInfo* pInfo, IppsMLKEMParamSet schemeType);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pInfo
     - Pointer to the ML-KEM ``pInfo`` structure.
   * - schemeType
     - Parameter specifying the scheme type. See 
       :ref:`Supported ML-KEM parameters <ml-kem-params>` for more information.

Description
-----------

The function fills ``IppsMLKEMInfo`` structure with the sizes corresponding to the given scheme
type. The sizes are used to allocate memory for the public key, secret key, ciphertext, and
shared secret.

``IppsMLKEMInfo`` is the public data type and has the following structure:

.. code:: cpp

    typedef struct {
        int encapsKeySize;
        int decapsKeySize;
        int cipherTextSize;
        int sharedSecretSize;
    } IppsMLKEMInfo;

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
     - ``pInfo`` is a ``NULL`` pointer.
   * - ippStsBadArgErr
     - ``schemeType`` is not supported.
