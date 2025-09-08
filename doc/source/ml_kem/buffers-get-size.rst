.. _ml-kem-buffers-get-size:

API to query working buffers size  
=================================

Query the size of the working buffers.

Syntax
------
.. code:: cpp

    IppStatus ippsMLKEM_KeyGenBufferGetSize(int* pSize, const IppsMLKEMState* pMLKEMCtx);
    IppStatus ippsMLKEM_EncapsBufferGetSize(int* pSize, const IppsMLKEMState* pMLKEMCtx);
    IppStatus ippsMLKEM_DecapsBufferGetSize(int* pSize, const IppsMLKEMState* pMLKEMCtx);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the buffers size.
   * - pMLKEMCtx
     - Pointer to the initialized ML-KEM context

Description
-----------

``ippsMLKEM_KeyGenBufferGetSize`` queries the size for working buffer required for the
``ippsMLKEM_KeyGen`` function.

``ippsMLKEM_EncapsBufferGetSize`` queries the size for working buffer required for the
``ippsMLKEM_Encaps`` function.

``ippsMLKEM_DecapsBufferGetSize`` queries the size for working buffer required for the
``ippsMLKEM_Decaps`` function.

Allocated memory should be passed directly to the processing API.

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
     - ``pSize`` or ``pMLKEMCtx`` are ``NULL`` pointers.
   * - ippStsContextMatchErr
     - ``pMLKEMCtx`` was not initialized.
