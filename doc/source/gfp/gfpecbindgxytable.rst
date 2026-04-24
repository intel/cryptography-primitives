.. _gfpecbindgxytable:

GFpECBindGxyTblStd
==================

Enables the use of base point-based pre-computed tables in kernels performing scalar*Point multiplication.

Syntax
------
.. code:: cpp

  IppStatus ippsGFpECBindGxyTblStd192r1(IppsGFpECState* pEC);

  IppStatus ippsGFpECBindGxyTblStd224r1(IppsGFpECState* pEC);

  IppStatus ippsGFpECBindGxyTblStd256r1(IppsGFpECState* pEC);

  IppStatus ippsGFpECBindGxyTblStd384r1(IppsGFpECState* pEC);

  IppStatus ippsGFpECBindGxyTblStd521r1(IppsGFpECState* pEC);

  IppStatus ippsGFpECBindGxyTblStdSM2(IppsGFpECState* pEC);


Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEC
     - Pointer to the cryptosystem context based on a standard elliptic curve

Description
-----------

The functions enable the use of base point-based pre-computed tables in kernels
performing scalar*Point multiplication. This will result in the better performance for
:ref:`ippsGFpECSignDSA <gfpecpsigndsa-gfpecpsignnr-gfpecpsignsm2>`,
:ref:`ippsGFpECVerifyDSA <gfpecpverifydsa-gfpecpverifynr-gfpecpverifysm2>`
and :ref:`ippsGFpECPublicKey<gfpecprivatekey-gfpecpublickey-gfpectstkeypair>` public API.
The call to these functions should be placed after ``pEC`` state is allocated and initialized.

.. note::
    Note: Pre-computed tables reside in memory and may be vulnerable to hardware-specific attacks.
    For non-performance-critical applications, use the standard point multiplication kernel by excluding
    the above functions from the execution path.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is ``NULL``.
   * - ippStsContextMatchErr
     - Indicates an error condition if the ``pEC`` parameter does not match the operation.
   * - ippStsBadArgErr
     - Indicates an error condition if the ``pEC`` parameter does not specify the finite field
       over which the given standard elliptic curve is defined.
