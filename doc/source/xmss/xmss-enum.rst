.. _xmss-enum:

Supported XMSS Algorithms
=========================

XMSS includes a various set of algorithms that are different by
WOTS+ parameter (``n``, ``w``, ``len``) and the XMSS tree height (``h``).

Here you can find the actual set of XMSS parameters and how they map to the enum.

Syntax
------

.. code:: cpp

    typedef enum
    {
        reserved = 0,
        XMSS_SHA2_10_256 = 1,
        XMSS_SHA2_16_256 = 2,
        XMSS_SHA2_20_256 = 3,
        XMSS_SHA2_10_512 = 4,
        XMSS_SHA2_16_512 = 5,
        XMSS_SHA2_20_512 = 6
    } IppsXMSSAlgo;

Table of values
---------------

``reserved`` is not expected to be used.

.. list-table::
   :header-rows: 1 
   :align: center

   * -  Name
     -  SHA Function
     -  n
     -  w
     -  len
     -  h
   * -  XMSS_SHA2_10_256
     -  SHA2-256
     -  32
     -  16
     -  67
     -  10
   * -  XMSS_SHA2_16_256
     -  SHA2-256
     -  32
     -  16
     -  67
     -  16
   * -  XMSS_SHA2_20_256
     -  SHA2-256
     -  32
     -  16
     -  67
     -  20
   * -  XMSS_SHA2_10_512
     -  SHA2-512
     -  64
     -  16
     -  131
     -  10
   * -  XMSS_SHA2_16_512
     -  SHA2-512
     -  64
     -  16
     -  131
     -  16
   * -  XMSS_SHA2_20_512
     -  SHA2-512
     -  64
     -  16
     -  131
     -  20


Description
-----------

This ``enum`` is required to pass one value to XMSS functions instead of
passing all parameters for the XMSS algorithm.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   This is a :ref:`Preview Feature <experimental>`.
   You need to enable the ``IPPCP_PREVIEW_XMSS`` macro to use the feature.
