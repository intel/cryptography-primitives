.. _lms-enum:

Supported LMS Algorithms
========================

LMS includes a various set of algorithms that are different by LM-OTS parameter
(``n``, ``w``, ``p``, ``ls``) and the LMS parameters itself (``m``, ``h``).

Here you can find the actual set of LMS parameters and how they map to the enum.

Syntax
------

.. code:: cpp

    typedef enum
    {
        LMOTS_SHA256_N32_W1 = 1,
        LMOTS_SHA256_N32_W2 = 2,
        LMOTS_SHA256_N32_W4 = 3,
        LMOTS_SHA256_N32_W8 = 4,
        LMOTS_SHA256_N24_W1 = 5,
        LMOTS_SHA256_N24_W2 = 6,
        LMOTS_SHA256_N24_W4 = 7,
        LMOTS_SHA256_N24_W8 = 8
    } IppsLMOTSAlgo;

    typedef enum
    {
        LMS_SHA256_M32_H5  = 5,
        LMS_SHA256_M32_H10 = 6,
        LMS_SHA256_M32_H15 = 7,
        LMS_SHA256_M32_H20 = 8,
        LMS_SHA256_M32_H25 = 9,
        LMS_SHA256_M24_H5  = 10,
        LMS_SHA256_M24_H10 = 11,
        LMS_SHA256_M24_H15 = 12,
        LMS_SHA256_M24_H20 = 13,
        LMS_SHA256_M24_H25 = 14
    } IppsLMSAlgo;

    typedef struct {
        IppsLMOTSAlgo lmotsOIDAlgo;
        IppsLMSAlgo   lmsOIDAlgo;
    } IppsLMSAlgoType;

Table of values for LM-OTS algorithms
-------------------------------------

.. list-table::
   :header-rows: 1
   :align: center

   * -  Name
     -  SHA Function
     -  n
     -  w
     -  p
     -  ls
   * -  LMOTS_SHA256_N32_W1
     -  SHA2-256
     -  32
     -  1
     -  265
     -  7
   * -  LMOTS_SHA256_N32_W2
     -  SHA2-256
     -  32
     -  2
     -  133
     -  6
   * -  LMOTS_SHA256_N32_W4
     -  SHA2-256
     -  32
     -  4
     -  67
     -  4
   * -  LMOTS_SHA256_N32_W8
     -  SHA2-256
     -  32
     -  8
     -  34
     -  0
   * -  LMOTS_SHA256_N24_W1
     -  SHA2-256/192
     -  24
     -  1
     -  200
     -  8
   * -  LMOTS_SHA256_N24_W2
     -  SHA2-256/192
     -  24
     -  2
     -  101
     -  6
   * -  LMOTS_SHA256_N24_W4
     -  SHA2-256/192
     -  24
     -  4
     -  51
     -  4
   * -  LMOTS_SHA256_N24_W8
     -  SHA2-256/192
     -  24
     -  8
     -  26
     -  0

Table of values for LMS algorithms
----------------------------------

.. list-table::
   :header-rows: 1
   :align: center

   * -  Name
     -  SHA Function
     -  m
     -  h
   * -  LMS_SHA256_M32_H5
     -  SHA2-256
     -  32
     -  5
   * -  LMS_SHA256_M32_H10
     -  SHA2-256
     -  32
     -  10
   * -  LMS_SHA256_M32_H15
     -  SHA2-256
     -  32
     -  15
   * -  LMS_SHA256_M32_H20
     -  SHA2-256
     -  32
     -  20
   * -  LMS_SHA256_M32_H25
     -  SHA2-256
     -  32
     -  25
   * -  LMS_SHA256_M24_H5
     -  SHA2-256/192
     -  24
     -  5
   * -  LMS_SHA256_M24_H10
     -  SHA2-256/192
     -  24
     -  10
   * -  LMS_SHA256_M24_H15
     -  SHA2-256/192
     -  24
     -  15
   * -  LMS_SHA256_M24_H20
     -  SHA2-256/192
     -  24
     -  20
   * -  LMS_SHA256_M24_H25
     -  SHA2-256/192
     -  24
     -  25

Description
-----------

``IppsLMSAlgoType`` is required to pass one value to LMS functions instead of
passing all parameters for the LMS algorithm call.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   This is a :ref:`Preview Feature <experimental>`.
   You need to enable the ``IPPCP_PREVIEW_LMS`` macro to use the feature.
