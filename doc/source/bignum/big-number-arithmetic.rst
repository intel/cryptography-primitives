.. _big-number-arithmetic:

Big Number Arithmetic
=====================


This section describes primitives for performing arithmetic operations
with integer big numbers of variable length.

The magnitude of an integer big number is specified by an array of
unsigned integer data type Ipp32u rp[length] and corresponds to the
mathematical value
|image1|


This section uses the following definition for the sign of an integer
big number:


.. code-block:: cpp


   typedef enum {
        IppsBigNumNEG=0,
        IppsBigNumPOS=1
   } IppsBigNumSGN;


The functions described in this section use the context IppsBigNumState
to serve as an operational vehicle that carries not only the sign and
value of the data, but also a sufficient working buffer reserved for
various arithmetic operations. The length of the context IppsBigNumState
is defined as the length of the data carried by the structure and the
size of the context IppsBigNumState is therefore defined as the maximal
length of the data that this operational vehicle can carry.


.. note::


   In all unsigned big number arithmetic functions, integers pointed to
   by a, b, and r are all of (n\*32) bits.


.. |image1| image:: GUID-74E1AC12-3431-4D3F-BA96-0EE9CEF50ECB-low.jpg

.. toctree::
   :maxdepth: 1

   
   bignumgetsize
   bignuminit
   set_bn
   setoctstring_bn
   getsize_bn
   get_bn
   extget_bn
   ref_bn
   getoctstring_bn
   cmp_bn
   cmpzero_bn
   add_bn
   sub_bn
   mul_bn
   mac_bn_i
   div_bn
   mod_bn
   gcd_bn
   modinv_bn