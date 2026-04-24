.. _finite-field-arithmetic:



Finite Field Arithmetic
=======================


This section describes the Intel® Cryptography Primitives Library functions that implement
arithmetic operations with elements of the following finite fields
:term:`ANT <[ANT]>`:


.. list-table::
   :header-rows: 0

   * - GF(``p``)
     - A finite field of ``p`` elements.
   * - GF(``q``)
     - If ``q`` is an odd prime number, then the finite field is represented by integers modulo ``q``. This field is also known as the *prime finite field*.
   * - GF(``p``\ :sup:`d`)
     - If ``p`` = ``q``, ``q`` is an odd prime number and ``d`` > 1, the finite field is represented by polynomials modulo ``g``\ (``x``), GF(``p``)[``x``]/``g``\ (``x``), where ``g``\ (``x``) is an irreducible polynomial over GF(``p``). This field is also known as *a degree ``d`` extension of the GF(``p``) field*.
   * - GF(((``q``\ :sup:`n1`)\ :sup:`n2`)\ :sup:`n3`)
     - A very complex extension of the prime finite field GF(``q``). The initial prime field GF(``q``) used at the lowest level of the construct is frequently called the *basic finite field* with respect to the extension.




The finite field arithmetic functions use context structures of the
IppsGFpState and IppsGFpElement types to store data of the finite field
and the field elements, respectively.


The IppsGFpElement type structure is used for *internal* representation
of field elements. In application (*or external*) representation of
field element is straightforward. Each element ``E`` of the prime field
GF(``q``) is an unsigned number in the range [0, ``q`` - 1], which is
represented by a data array ``Ipp32u qe[len32]`` , so that


.. container:: fignone
   :name: GUID-1CFB48BF-C28A-4987-B5A7-C784A35EE26F


   |image1|


where |image2| is the length of the prime ``q``, expressed in *dwords*
(32-bit chunks).


Each element ``E`` of GF(``p``\ :sup:`d`) is represented by a polynomial
of degree less than ``d``. This polynomial is represented by an array of
coefficients ``pe[d]`` that belong to GF(``p``).


.. container:: fignone
   :name: GUID-2FFAAE39-A6DB-4FD6-B5F3-1968828EB62C


   |image3|


Thus,


.. code-block:: cpp


   Ipp32u a[4] = {0xBFF9AEE1,0xBF59CC9B,0xD1B3BBFE,0xD6031998};


is an external (application-side) representation of an element that
belongs to some prime field GF(``q``), bitsize(``q``)=128.


Similarly,


.. code-block:: cpp


   Ipp32u b[2][4] = { {0xBFF9AEE1,0xBF59CC9B,0xD1B3BBFE,0xD6031998},
                      {0xBB6D8A5D,0xDC2C6558,0x80D02919,0x5EEEFCA3} };


is an external (application-side) representation of an element that
belongs to GF(``q``\ :sup:`2`) - a degree 2 extension of some prime
field GF(``q``), bitsize(``q``)=128.


You can use Intel® Cryptography Primitives Library finite field functions to convert
between the internal and the external representations of a finite field
element.


Prime finite fields are the basic mathematical objects of Elliptic Curve
(EC) cryptography. Intel® Cryptography Primitives Library supports different kinds of EC
over finite fields and, in particular, the *standard* elliptic curves -
elliptic curves with pre-defined parameters, including the underlying
finite field. The performance of EC functionality directly depends on
the efficiently of the implementation of operations with finite field
elements such as addition, multiplication, and squaring.


Intel® Cryptography Primitives Library contains several different optimized
implementations of finite field arithmetic functions. These
implementations, referred to in this document as "methods", are grouped
together in structures. Intel® Cryptography Primitives Library does not reveal the
content of these structures. The implementations, including those
optimized for a particular prime ``q``, are accessed by special Intel® Cryptography Primitives Library
functions. For example, ippsGFpMethod_p192r1() returns
a pointer to the structure containing optimized arithmetic over prime
``p192r1`` (see
:ref:`GFpMethod <gfpmethod>` for
details).


Similarly, for GF(``p``\ :sup:`d`), additional knowledge concerning the
predefined field polynomial ``g``\ (``x``) allows Intel® Cryptography Primitives Library
to provide a more efficient implementation of finite field arithmetic
than in the case of an arbitrary field polynomial ``g``\ (``x``).
Intel® Cryptography Primitives Library contains *methods* dedicated to certain predefined
``g``\ (``x``). For example, the functions ippsGFpxMethod_binom2()
returns a pointer to the structure containing optimized arithmetic over
GF(``p``\ :sup:`2`).


The comparison function GFpCmpElement returns the result of comparison:


.. code-block:: cpp


   #define IPP_IS_EQ (0) // elements are equal
   #define IPP_IS_GT (1) // the first element is greater than the second one
   #define IPP_IS_LT (2) // the first element is less than the second one
   #define IPP_IS_NE (3) // elements are not equal
   #define IPP_IS_NA (4) // elements are not comparable



.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201


.. |image1| image:: GUID-4C692AD4-DCB2-4AB5-8610-32416C380ee1.png
.. |image2| image:: GUID-6F8BBE27-615C-4B95-9FD9-A361DFE3CCA0-low.png
.. |image3| image:: GUID-4C692AD4-DCB2-4AB5-8610-32416C380ee2.png

.. toctree::
   :maxdepth: 1


   gfpinit
   gfpmethod
   gfpgetsize
   gfpxinitbinomial
   gfpxinit
   gfpxmethod
   gfpxgetsize
   gfpscratchbuffersize
   gfpelementgetsize
   gfpelementinit
   gfpsetelement
   gfpsetelementoctstring
   gfpsetelementrandom
   gfpsetelementhash
   gfpcpyelement
   gfpgetelement
   gfpgetelementoctstring
   gfpcmpelement
   gfpiszeroelement
   gfpisunityelement
   gfpconj
   gfpneg
   gfpinv
   gfpsqrt
   gfpadd
   gfpsub
   gfpmul
   gfpsqr
   gfpexp
   gfpmultiexp
   gfpadd_pe
   gfpsub_pe
   gfpmul_pe