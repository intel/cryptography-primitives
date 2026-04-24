.. _gfpxinit:


GFpxInit
========


Initializes the context of a GF(p\ :sup:`d`) field.


Syntax
------


IppStatus ippsGFpxInit(const IppsGFpState\* pParentGF, int extDeg, const
IppsGfpElement\* const ppGroundElm[], int polyTerms, const
IppsGFpMethod\* method, IppsGFpState\* pGFpx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pParentGF   
     -  Pointer to the context of the finite field GF(``p``) being extended.
   * -     extDeg   
     -  Degree of the extension.
   * -     ppGroundElm[]   
     -  Double pointer to the array of IppsGFpElement contexts representing coefficients of the field polynomial.
   * -     polyTerms   
     -  Number of the field polynomial coefficients.
   * -     method   
     -  Pointer to the implementation of a basic arithmetic (methods) over the extended GF(``p``) finite field.
   * -     pGFpx   
     -  Pointer to the context of the GF(``p``\ :sup:`d`) field being initialized.




Description
-----------


The function initializes the memory buffer pGFpx associated with the
IppsGFpState context and sets up the specific irreducible polynomial.
The initialized context is used in the functions that create contexts of
elements of the GF(``p``\ :sup:`d`) field and perform operations with
the field elements. The function assumes the use of a general field
polynomial ``g``\ (``x``) = ``x``\ :sup:`d` + ``x``\ :sup:```d`` -
1`\ ``a``\ :sub:```d`` - 1` + ``x``\ :sup:```d`` -
2`\ ``a``\ :sub:```d`` - 2` + ⋯ + ``x``\ :sup:`1`\ ``a``\ :sub:`1` +
``a``\ :sub:`0` over GF(``p``).


.. note::


   -  The function does not check the polynomial's irreducibility.


   -  In general, the GF(``p``\ :sup:`d`) extension requires a field
      polynomial ``g``\ (``x``) of degree ``d``. However, because
      ``g``\ (``x``) is considered a monic polynomial (the coefficient
      of ``x``\ ``d`` is always assumed equal to 1), the leading
      coefficient is not required: polyTerms <= (extDeg - 1).


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   -  When calling the functions over the GF(``p``\ :sup:`d`) field, a
      properly initialized pParentGF context of the finite field
      GF(``p``) is required.


   -  Do not release the pParentGF context of the parent field as long
      as application deals with either the parent or the extended finite
      field pointed to by pGFpx.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters referenced by elements of ppGroundElm[] or pParentGF does not match the operation.
   * -     ippStsBadArgErr   
     - Indicates an error condition in the following cases:
       
       * extDeg > 8 or extDeg < 2.
       * polyTerms > (extDeg - 1) or polyTerms < 1.
       * method is not an output of a ``GFpxMethod`` function.
       * method is not compatible with the value of extDeg.
       
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the length of any of the values defined by ppGroundElm[] is not equal to the length of an element of the parent finite field pParentGF.



