.. _gfpxinitbinomial:


GFpxInitBinomial
================


Initializes the context of a GF(p\ :sup:`d`) field.


Syntax
------


IppStatus ippsGFpxInitBinomial(const IppsGFpState\* pParentGF, int
extDeg, const IppsGFpElement\* const pGroundElm, const IppsGFpMethod\*
method, IppsGFpState\* pGFpx);


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
   * -     pGroundElm   
     -  Pointer to the IppsGFpElement context containing the trailing coefficient of the field binomial.
   * -     method   
     -  Pointer to the implementation of a basic arithmetic (methods) over GF(``p``\ :sup:`d`).
   * -     pGFpx   
     -  Pointer to the context of the GF(``p``\ :sup:`d`) field being initialized.




Description
-----------


This function initializes the memory buffer pGFpx associated with the
IppsGFpState context and sets up the specific irreducible binomial. The
initialized context is used in the functions that create contexts of
elements of the GF(``p``\ :sup:`d`) field and perform operations with
field elements.


.. note::


   The function does not check the binomial's irreducibility.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   When calling the functions over the GF(``p``\ :sup:`d`) field, a
   properly initialized pParentGF context of the finite field GF(``p``)
   is required.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters pParentGF and pGroundElm does not match the operation.
   * -     ippStsBadArgErr   
     - Indicates an error condition in the following cases:
       
       * extDeg > 8 or extDeg < 2.
       * method is not in agreement with other parameters.
       
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the length of the value defined in pGroundElm is not equal to that of an element of pParentGF.



