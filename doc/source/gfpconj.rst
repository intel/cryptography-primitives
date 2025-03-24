.. _gfpconj:


GFpConj
=======


Computes the conjugate of the element of the finite field
GF(p\ :sup:`2`).


Syntax
------


IppStatus ippsGFpConj(const IppsGFpElement\* pA, IppsGFpElement\* pR,
IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the finite field element.
   * - pR   
     - Pointer to the context of the resulting element of the finite field.
   * - pGFp   
     - Pointer to the context of the finite field.




Description
-----------


This function computes the conjugate of an element of the finite field
GF(``p``\ :sup:`2`). If the element of the GF(``p``\ :sup:`2`) field is
the polynomial ``x + a``, the conjugate element is equal to ``x – a``,
where ``a`` is an element of the ground field GF(``p``).


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if the element pA does not belong to the finite field specified by the context pGFp.
   * - ippStsBadArgErr   
     - Indicates an error condition if the element pA does not belong to the GF(``p``\ :sup:`2`) field.



