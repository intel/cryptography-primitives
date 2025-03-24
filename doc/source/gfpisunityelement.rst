.. _gfpisunityelement:



GFpIsUnityElement
=================


Compares an element of the finite field with the unity element.


Syntax
------


IppStatus ippsGFpIsUnityElement(const IppsGFpElement\* pA, int\*
pResult, const IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the context of the first finite field element.
   * -     pResult   
     -  Pointer to the result of the comparison.For details, see :ref:`comparison results <finite-field-arithmetic>`.
   * -     pGFp   
     -  Pointer to the context of the finite field.




Description
-----------


This function compares an element of the finite field with the unity
element. The finite field is specified by the context pGFp.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of IppsGFpState and IppsGFpElement context parameters does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition ifpA does not belong to the finite field specified by the context pGFp.



