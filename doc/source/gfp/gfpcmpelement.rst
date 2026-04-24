.. _gfpcmpelement:



GFpCmpElement
=============


Compares two elements of the finite field.


Syntax
------


IppStatus ippsGFpCmpElement(const IppsGFpElement\* pA, const
IppsGFpElement\* pB, int\* pResult, const IppsGFpState\* pGFp);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pA
     - Pointer to the context of the first finite field element.
   * - pB
     - Pointer to the context of the second finite field element.
   * - pResult
     - Pointer to the result of the comparison. For details, see :ref:`comparison results <finite-field-arithmetic>`.
   * - pGFp
     - Pointer to the context of the finite field.




Description
-----------


This function compares two elements of the finite field and returns the
result in pResult. The finite field is specified by the context pGFp.


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
     - Indicates an error condition if either pA or pB does not belong to the finite field specified by the context pGFp.



