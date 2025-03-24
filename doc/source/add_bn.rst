.. _add_bn:

Add_BN
======

Adds two integer big numbers.


Syntax
------


IppStatus ippsAdd_BN(IppsBigNumState \*pA, IppsBigNumState \*pB,
IppsBigNumState \* pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the first integer big number of the data type IppsBigNumState.
   * - pB   
     - Pointer to the second integer big number of the data type IppsBigNumState.
   * - pR   
     - Pointer to the addition result.




Description
-----------


The function adds two integer big numbers regardless of their signs and
sizes and returns the result of the operation.


The following pseudocode represents this function:

``(\*\ ``pR``) ← (\*\ ``pA``) + (\*\ ``pB``)``


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if the size of pR is smaller than the resulting data length.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The function executes only under the condition that size of
   IppsBigNumState \*pR is not less than either the length of
   IppsBigNumState \*pA or that of IppsBigNumState \*pB.


Example
-------


The code example below adds big numbers.


.. code-block:: cpp


   void Add_BN_sample(void){
      // define and set up Big Number A
      const Ipp32u bnuA[] = {0x01234567,0x9abcdeff,0x11223344};
      IppsBigNumState* bnA = New_BN(sizeof(bnuA)/sizeof(Ipp32u));
      // define and set up Big Number B
      const Ipp32u bnuB[] = {0x76543210,0xfedcabee,0x44332211};
      IppsBigNumState* bnB = New_BN(sizeof(bnuB)/sizeof(Ipp32u), bnuB);
      // define Big Number R
      int sizeR = max(sizeof(bnuA), sizeof(bnuB));
      IppsBigNumState* bnR = New_BN(1+sizeR/sizeof(Ipp32u));
      // R = A+B
      ippsAdd_BN(bnA, bnB, bnR);
      // type R
      Type_BN("R=A+B:\n", bnR);
      delete [] (Ipp8u*)bnA;
      delete [] (Ipp8u*)bnB;
      delete [] (Ipp8u*)bnR;
   }

