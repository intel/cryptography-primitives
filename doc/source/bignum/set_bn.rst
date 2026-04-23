.. _set_bn:




Set_BN
======


Defines the sign and value of the context.


Syntax
------


IppStatus ippsSet_BN(IppsBigNumSGN sgn, int length, const Ipp32u\*
pData, IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     sgn   
     -  Sign of IppsBigNumState \*x.
   * -     length   
     -  Array length of the input data.
   * -     pData   
     -  Pointer to the data array.
   * -     pBN   
     -  On output, the context IppsBigNumState updated with the input data.




Description
-----------


The function defines the sign and value for IppsBigNumState \*x with the
specified inputs IppsBigNumSGN sgn and const Ipp32u \*pData.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if length is less than or equal to 0.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if length is more than the size of IppsBigNumState \*pBN.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if the big number is set to zero with the negative sign.




Example
-------


The code example below shows how to create a big number.


.. code-block:: cpp


   IppsBigNumState* New_BN(int size, const Ipp32u* pData=0){
      // get the size of the Big Number context
      int ctxSize;
      ippsBigNumGetSize(size, &ctxSize);
      // allocate the Big Number context
      IppsBigNumState* pBN = (IppsBigNumState*) (new Ipp8u [ctxSize] );
      // and initialize one
      ippsBigNumInit(size, pBN);
      // if any data was supplied, then set up the Big Number value
      if(pData)
         ippsSet_BN(IppsBigNumPOS, size, pData, pBN);
      // return pointer to the Big Number context for future use
      return pBN;
   }

