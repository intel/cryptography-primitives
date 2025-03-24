.. _getoctstring_bn:


GetOctString_BN
===============


Converts a positive Big Number into octet String.


Syntax
------


IppStatus ippsGetOctString_BN(Ipp8u\* pStr, int strLen, const
IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pStr   
     - Pointer to the input octet string.
   * - strLen   
     - Octet string length in bytes.
   * - pBN   
     - Pointer to the context of the input Big Number.




Description
-----------


This function converts a positive Big Number into the octet string.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsLengthErr   
     - Indicates an error condition if specified pStr is insufficient in length.
   * - ippStsRangeErr   
     - Indicates an error condition if Big Number is negative.




Example
-------


The code example below types a big number.


.. code-block:: cpp


   void Type_BN(const char* pMsg, const IppsBigNumState* pBN){
      // size of Big Number
      int size;
      ippsGetSize_BN(pBN, &size);
           

     // extract Big Number value and convert it to the string presentation
     Ipp8u* bnValue = new Ipp8u [size*4];
     ippsGetOctString_BN(bnValue, size*4, pBN);
           

     // type header
     if(pMsg)
        cout<<pMsg;
           

     // type value
     for(int n=0; n<size*4; n++)
        cout<<hex<<setfill('0')<<setw(2)<<(int)bnValue[n];
     cout<<endl;


     delete [] bnValue;
   }

