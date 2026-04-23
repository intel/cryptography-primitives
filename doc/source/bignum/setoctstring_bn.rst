.. _setoctstring_bn:



SetOctString_BN
===============


Converts octet string into a positive Big Number.


Syntax
------


IppStatus ippsSetOctString_BN(const Ipp8u\* pStr, int strLen,
IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pStr
     -  Pointer to the input octet string.
   * -     strLen
     -  Octet string length in bytes.
   * -     pBN
     -  Pointer to the context of the output Big Number.




Description
-----------


This function converts an octet string into a positive Big Number.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsLengthErr
     -  Indicates an error condition if specified strLen is less than 1.
   * -     ippStsSizeErr
     -  Indicates an error condition if insufficient space has been reserved for Big Number.




Example
-------


The code example below shows how to create a big number from a string.


.. code-block:: cpp


   void Set_BN_sample(void){
      // desired value of Big Number is 0x123456789abcdef0fedcba9876543210
      Ipp8u desiredBNvalue[] = "\x12\x34\x56\x78\x9a\xbc\xde\xf0"
                               "\xfe\xdc\xba\x98\x76\x54\x32\x10";
      // estimate required size of Big Number
      //int size = (sizeof(desiredBNvalue)+3)/4;
      //int size = (sizeof(desiredBNvalue)+3)/4;
      int size = (sizeof(desiredBNvalue)-1+3)/4;
      // and create new (and empty) one
      IppsBigNumState* pBN = New_BN(size);
      // set up the value from the string
      ippsSetOctString_BN(desiredBNvalue, sizeof(desiredBNvalue)-1, pBN);
      Type_BN("Big Number value is:\n", pBN);
   }

