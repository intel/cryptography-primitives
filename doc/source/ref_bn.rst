.. _ref_bn:


Ref_BN
======


*Extracts the main characteristics of the integer big number from the
input structure.*


Syntax
------


IppStatus ippsRef_BN(IppsBigNumSGN\* pSgn, int\* bitSize, Ipp32u*\*
const ppData, const IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSgn   
     -  Pointer to the sign of IppsBigNumState \*x.
   * -     bitSize    
     -  Length of the integer big number in bits.
   * -     ppData   
     -  Double pointer to the data array.
   * -     pBN   
     -  Integer big number of the context IppsBigNumState.




Description
-----------


The function extracts from the input structure the main characteristics
of the integer big number: sign, length, and pointer to the data array.
You can extract either the entire set or any subset of these
characteristics. To turn off extraction of a particular characteristic,
set the appropriate function parameter to NULL.


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



