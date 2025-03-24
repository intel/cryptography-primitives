.. _gfpscratchbuffersize:


GFpScratchBufferSize
====================


Gets the size of the scratch buffer.


Syntax
------


IppStatus ippsGFpScratchBufferSize(int nExponents, int ExpBitSize, const
IppsGFpState\* pGFp, int\* pBufferSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     nExponents   
     -  Number of exponents.
   * -     ExpBitSize   
     -  Maximum bit size of the exponents.
   * -     pGFp   
     -  Pointer to the context of the finite field.
   * -     pBufferSize   
     -  Pointer to the calculated buffer size in bytes.




Description
-----------


This function computes the size of the scratch buffer for the ippsGFpExp
and ippsGFpMultiExp functions. The pGFp parameter specifies the context
of the finite field.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the pGFp context parameter does not match the operation.
   * -     ippStsBadArgErr   
     - Indicates an error condition in the following cases:
       
       * The number of exponents is zero or negative.
       * The number of exponents is greater than 6.




