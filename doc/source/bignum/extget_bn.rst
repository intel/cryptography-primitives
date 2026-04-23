.. _extget_bn:

ExtGet_BN
=========


Extracts the specified combination of the sign, data length, and value
characteristics of the integer big number from the input structure.


Syntax
------


IppStatus ippsExtGet_BN(IppsBigNumSGN\* pSgn, int\* pBitSize, Ipp32u\*
pData, const IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSgn
     - Pointer to the sign of IppsBigNumState pBN.
   * - pBitSize
     - Pointer to the length of pData in bits.
   * - pData
     - Pointer to the data array.
   * - pBN
     - Pointer to the integer big number context IppsBigNumState.




Description
-----------


For the integer big number from the input structure, the function
extracts the specified combination of the following characteristics:
sign, data length, and value. The function is similar to the
:ref:`Get_BN <get_bn>`
function but more flexible, because any target pointer (pSgn, pBitSize,
and/or pData) may be NULL, in which case the appropriate big number
characteristic will not be extracted. For example,


ippsExtGet_BN(&sgn, 0,0, pBN); extracts only the sign


ippsExtGet_BN(0, &dataLen, 0, pBN); extracts only the data length


ippsExtGet_BN(&sgn, &dataLen, 0, pBN); extracts the sign and data length


ippsExtGet_BN(0,0,0, pBN); does nothing


ippsExtGet_BN(&sgn, &dataLen, pData, pBN); does exactly what
:ref:`Get_BN <get_bn>`
does.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if the pointer to the integer big number of the context is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.



