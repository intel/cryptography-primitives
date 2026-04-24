.. _gfpecscratchbuffersize:


GFpECScratchBufferSize
======================


Gets the size of the scratch buffer.


Syntax
------


IppStatus ippsGFpECScratchBufferSize(int nScalars, const
IppsGFpECState\* pEC, int\* pBufferSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - nScalars   
     - Number of scalar values. This may take the following values:   
        - Number of scalar values used in the multiplication operation.   
        - 1 if it is not applicable.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pBufferSize   
     - Pointer to the calculated buffer size in bytes.




Description
-----------


This function computes the size of the scratch buffer for functions that
require an external scratch buffer.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsGFpECState context parameter does not match the operation.
   * - ippStsBadArgErr   
     - Indicates an error condition if nScalars <= 0 or nScalars > 6



