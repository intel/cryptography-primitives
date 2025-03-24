.. _arcfourreset:

ARCFourReset
============


Resets the IppsARCFourState context to the initial state (deprecated).


Syntax
------


IppStatus ippsARCFourReset(IppsARCFourState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pCtx   
     - Pointer to the IppsARCFourState context being reset.




Description
-----------


.. note::


   This function is deprecated.


The function resets the IppsARCFourState context to the state it had
immediately after the
:ref:`ARCFourInit <arcfourinit>`
function call. Contrary to ARCFourInit, ARCFourReset requires no secret
key to initialize the S-Box.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNullPtrErr    
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.



