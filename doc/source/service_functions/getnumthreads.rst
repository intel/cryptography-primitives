.. _getnumthreads:

GetNumThreads
=============


Not functional (deprecated). Returns 1 as the number of threads and ippStsNoOperation status.


Syntax
------


IppStatus ippcpGetNumThreads(int\* pNumThr);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pNumThr
     - Pointer to the number of threads.




Description
-----------


Returns 1 as the number of threads and ippStsNoOperation status.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoOperation
     - Indicates that there is no such operation in the static version of the library.



