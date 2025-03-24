.. _init:

Init
====


Automatically initializes the library code that matches the current
processor best.


Syntax
------


IppStatus ippcpInit(void);


Include Files
-------------


``ippcp.h``


Description
-----------


This function detects the processor type of the user system and sets the
processor-specific code of the Intel® Cryptography Primitives Library that matches the current processor type best.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates that the required processor-specific code is successfully set.
   * -     ippStsNotSupportedCpu   
     -  Indicates that the CPU is not supported.
   * -     ippStsNonIntelCpu   
     -  Indicates that the target CPU is not Genuine Intel.



