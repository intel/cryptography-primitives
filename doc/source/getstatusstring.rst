.. _getstatusstring:


GetStatusString
===============


Translates a status code into a message.


Syntax
------


const char\* ippcpGetStatusString(IppStatus stsCode);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - stsCode   
     - Code that indicates the status type.




Description
-----------


This function returns a pointer to the text string associated with a
status code of IppStatus type. Use this function to produce error and
warning messages for users. The returned pointer is a pointer to an
internal static buffer and does not need to be released.

