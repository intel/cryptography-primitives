.. _support-functions:

Support Functions
=================


There are several general purpose functions that simplify using the
library and report information on how it is working:


-  :samp:`GetCpuFeatures/ SetCpuFeatures/GetEnabledCpuFeatures`
-  :samp:`GetStatusString`
-  :samp:`GetLibVersion`


:samp:`GetCpuFeatures/ SetCpuFeatures/GetEnabledCpuFeatures`
------------------------------------------------------------


In some cases like debugging and performance analysis, you may want to
get the data on the difference between various processor-specific codes
on the same machine. Use the :samp:`ippcpSetCpuFeatures` function for this. This
function sets the dispatcher to use the processor-specific code
according to the specified set of CPU features. You can obtain features
supported by CPU using :samp:`ippcpGetCpuFeatures` and obtain features supported
by the currently dispatched Intel® Cryptography Primitives Library code using
:samp:`ippcpGetEnabledCpuFeatures`. If you need to enable support of some CPU
features without querying the system (without using the CPUID
instruction call), you must set the :samp:`ippCPUID_NOCHECK` bit for
:samp:`ippcpSetCpuFeatures`, otherwise, only the features supported by the
current CPU are set.


The :samp:`ippcpGetCpuFeatures`, :samp:`ippcpGetEnabledCpuFeatures`, and
:samp:`ippcpSetCpuFeatures` functions are a part of the :samp:`ippCP` library.


:samp:`GetStatusString`
-----------------------


The :samp:`ippcpGetStatusString` function decodes the numeric status return
value of Intel® Cryptography Primitives Library functions and converts them to a
human-readable text:


.. code:: c


   Ipp64u mask;
   status = ippcpGetCpuFeatures(&mask);
   if( status != ippStsNoErr ) {
           printf("ippcpGetCpuFeatures() Error:\n");
           printf("%s\n", ippcpGetStatusString(status) );
           return -1;
   }


The :samp:`ippcpGetStatusString` function is a part of the :samp:`ippCP` library.


:samp:`GetLibVersion`
---------------------


The :samp:`GetLibVersion` function returns information about the library layer
in use from the dispatcher. The code snippet below demonstrates the
usage of the :samp:`cryptoGetLibVersion`:


.. code:: c


   const CryptoLibraryVersion* lib = cryptoGetLibVersion();
   printf("%s %d.%d.%d\n", lib->name, lib->major, lib->minor, lib->patch);
   // or you can print the library version string
   printf("%s\n", lib->strVersion);



