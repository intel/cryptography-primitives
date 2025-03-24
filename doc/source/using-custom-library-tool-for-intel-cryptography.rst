.. _using-custom-library-tool-for-crypto-primitives-library:

Using Custom Library Tool for Intel® Cryptography Primitives Library
====================================================================


With the Intel® Integrated Performance Primitives (Intel® IPP) Custom
Library Tool, you can build your own dynamic library containing only the
Intel® Cryptography Primitives Library functionality that is necessary for
your application.


The use of custom libraries built with the Custom Library Tool provides
the following advantages:


-  **Package size**. Your package may be much smaller if linked
   with a custom library because standard dynamic libraries
   contain all optimized versions of Intel® Cryptography Primitives Library
   functions and a dispatcher. The following table compares the contents
   and size of packages for an end-user application linked with a custom
   dynamic library and an application linked with the standard Intel IPP
   dynamic libraries:


   .. list-table:: 
      :header-rows: 1
      :widths: 1 1

      * - Application linked with custom DLL    
        - Application linked with Intel IPP dynamic libraries       
      * - :file:`ipp_test_app.exe` (for Windows\*) or :file:`ipp_test_app` (for Linux\* OS)
          

          ``crypto_custom\_{dll\|so}.{dll\|so\}``
        - :file:`ipp_test_app.exe` (for Windows\*) or :file:`ipp_test_app` (for Linux\* OS)
          
          ``ippcp.dll`` (for Windows*) or ``libippcp.so`` (for Linux* OS)
      * - **Package size: 0.1 Mb**
        - **Package size: 6.9 Mb**


-  **Smooth transition to a higher version of Intel® Cryptography
   Primitives Library**. You can build the same custom dynamic library
   from a higher version of Intel® Cryptography Primitives Library and
   substitute the libraries in your application without relinking.


.. note::


   The current Python\* version of the Intel IPP Custom Library Tool
   supports the host-host configuration only, the host-target
   configuration is currently not supported.

.. toctree::
   :maxdepth: 1

   
   system-requirements-for-custom-library-tool
   operation-modes
   building-a-custom-dll-with-custom-library-tool
   using-console-version-of-custom-library-tool