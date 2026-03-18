.. _using-custom-library-tool-for-crypto-primitives-library:

Using Custom Library Tool for Intel® Cryptography Primitives Library
====================================================================


With the Custom Library Tool, you can build your own dynamic/shared library containing only the
Intel® Cryptography Primitives Library functionality that is necessary for
your application.


The use of custom libraries built with the Custom Library Tool provides
the following advantages:


-  **Package size**. Your package may be much smaller if linked
   with a custom library because standard dynamic/shared libraries
   contain all optimized versions of Intel® Cryptography Primitives Library
   functions and a dispatcher. The following table compares the contents
   and size of packages for an end-user application linked with a custom
   dynamic/shared library and an application linked
   with the standard Intel® Cryptography Primitives Library dynamic/shared libraries:


   .. list-table::
     :header-rows: 1

     * - OS
       - Application linked with custom dynamic/shared library
       - Application linked with Intel® Cryptography Primitives Library dynamic/shared libraries  
     * - Windows\*
       - | :file:`crypto_test_app.exe`
         | :file:`crypto_custom_lib.dll`
         |
         | **Package size: 0.1 Mb**
       - | :file:`crypto_test_app.exe`
         | :file:`ippcp.dll`
         |
         | **Package size: 7.4 Mb**
     * - Linux\* OS
       - | :file:`crypto_test_app`
         | :file:`crypto_custom_lib.so`
         |
         | **Package size: 0.1 Mb**
       - | :file:`crypto_test_app`
         | :file:`libippcp.so`
         |
         | **Package size: 9.0 Mb**


-  **Smooth transition to a higher version of Intel® Cryptography
   Primitives Library**. You can build the same custom dynamic/shared library
   from a higher version of Intel® Cryptography Primitives Library and
   substitute the libraries in your application without relinking.


.. note::


   The current Python\* version of the Custom Library Tool
   supports the host-host configuration only, the host-target
   configuration is currently not supported.

.. toctree::
   :maxdepth: 1

   
   system-requirements-for-custom-library-tool
   operation-modes
   using-custom-library-tool
