.. _compiler-integration:

Compiler Integration
====================



Intel® oneAPI DPC++/C++ Compiler and Microsoft Visual Studio\* compilers simplify
developing with Intel® Cryptography Primitives Library.


On Windows\* OS, a default installation of Intel® Parallel Studio XE
Composer Edition and Intel® Cryptography Primitives Library installs integration
plug-ins. These enable the option to configure your Microsoft Visual
Studio\* project for automatic linking with Intel® Cryptography Primitives Library.


Intel® oneAPI DPC++/C++ Compiler also provides command-line parameters to set the
link/include directories:


-  On Windows\* OS:

   :samp:`/Qipp:crypto`

-  On Linux\* OS:

   :samp:`-ipp:crypto` and :samp:`–ipp:nonpic_crypto`


See Also
--------

- :ref:`Linking Your Microsoft\* Visual Studio\* Project with Intel® Cryptography Primitives Library <linking-visual-studio-project-with-crypto-primitives-library>`
- :ref:`Linking Your Application with Intel® Cryptography Primitives Library <linking-app-with-crypto-primitives-library>`
