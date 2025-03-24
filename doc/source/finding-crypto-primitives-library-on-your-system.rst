.. _finding-crypto-primitives-library-on-your-system:

Finding Intel® Cryptography Primitives Library on Your System
=============================================================


The Unified Directory Layout was implemented in 2021.9
(Intel® oneAPI Toolkit release 2024.0). If you have
multiple toolkit versions installed, the Unified layout adds the ability
to ensure your development environment contains the component versions
that were released as part of that specific toolkit version.

The Unified Directory Layout is available **only** when installing the
Intel® oneAPI Base Toolkit (Base Kit). It is not available if you installed
Intel® Cryptography Primitives Library as a standalone component.

Environment variables are set up with a script called setvars or oneapi-vars,
depending on which layout you are using.

To understand more about the Unified Directory Layout, including how the
environment is initialized and the advantages of using the layout, see
`Use the setvars and oneapi-vars Scripts with
Linux\* <https://www.intel.com/content/www/us/en/docs/oneapi/programming-guide/2024-1/use-the-setvars-and-oneapi-vars-scripts-with-linux.html>`__
or
`Use the setvars and oneapi-vars Scripts with
Windows\* <https://www.intel.com/content/www/us/en/docs/oneapi/programming-guide/2024-1/use-the-setvars-and-oneapi-vars-scripts-with.html>`__.


By default, Intel® Cryptography Primitives Library
is installed in this directory:

**Unified Directory Layout**

-  On Windows\* OS:

   :file:`C:/Program files (x86)/Intel/oneAPI/{<toolkit-version>}`
   (on certain systems, instead of :file:`Program Files (x86)`,
   the directory name is :file:`Program Files`)

-  On Linux\* OS:

   -  admin: :file:`/opt/intel/oneapi/{<toolkit-version>}`
   -  user: :file:`~/intel/oneapi/{<toolkit-version>}`


**Component Directory Layout**

-  On Windows\* OS:

   :file:`C:/Program files (x86)/Intel/oneAPI` (on certain systems,
   instead of :file:`Program Files (x86)`,
   the directory name is :file:`Program Files`)
-  On Linux\* OS:

   -  admin: :file:`/opt/intel/oneapi`
   -  user: :file:`~/intel/oneapi`


The tables below describe the structure of the high-level directories
on:

-  `Windows\* OS <#windows>`__
-  `Linux\* OS <#linux>`__


.. _windows:

**Windows\* OS:**

.. list-table::
   :header-rows: 1
   :widths: 1 1 2

   * -  Directory in Component Directory Layout
     -  Directory in Unified Directory Layout
     -  Contents
   * -  ``cmake``
     -  ``cmake``
     -  CMake configuration files to use Intel® Cryptography Primitives Library in CMake scripts
   * -  ``components``
     -  ``components``
     -  Intel® Cryptography Primitives Library interfaces and example files
   * -  ``documentation``
     -  ``share\doc\ippcp``
     -  Intel® Cryptography Primitives Library documentation
   * -  ``env``
     -  ``env``
     -  Batch files to set environmental variables in the user shell
   * -  ``include``
     -  ``include``
     -  Header files for the library functions
   * -  ``lib\intel64``
     -  ``lib``
     -  Single-threaded static libraries for the Intel® 64 architecture
   * -  ``licensing``
     -  ``share\doc\ippcp\licensing``
     -  Intel® Cryptography Primitives Library license files
   * -  ``lib\intel64``
     -  ``bin``
     -  Single-threaded DLLs for applications running on processors with the Intel® 64 architecture
   * -  ``tools\custom_library_tool_python``
     -  ``opt\ippcp\tools\custom_library_tool_python``
     -  Command-line and GUI tool for building custom dynamic libraries


.. _linux:

**Linux\* OS:**

.. list-table::
   :header-rows: 1
   :widths: 1 1 2

   * -  Directory in Component Directory Layout
     -  Directory in Unified Directory Layout
     -  Contents
   * -  ``share/doc/ippcp/examples``
     -  ``share/doc/ippcp/examples``
     -  Intel® Cryptography Primitives Library interfaces and example files
   * -  ``share/doc/ippcp``
     -  ``share/doc/ippcp``
     -  Intel® Cryptography Primitives Library documentation
   * -  ``env/vars.sh``
     -  bash files are handled through ``oneapi-vars.sh``.
     -  bash files to set environmental variables in the user shell
   * -  ``include``
     -  ``include``
     -  Header files for the library functions
   * -  ``lib/intel64``
     -  ``lib``
     -  Single-threaded static libraries for the Intel® 64 architecture
   * -  ``share/doc/ippcp/licensing``
     -  ``share/doc/ippcp/licensing``
     -  Intel® Cryptography Primitives Library license files
   * -  ``modulefiles``
     -  ``etc/modulefiles/intel_ippcp_intel64``
     -  Module files for environment configuration
   * -  ``tools/custom_library_tool_python``
     -  ``opt/ipp/tools/custom_library_tool_python``
     -  Command-line and GUI tool for building custom dynamic libraries

