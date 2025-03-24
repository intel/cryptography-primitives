.. _setting-environment-variables:

Setting Environment Variables
=============================


When the installation of  Intel® Cryptography Primitives Library is complete, set the
environment variables in the command shell using one of the script files in
the appropriate directory of the Unified Directory Layout or the Component
Directory Layout. To learn more about these directory layouts,
see :ref:`Finding Intel® Cryptography Primitives Library on Your System<finding-crypto-primitives-library-on-your-system>`.

**Unified Directory Layout**

-  On Windows\* OS:

   :file:`C:/Program files (x86)/Intel/oneAPI/<toolkit-version>/oneapi-vars.bat`
   (on certain systems, instead of :file:`Program Files (x86)`,
   the directory name is :file:`Program Files`)

-  On Linux\* OS:

   -  admin: :file:`/opt/intel/oneapi/<toolkit-version>/oneapi-vars.sh`
   -  user: :file:`~/intel/oneapi/<toolkit-version>/oneapi-vars.sh`


**Component Directory Layout**
Use the ``vars`` files located in the :file:`bin` subdirectory
of the Intel® Cryptography Primitives Library installation
directory:


On Windows\* OS:

.. list-table::
   :widths: 1 2


   * -  :file:`vars.bat`
     -  for the Intel® 64 architecture.


On Linux\* OS:

.. list-table::
   :header-rows: 1
   :widths: 1 2

   * -  Shell
     -  Script File
   * -  C
     -  :file:`vars.csh`
   * -  Bash
     -  :file:`vars.sh`


When using the :file:`vars` script, you need to specify the architecture as a
parameter. For example:

- :samp:`vars.bat intel64`

  sets the environment for Intel® Cryptography Primitives Library to use the Intel® 64 architecture on Windows\* OS.
- :samp:`. vars.sh intel64`

  sets the environment for Intel® Cryptography Primitives Library to use the Intel® 64 architecture on Linux\* OS.


The scripts set the following environment variables:

.. list-table::
   :header-rows: 1
   :widths: 1 1 2

   * -  Windows\* OS
     -  Linux\* OS
     -  Purpose
   * -  :samp:`IPPCRYPTOROOT`
     -  :samp:`IPPCRYPTOROOT`
     -  Point to the Intel® Cryptography Primitives Library installation directory
   * -  :samp:`LIB`
     -  n/a
     -  Add the search path for the Intel® Cryptography Primitives Library single-threaded libraries
   * -  :samp:`PATH`
     -  :samp:`LD_LIBRARY_PATH`
     -  Add the search path for the Intel® Cryptography Primitives Library single-threaded DLLs
   * -  :samp:`INCLUDE`
     -  n/a
     -  Add the search path for the Intel® Cryptography Primitives Library header files

