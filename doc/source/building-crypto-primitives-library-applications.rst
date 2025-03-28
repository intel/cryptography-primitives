.. _building-crypto-primitives-library-applications:

Building Intel® Cryptography Primitives Library Applications
============================================================


The code example below represents a short application to help you get
started with Intel® Cryptography Primitives Library:

.. literalinclude:: ../../examples/common/library_get_started.cpp
    :language: c


This application consists of three sections:


#. Initialize the Intel® Cryptography Primitives Library. The Intel® Cryptography
   Primitives Library is auto-initialized with the first call of an
   Intel® Cryptography Primitives Library function.


   In certain debugging scenarios, it is helpful to force a specific
   implementation layer using :samp:`ippcpSetCpuFeatures()`, instead of the best
   as chosen by the dispatcher.


#. Get the library layer name and version. You can also get the version
   information using the :file:`ippcpversion.h` file located in the :file:`/include`
   directory.


#. Show the hardware optimizations used by the selected library layer
   and supported by CPU.


Building the First Example on Windows\* OS
------------------------------------------


To build the code example above on Windows\* OS, follow the steps:


#. Start Microsoft Visual Studio\* and create an empty C++ project.


#. Add a new c file and paste the code into it.


#. Set the include directories and the linking model as described in
   :ref:`Linking Your Microsoft\* Visual Studio\* Project with
   Intel® Cryptography Primitives Library <linking-visual-studio-project-with-crypto-primitives-library>`.


#. Compile and run the application.


Building the First Example on Linux\* OS
----------------------------------------


To build the code example above on Linux\* OS, follow the steps:


#. Paste the code into the editor of your choice.


#. Make sure the compiler and Intel® Cryptography Primitives Library
   variables are set in your shell. For information on how to set
   environment variables, see :ref:`Setting Environment
   Variables <setting-environment-variables>`.


#. Compile with the following command:

     .. code:: cpp

      icpx ippcptest.cpp -o ippcptest -I $IPPCRYPTOROOT/include -L $IPPCRYPTOROOT/lib -lippcp.


For more information, see :ref:`Linking Options <linking-options>`.


#. Run the application.

See Also
--------

- :ref:`Linking Your Microsoft\* Visual Studio\* Project with Intel® Cryptography Primitives Library <linking-visual-studio-project-with-crypto-primitives-library>`
- :ref:`Setting Environment Variables <setting-environment-variables>`
- :ref:`Linking Options <linking-options>`
- :ref:`Dispatching <dispatching>`
