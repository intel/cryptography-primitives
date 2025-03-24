.. _linking-options:

Linking Options
===============


Intel® Cryptography Primitives Library is distributed as:


-  **Static library:** static linking results in a standalone executable
-  **Dynamic/shared library:** dynamic linking defers function
   resolution until runtime and requires that you bundle the
   redistributable libraries with your application


The following table provides description of libraries available for
linking.


.. list-table::
   :header-rows: 1
   :widths: 1 2

   * -
     -  **Single-threaded** (non-threaded)
   * -  **Description**
     -  Suitable for application-level threading
   * -  **Found in**
     -  Main package

        After installation:
        Component Directory Layout:
        ``<install directory>/lib/<arch>``

        Unified Directory Layout:

        64 bit: ``<install directory>/lib/``

   * -  **Static linking**
     -  Windows\* OS\: :samp:`mt` suffix in a library name (:samp:`ippcpmt.lib`)

        Linux\* OS: no suffix in a library name (:samp:`libippcp.a`)
   * -  **Dynamic Linking**
     -  Default (no suffix)

        Windows\* OS: :samp:`ippcp.lib`

        Linux\* OS: :samp:`libippcp.a`





.. note::


   On Linux\* OS, Intel® Cryptography Primitives Library depends on
   the Intel® C++ Compiler Classic runtime library :samp:`libirc.a`. You should
   add a link to this library into your project. You can find this
   library in the Intel® Cryptography Primitives Library or Intel® C++ Compiler
   :samp:`{<install directory>}/lib` folders.


See Also
--------

- :ref:`Linking Your Microsoft\* Visual Studio\* Project with Intel® Cryptography Primitives Library <linking-visual-studio-project-with-crypto-primitives-library>`
