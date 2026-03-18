.. _using-custom-library-tool:

Using Custom Library Tool
=========================


Follow the steps below to build a custom dynamic/shared library using the Custom Library Tool:


#. Define a list of Intel® Cryptography Primitives Library functions that the Custom
   Library Tools should export to your custom dynamic/shared library. See the
   example text file ``my_functions.txt`` below:

   .. code-block:: none

      ippcpGetLibVersion
      ippsDESGetSize
      ippsDESInit
      ippsDESPack
      ippsDESUnpack


#. Run ``python clt.py`` with the following parameters:


   .. list-table:: 
      :header-rows: 0

      * - | ``-c``
          | ``--console``
        - Does nothing. The option is left for compatibility with previous versions of Custom Library Tool.
      * - | ``-g``
          | ``--generate``
          | ``-g={none|dynamic|static}``
          | ``--generate={none|dynamic|static}``
        - Enables the script generation mode (the build mode is used by default). For more information, see :ref:`Operation Modes <operation-modes>`. If no arguments are provided to the options ``-g`` / ``--generate``, dynamic dispatcher generation mode is used.
      * - | ``-n <name>``
          | ``--name <name>``
        - Output library name.
      * - | ``-p <path>``
          | ``--path <path>``
        - Path to the output directory.
      * - ``-root <root_path>``
        - Path to Intel® Cryptography Primitives Library package root directory
      * - | ``-f <function>``
          | ``--function <function>``
        - Name of a function to be included into your custom dynamic/shared library.
      * - | ``-ff <functions_file>``
          | ``--functions_file <functions_file>``
        - Path to a file with a list of functions to be included into your custom dynamic/shared library (the ``-f`` or ``--function`` flag can be used to add functions on the command line).
      * - | ``-arch={intel64}``
          | ``--architecture={intel64}``
        - Enables all actions for the Intel® 64 architecture. This is enabled by default. It is left for compatibility with previous versions of Custom Library Tool.
      * - | ``-tl={tbb|openmp}``
          | ``--threading_layer_type={tbb|openmp}``
        - Does nothing. This option is not applicable in case of Intel® Cryptography Primitives Library.
      * - | ``-d <cpu_set>``
          | ``--custom_dispatcher <cpu_set>``
        - Sets the exact list of CPUs that must be supported by custom dynamic/shared library and generates a C-file with the custom dispatcher.
      * - ``--prefix <prefix>``
        - Renames selected functions with specified prefix in the custom dispatcher files.
      * - | ``-h``
          | ``--help``
        - Prints command help.




   For example:


   .. code-block:: bash


      # Generate build scripts
      # with the output shared library name "my_custom_lib"
      # with functions defined in the "my_functions.txt" file
      # optimized only for processors with
      # Intel® Advanced Vector Extensions 512 (Intel® AVX-512)
      # using Intel® Cryptography Primitives Library

      python3 clt.py \
        -g \
        -n my_custom_lib \
        -p "~/my_project" \
        -ff "~/my_project/my_functions.txt" \
        -d avx512bw
