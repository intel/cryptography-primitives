.. _using-console-version-of-custom-library-tool:

Using Console Version of Custom Library Tool
============================================


Follow the steps below to build a custom dynamic library using console
version of the Custom Library Tool:


#. Define a list of Intel® Cryptography Primitives Library functions that the Intel® Integrated Performance Primitives
   (Intel® IPP) Custom
   Library Tools should export to your custom dynamic library. See the
   example text file below:

   .. image:: GUID-20F62B7C-3FE2-4F04-AD51-621719596B13-low.png
      :width: 241px
      :align: left




#. Run :samp:`python main.py` with the following parameters:


   .. list-table::
      :widths: 1 2


      * -  :samp:`-c, --console`
        -  Launches the console version of the tool (the GUI version is used by default).
      * -  :samp:`-g, --generate`
        -  Enables the script generation mode (the build mode is used by default).
      * -  :samp:`-n {<name>}, --name {<name>}`
        -  Output library name.
      * -  :samp:`-p {<path>}, --path {<path>}`
        -  Path to the output directory.
      * -  :samp:`-root {<root_path>}`
        -  Path to Intel IPP or Intel® Cryptography Primitives Library package root directory
      * -  :samp:`-f {<function>}, --function {<function>}`
        -  Name of a function to be included into your custom dynamic library.
      * -  :samp:`-ff {<functions_file>}, --functions_file {<functions_file>}`
        -  Path to a file with a list of functions to be included into your final dynamic library (the :samp:`-f` or :samp:`--function` flag can be used to add functions on the command line).
      * -  ``-arch={intel64}``
        -  Enables all actions for the Intel® 64 architecture.
      * -  ``-tl={tbb|openmp}``
        -  Sets Intel® Threading Building Blocks or OpenMP\* as the threading layer.
      * -  :samp:`-d , --custom_dispatcher {<cpu_set>}`
        -  Sets the exact list of CPUs that must be supported by custom dynamic library and generates a C-file with the custom dispatcher.
      * -  :samp:`--prefix {<prefix>}`
        -  Renames selected functions with specified prefix in the custom    dispatcher files.
      * -  :samp:`-h, --help`
        -  Prints command help.




   For example:


   .. code-block:: bash


      # Generate build scripts in console mode
      # with the output dynamic library name "my_custom_dll.dll"
      # with functions defined in the "functions.txt" file
      # optimized only for processors with
      # Intel® Advanced Vector Extensions 512 (Intel® AVX-512)
      # using Intel® Cryptography Primitives Library


      python main.py -c -g
      -n my_custom_dll
      -p "C:\my_project"
      -ff "C:\my_project\functions.txt"
      -d avx512bw



