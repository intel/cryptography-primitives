.. _appendix-performance-test-perfsys-cli-options:

Performance Test Tool (perfsys) Command Line Options
====================================================


Intel® Cryptography Primitives Library
installation includes a command-line tool for performance testing in the
:samp:`<{install_dir}>/tools/perfsys` directory. The :samp:`ps_ippcp` executable
measures performance for all Intel® Cryptography Primitives Library functions. The
:samp:`ps_crypto_mb` executable measures performance for all Intel® Cryptography Primitives Library
Multi-buffer functions. Note that :samp:`ps_crypto_mb` executable
can be ran on 3rd Gen Intel® Xeon® Scalable processors only.


Many factors may affect Intel® Cryptography Primitives Library performance. One of the
best way to understand them is to run multiple tests in the specific
environment you are targeting for optimization. The purpose of the
perfsys tools is to simplify performance experiments and empower
developers with useful information to get the best performance from
Intel® Cryptography Primitives Library functions.


With the command-line options you can:


-  Create a list of functions to test
-  Set parameters for each function
-  Set image/buffer sizes


To simplify re-running specific tests, you can define the functions and
parameters in the initialization file, or enter them directly from the
console.


The command-line format is:


.. code-block:: bash


   ps_ippcp.exe [option_1] [option_2] ... [option_n]


To invoke the short reference for the command-line options, use :samp:`-?`
or :samp:`-h` commands:


.. code-block:: bash


   ps_ippcp.exe -h


The command-line options are divided into several groups by
functionality. You can enter options in arbitrary order with at least
one space between each option name. Some options (like :samp:`-r, -R, -o, -O`)
may be entered several times with different file names, and option :samp:`-f`
may be entered several times with different function patterns. For
detailed descriptions of the perfsys command-line options see the
following table:


Performance Test Tool Command Line Options
------------------------------------------

.. list-table:: Group: Set optimization layer to test
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`-T[{cpu-features}]`
     - Call :samp:`ippcpSetCpuFeatures`


.. list-table:: Group: Report Configuration
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`-A<Timing|Params|Misalign|All>`
     - Prompt for the parameters before every test from console
   * - :samp:`-o[{<file-name>}]`
     - Create :samp:`{<file-name>}.txt` file and write console output to it
   * - :samp:`-O[{<file-name>}]`
     - Add console output to the file :samp:`{<file-name>}.txt`
   * - :samp:`-L {<ERR|WARN|PARM|INFO|TRACE>}`
     - Set detail level of the console output
   * - :samp:`-r[{<file-name>}]`
     - Create :samp:`{<file-name>}.csv` file and write perfsys results to it
   * - :samp:`-R[{<file-name>}]`
     - Add test results to the file :samp:`{<file-name>}.csv`
   * - :samp:`-q[{<file-name>}]`
     - Create :samp:`{<file-name>}.csv` and write function parameter name lines to it
   * - :samp:`-q+`
     - Add function parameter name lines to perfsys results table file
   * - :samp:`-Q`
     - Exit after creation of the function parameter name table
   * - :samp:`-u[{<file-name>}]`
     - Create :samp:`{<file-name>}.csv` file and write summary table (:samp:`'_sum'` is added to default file name)
   * - :samp:`-U[{<file-name>}]`
     - Add summary table to the file :samp:`{<file-name>}.csv` (:samp:`'_sum'` is added to default file name)
   * - :samp:`-g[{<file-name>}]`
     - Create signal file at the end of the whole testing
   * - :samp:`-l{<dir-name>}`
     - Set default directory for output files
   * - :samp:`-k<and|or>`
     - Compose different keys (-f, -t, -m) by logical operation
   * - :samp:`-F{<func-name>}`
     - Start testing from function with func-name full name
   * - :samp:`-Y{<HIGH/NORMAL>}`
     - Set high or normal process priority (normal is default)
   * - :samp:`-H[ONLY]`
     - Add 'Interest' column to :file:`.csv` file [and run only hot tests]
   * - :samp:`-N{<num-threads>}`
     - Call :samp:`ippcpSetNumThreads({<num-treads>})`
   * - :samp:`-s[-]`
     - Sort or do not sort functions (sort mode is default)
   * - :samp:`-e`
     - Enumerate tests and exit
   * - :samp:`-v`
     - Display the version number of the perfsys and exit
   * - :samp:`-@{<file-name>}`
     - Read command-line options for the specified file


.. list-table:: Group: Set function parameters
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`-d{<name>}={<value>}`
     - Set perfsys parameter value


.. list-table:: Group: Initialization files
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`i[{<file-name>}]`
     - Read perfsys parameters from the file :samp:`{<file-name>}.ini`
   * - :samp:`-I[{<file-name>}]`
     - Write perfsys parameters to the file :samp:`{<file-name>}.ini` and exit
   * - :samp:`-P`
     - Read tested function names from the :file:`.ini` file
   * - :samp:`-n{<title-name>}`
     - Set default title name for :file:`.ini` file and output files
   * - :samp:`-p<dir-name>}`
     - Set default directory for :file:`.ini` file and input test data files


.. list-table:: Group: Select functions
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`-f{<or-pattern>}`
     - Run tests for functions with ``pattern`` in their names, case sensitive
   * - :samp:`-f-{<not-pattern>}`
     - Do not test functions with ``pattern`` in their names, case sensitive
   * - :samp:`-f+{<and-pattern>}`
     - Run tests only for functions with ``pattern`` in their names, case sensitive
   * - :samp:`-f={<eq-pattern>}`
     - Run tests for functions with ``pattern`` full name
   * - :samp:`-t[-|+|=]{<pattern>}`
     - Run (do not run) tests with ``pattern`` in test name
   * - :samp:`-m[-|+|=]{<pattern>}`
     - Run (do not run) tests registered in file with ``pattern`` in file name


.. list-table:: Group: Help
   :header-rows: 1
   :widths: 1 2

   * - Option
     - Description
   * - :samp:`-h`
     - Display short help and exit
   * - :samp:`-hh`
     - Display extended help and exit
   * - :samp:`-h{<key>}`
     - Display extended help for the ``key`` and exit

