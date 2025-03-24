.. _notational-conventions:


Notational Conventions
======================


The code and syntax used in this document for function and variable
declarations are written in the ANSI C style. However, versions of
Intel® Cryptography Primitives Library for different processors or operating systems may,
of necessity, vary slightly.


.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201


In this document, notational conventions include:

-  Fonts used for distinction between the text and the code
-  Naming conventions for different items.


Font Conventions
----------------


The following font conventions are used throughout this document:


.. list-table::
   :header-rows: 0

   * - **This type style**
     -  Mixed with the uppercase in function names, code examples, and call statements, for example, ippsAdd_BNU.
   * - ``This type style``
     -  Parameters in function prototype parameters and parameters description, for example, pCtx, pSrcMesg.




Naming Conventions
------------------


The naming conventions for different items are the same as used by the
Intel® Cryptography Primitives Library software.


-  All names of the functions used for cryptographic operations have the
   ipps prefix. In code examples, you can distinguish the Intel® Cryptography Primitives Library
   interface functions from the application functions by this prefix.


   .. note::


      In this document, each function is introduced by its short name
      (without the ipps prefix and descriptors) and a brief description
      of its purpose.


      The ipps prefix in function names is always used in code examples
      and function prototypes. In the text, this prefix is omitted when
      referring to the function group.


-  Each new part of a function name starts with an uppercase character,
   without underscore, for example, ippsDESInit.

