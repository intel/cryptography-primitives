.. _building-crypto-primitives-library-applications:

Building Intel® Cryptography Primitives Library Applications
============================================================


The code example below represents a short application to help you get
started with Intel® Cryptography Primitives Library:


.. code:: c


   #include "ippcp.h"
   #include <stdio.h>
   int main(int argc, char* argv[])
   {
      const CryptoLibraryVersion *lib;
      IppStatus status;
      Ipp64u mask, emask;


      /* Get Intel(R) Cryptography Primitives Library version info */
      lib = cryptoGetLibVersion();
      printf("%s %s\n", lib->strVersion);


      /* Get CPU features and features enabled with selected library level */
      status = ippcpGetCpuFeatures( &mask );
      if( ippStsNoErr == status ) {
         emask = ippcpGetEnabledCpuFeatures();
         printf("Features supported by CPU\tby Intel(R) Cryptography Primitives Library\n");
         printf("-----------------------------------------\n");
         printf("  ippCPUID_MMX        = ");
         printf("%c\t%c\t",( mask & ippCPUID_MMX ) ? 'Y':'N',( emask & ippCPUID_MMX ) ? 'Y':'N');
         printf("Intel(R) Architecture MMX technology supported\n");
         printf("  ippCPUID_SSE        = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSE ) ? 'Y':'N',( emask & ippCPUID_SSE ) ? 'Y':'N');
         printf("Intel(R) Streaming SIMD Extensions (Intel(R) SSE)\n");
         printf("  ippCPUID_SSE2       = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSE2 ) ? 'Y':'N',( emask & ippCPUID_SSE2 ) ? 'Y':'N');
         printf("Intel(R) Streaming SIMD Extensions 2 (Intel(R) SSE2)\n");
         printf("  ippCPUID_SSE3       = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSE3 ) ? 'Y':'N',( emask & ippCPUID_SSE3 ) ? 'Y':'N');
         printf("Intel(R) Streaming SIMD Extensions 3 (Intel(R) SSE3)\n");
         printf("  ippCPUID_SSSE3      = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSSE3 ) ? 'Y':'N',( emask & ippCPUID_SSSE3 ) ? 'Y':'N');
         printf("Supplemental Streaming SIMD Extensions 3 (SSSE3)\n");
         printf("  ippCPUID_MOVBE      = ");
         printf("%c\t%c\t",( mask & ippCPUID_MOVBE ) ? 'Y':'N',( emask & ippCPUID_MOVBE ) ? 'Y':'N');
         printf("The processor supports MOVBE instruction\n");
         printf("  ippCPUID_SSE41      = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSE41 ) ? 'Y':'N',( emask & ippCPUID_SSE41 ) ? 'Y':'N');
         printf("Intel(R) Streaming SIMD Extensions 4.1 (Intel(R) SSE4.1)\n");
         printf("  ippCPUID_SSE42      = ");
         printf("%c\t%c\t",( mask & ippCPUID_SSE42 ) ? 'Y':'N',( emask & ippCPUID_SSE42 ) ? 'Y':'N');
         printf("Intel(R) Streaming SIMD Extensions 4.2 (Intel(R) SSE4.2)\n");
         printf("  ippCPUID_AVX        = ");
         printf("%c\t%c\t",( mask & ippCPUID_AVX ) ? 'Y':'N',( emask & ippCPUID_AVX ) ? 'Y':'N');
         printf("Intel(R) Advanced Vector Extensions (Intel(R) AVX) instruction set\n");
         printf("  ippAVX_ENABLEDBYOS  = ");
         printf("%c\t%c\t",( mask & ippAVX_ENABLEDBYOS ) ? 'Y':'N',( emask & ippAVX_ENABLEDBYOS ) ? 'Y':'N');
         printf("The operating system supports Intel(R) AVX\n");
         printf("  ippCPUID_AES        = ");
         printf("%c\t%c\t",( mask & ippCPUID_AES ) ? 'Y':'N',( emask & ippCPUID_AES ) ? 'Y':'N');
         printf("Intel(R) Advanced Encryption Standard New Instructions (Intel(R) AES-NI)\n");
         printf("  ippCPUID_SHA        = ");
         printf("%c\t%c\t",( mask & ippCPUID_SHA ) ? 'Y':'N',( emask & ippCPUID_SHA ) ? 'Y':'N');
         printf("Intel(R) Secure Hash Algorithm - New Instructions (Intel(R) SHA-NI)\n");
         printf("  ippCPUID_CLMUL      = ");
         printf("%c\t%c\t",( mask & ippCPUID_CLMUL ) ? 'Y':'N',( emask & ippCPUID_CLMUL ) ? 'Y':'N');
         printf("PCLMULQDQ instruction\n");
         printf("  ippCPUID_RDRAND     = ");
         printf("%c\t%c\t",( mask & ippCPUID_RDRAND ) ? 'Y':'N',( emask & ippCPUID_RDRAND ) ? 'Y':'N');
         printf("Read Random Number instructions\n");
         printf("  ippCPUID_F16C       = ");
         printf("%c\t%c\t",( mask & ippCPUID_F16C ) ? 'Y':'N',( emask & ippCPUID_F16C ) ? 'Y':'N');
         printf("Float16 instructions\n");
         printf("  ippCPUID_AVX2       = ");
         printf("%c\t%c\t",( mask & ippCPUID_AVX2 ) ? 'Y':'N',( emask & ippCPUID_AVX2 ) ? 'Y':'N');
         printf("Intel(R) Advanced Vector Extensions 2 (Intel(R) AVX2) instruction set\n");
         printf("  ippCPUID_AVX512F    = ");
         printf("%c\t%c\t",( mask & ippCPUID_AVX512F ) ? 'Y':'N',( emask & ippCPUID_AVX512F ) ? 'Y':'N');
         printf("Intel(R) Advanced Vector Extensions 3.1 instruction set\n");
         printf("  ippCPUID_AVX512CD   = ");
         printf("%c\t%c\t",( mask & ippCPUID_AVX512CD ) ? 'Y':'N',( emask & ippCPUID_AVX512CD ) ? 'Y':'N');
         printf("Intel(R) Advanced Vector Extensions CD (Conflict Detection) instruction set\n");
         printf("  ippCPUID_AVX512ER   = ");
         printf("%c\t%c\t",( mask & ippCPUID_AVX512ER ) ? 'Y':'N',( emask & ippCPUID_AVX512ER ) ? 'Y':'N');
         printf("Intel(R) Advanced Vector Extensions ER instruction set\n");
         printf("  ippCPUID_ADCOX      = ");
         printf("%c\t%c\t",( mask & ippCPUID_ADCOX ) ? 'Y':'N',( emask & ippCPUID_ADCOX ) ? 'Y':'N');
         printf("ADCX and ADOX instructions\n");
         printf("  ippCPUID_RDSEED     = ");
         printf("%c\t%c\t",( mask & ippCPUID_RDSEED ) ? 'Y':'N',( emask & ippCPUID_RDSEED ) ? 'Y':'N');
         printf("The RDSEED instruction\n");
         printf("  ippCPUID_PREFETCHW  = ");
         printf("%c\t%c\t",( mask & ippCPUID_PREFETCHW ) ? 'Y':'N',( emask & ippCPUID_PREFETCHW ) ? 'Y':'N');
         printf("The PREFETCHW instruction\n");
         printf("  ippCPUID_KNC        = ");
         printf("%c\t%c\t",( mask & ippCPUID_KNC ) ? 'Y':'N',( emask & ippCPUID_KNC ) ? 'Y':'N');
         printf("Intel(R) Xeon Phi™ Coprocessor instruction set\n");
      }
      return 0;
   }


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
