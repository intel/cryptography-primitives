.. _setcpufeatures:


SetCpuFeatures
==============


Sets the processor-specific library code for the specified processor
features.


Syntax
------


IppStatus ippcpSetCpuFeatures(Ipp64u cpuFeatures);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     cpuFeatures
     -     Features to be supported by the library. Refer to ippcpdefs.h for ippCPUID_xx definition.




Description
-----------


This function sets the processor-specific code of the Intel® Cryptography Primitives Library 
according to the processor features specified in
cpuFeatures. You can use the following predefined sets of features (the
FM suffix below means *feature mask*):

.. code-block:: cpp


   #define PX_FM ( ippCPUID_MMX | ippCPUID_SSE | ippCPUID_SSE2 )
   #define Y8_FM (PX_FM | ippCPUID_SSE3 | ippCPUID_SSSE3 | ippCPUID_MOVBE | ippCPUID_SSE41 | ippCPUID_SSE42 | ippCPUID_AES | ippCPUID_CLMUL | ippCPUID_SHA)
   #define E9_FM (Y8_FM | ippCPUID_AVX | ippAVX_ENABLEDBYOS | ippCPUID_RDRAND | ippCPUID_F16C)
   #define L9_FM (E9_FM | ippCPUID_MOVBE | ippCPUID_AVX2 | ippCPUID_ADCOX | ippCPUID_RDSEED | ippCPUID_PREFETCHW)
   #define K0_FM (L9_FM | ippCPUID_AVX512F | ippCPUID_AVX512CD | ippCPUID_AVX512VL | ippCPUID_AVX512BW | ippCPUID_AVX512DQ | ippAVX512_ENABLEDBYOS)
   #define K1_FM (K0_FM | ippCPUID_SHA | ippCPUID_AVX512VBMI | ippCPUID_AVX512VBMI2 | ippCPUID_AVX512IFMA | ippCPUID_AVX512GFNI | ippCPUID_AVX512VAES | ippCPUID_AVX512VCLMUL)
   #define D1_FM (K1_FM | ippCPUID_AVX10_2)


.. note::


   Do not use any other Intel® Cryptography Primitives Library function while
   ippcpSetCpuFeatures is executing. Otherwise, your application
   behavior is undefined.


.. note::


   To avoid initialization of internal structures for one Intel®
   architecture and then call of the processing function that is
   optimized for another architecture, do not use the
   ippcpSetCpuFeatures function in chains of Intel® Cryptography Primitives Library
   connected calls like ``<processing function``\ GetSize +
   ``<processing function``\ Init + ``<processing function>``.
   Otherwise, Intel® Cryptography Primitives Library functionality behavior is
   undefined.


Intel® Cryptography Primitives Library supports two internal sets of CPU
features:


-  *Real CPU features*: the features that are supported by the CPU at
   which the library is executed. These features are read-only and can
   be obtained with the
   :ref:`ippcpGetCpuFeatures <getcpufeatures>`
   function.


-  *Enabled features*: the features that are enabled externally to
   Intel® Cryptography Primitives Library by the application. These features can be set with
   ippcpSetCpuFeatures.


The ippcpSetCpuFeatures function provides additional flexibility in
measuring performance improvements reached by using specific CPU
features. For example, the first call of any Intel® Cryptography Primitives Library
function in an application running on the 4th Generation Intel® Core™ i7
processor with 64-bit OS installed dispatches the L9 code version
optimized for Intel® Advanced Vector Extensions 2 (Intel® AVX2) with
several other features like fast 16-bit floating point support, Intel®
AES New Instructions (Intel® AES-NI), PCLMULQDQ new instructions
support.


To check performance improvement for all Intel® Cryptography Primitives Library
functionality reached by using Intel® AVX2, you can run a benchmark for
the currently dispatched version of code and then compare performance
with the Intel® Advanced Vector Extensions (Intel® AVX) version of code
with Intel® AVX2 disabled. To disable Intel AVX2, call
``ippcpSetCpuFeatures(E9_FM)``. To enable Intel AVX2 back, call
``ippcpSetCpuFeatures( L9_FM )``. Thus, you can use the
ippcpSetCpuFeatures function to dispatch any version of Intel® Cryptography Primitives Library
code and enable/disable specific CPU features. If you are
not well familiar with the features of your CPU, use the
auto-initialization mechanism for the default library behavior.


.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201



Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -      Indicates that the required processor-specific code is successfully set.
   * -     ippStsCpuMismatch
     -      Indicates that the specified processor features are not valid. Previously set code is used. If the requested feature is below the minimal supported by the **px** library - that is Intel® Streaming SIMD Extensions 2 (Intel® SSE2) for Intel® 64 architecture, **px** code is dispatched.
   * -     ippStsFeatureNotSupported
     -     Indicates that the current CPU does not support at least one of the requested features. If the ippCPUID_NOCHECK bit of the cpuFeatures parameter is set to 1, these not supported features are enabled, otherwise - disabled.
   * -     ippStsUnknownFeature
     -     Indicates that at least one of the requested features is unknown. It means that the feature is not defined in the ippdefs.h file. Further behavior of the library depends on known features passed to cpuFeatures. Unknown features are ignored.
   * -     ippStsFeaturesCombination
     -     Indicates that the combination of features is not correct. For example, ippCPUID_AVX2 bit is set to 1 in cpuFeatures, but at least one of the ippCPUID_MMX, ippCPUID_SSE, …, ippCPUID_AVX bits is not set. All these missing bits, if supported by CPU, are set to 1. This means that if the library supports the Intel® AVX2 code, it also internally uses all known MMX™, Intel® SSE, and Intel® AVX extensions, which are below Intel® AVX2.



