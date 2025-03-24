.. _dispatching:

Dispatching
===========


Intel® Cryptography Primitives Library uses multiple function implementations optimized
for various CPUs. Dispatching refers to detection of your CPU and
selecting the corresponding Intel® Cryptography Primitives Library binary path. For
example, the :file:`ippcp` library in the :file:`/redist/lib/ippcp` directory
contains cryptographic functions optimized for 64-bit applications on
processors with Intel® Advanced Vector Extensions (Intel® AVX) enabled
such as the 2\ :sup:`nd` Generation Intel® Core™ processor family.


A single Intel® Cryptography Primitives Library function, for example
:samp:`ippsSHA256Update()`, may have many versions, each one optimized to run on
a specific Intel® processor with specific architecture, for example, the
64-bit version of this function optimized for the 2\ :sup:`nd`
Generation Intel® Core™ processor is :samp:`e9_ippsSHA256Update()`, and the
version optimized for 64-bit applications on processors with Intel®
Streaming SIMD Extensions 4.2 (Intel® SSE 4.2) is :samp:`y8_ippsSHA256Update()`.
This means that a prefix before the function name determines the CPU
model. However, during normal operation the dispatcher determines the
best version and you can call a generic function (:samp:`ippsSHA256Update()` in
this example).


Intel® Cryptography Primitives Library is designed to support application development
on various Intel® architectures. This means that the API definition is
common for all processors, while the underlying function implementation
takes into account the strengths of each hardware generation.


By providing a single cross-architecture API, Intel® Cryptography Primitives Library
enables you to port features across Intel® processor-based desktop,
server, and mobile platforms. You can use your code developed for one
processor architecture for many processor generations.


The following table shows processor-specific codes that Intel® Cryptography Primitives Library
uses:


.. list-table:: Description of Codes Associated with Processor-Specific Libraries
   :header-rows: 1
   :widths: 1 1 1 3

   * -  Intel® 64 architecture
     -  Windows\*
     -  Linux\* OS
     -  Description
   * -  **m7**
     -  +
     -  +
     -  Optimized for processors with Intel SSE3
   * -  **y8**
     -  +
     -  +
     -  Optimized for processors with Intel SSE4.2
   * -  **l9**
     -  +
     -  +
     -  Optimized for processors with Intel® Advanced Vector Extensions 2 (Intel® AVX2)
   * -  **k0**
     -  +
     -  +
     -  Optimized for processors with Intel® Advanced Vector Extensions 512 (Intel® AVX-512)(formerly codenamed SkyLake)
   * -  **k1**
     -  +
     -  +
     -  Optimized for processors with Intel® Advanced Vector Extensions 512 (Intel® AVX-512)(formerly codenamed IceLake)




.. list-table::
   :header-rows: 1

   * -  Product and Performance Information
   * -  Performance varies by use, configuration and other factors. Learn more at `www.Intel.com/PerformanceIndex <https://www.Intel.com/PerformanceIndex>`__.

        Notice revision #20201201

