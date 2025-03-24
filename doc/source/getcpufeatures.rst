.. _getcpufeatures:



GetCpuFeatures
==============


Retrieves the processor features.


Syntax
------


IppStatus ippсpGetCpuFeatures(Ipp64u\* pFeaturesMask);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pFeaturesMask
     - Pointer to the features mask. Possible value is ippCPUID_GETINFO_A.




Description
-----------


This function retrieves some of the CPU features returned by the
function CPUID.1 and stores them consecutively in the mask
pFeaturesMask. The following table lists the features stored in the
mask.


.. list-table::
   :header-rows: 1

   * - Mask Value
     - Bit Name
     - Feature
     - Mask Bit Number
   * - 0x00000001
     - ippCPUID_MMX
     - MMX™ Technology
     - 0
   * - 0x00000002
     - ippCPUID_SSE
     - Intel® Streaming SIMD Extensions
     - 1
   * - 0x00000004
     - ippCPUID_SSE2
     - Intel® Streaming SIMD Extensions 2
     - 2
   * - 0x00000008
     - ippCPUID_SSE3
     - Intel® Streaming SIMD Extensions 3
     - 3
   * - 0x00000010
     - ippCPUID_SSSE3
     - Supplemental Streaming SIMD Extensions 3
     - 4
   * - 0x00000020
     - ippCPUID_MOVBE
     - MOVBE (Move Data After Swapping Bytes) instruction is supported
     - 5
   * - 0x00000040
     - ippCPUID_SSE41
     - Intel® Streaming SIMD Extensions 4.1
     - 6
   * - 0x00000080
     - ippCPUID_SSE42
     - Intel® Streaming SIMD Extensions 4.2
     - 7
   * - 0x00000100
     - ippCPUID_AVX
     - The processor supports Intel® Advanced Vector Extensions (Intel® AVX) instruction set
     - 8
   * - 0x00000200
     - ippAVX_ENABLEDBYOS
     - The operating system supports Intel® AVX
     - 9
   * - 0x00000400
     - ippCPUID_AES
     - Intel® Advanced Encryption Standard New Instructions (Intel® AES-NI) are supported
     - 10
   * - 0x00000800
     - ippCPUID_CLMUL
     - PCLMULQDQ instruction is supported
     - 11
   * - 0x00002000
     - ippCPUID_RDRAND
     - Read Random Number instructions are supported
     - 13
   * - 0x00004000
     - ippCPUID_F16C
     - 16-bit floating point conversion instructions are supported
     - 14
   * - 0x00008000
     - ippCPUID_AVX2
     - Intel® Advanced Vector Extensions 2 (Intel® AVX2) instruction set is supported
     - 15
   * - 0x00010000
     - ippCPUID_ADCOX
     - ADCX and ADOX instructions are supported
     - 16
   * - 0x00020000
     - ippCPUID_RDSEED
     - RDSEED (Read Random SEED) instruction is supported.
     - 17
   * - 0x00040000
     - ippCPUID_PREFETCHW
     - PREFETCHW instruction is supported
     - 18
   * - 0x00080000
     - ippCPUID_SHA
     - Intel® Secure Hash Algorithm Extensions (Intel® SHA Extensions) are supported
     - 19
   * - 0x00100000
     - ippCPUID_AVX512F
     - Intel® Advanced Vector Extensions 512 (Intel® AVX-512) foundation instructions are supported
     - 20
   * - 0x00200000
     - ippCPUID_AVX512CD
     - Intel® AVX-512 Conflict Detection Instructions are supported
     - 21
   * - 0x00400000
     - ippCPUID_AVX512ER
     - Intel® AVX-512 exponential and reciprocal instructions are supported
     - 22
   * - 0x00800000
     - ippCPUID_AVX512PF
     - Intel® AVX-512 PF instruction set
     - 23
   * - 0x01000000
     - ippCPUID_AVX512BW
     - Intel® AVX-512 BW instruction set
     - 24
   * - 0x02000000
     - ippCPUID_AVX512DQ
     - Intel® AVX-512 DQ instruction set
     - 25
   * - 0x04000000
     - ippCPUID_AVX512VL
     - Intel® AVX-512 VL instruction set
     - 26
   * - 0x08000000
     - ippCPUID_AVX512VBMI
     - Intel® AVX-512 Bit Manipulation instructions
     - 27
   * - 0x10000000
     - ippCPUID_MPX
     - Intel® Memory Protection Extensions (Intel® MPX)
     - 28
   * - 0x20000000
     - ippCPUID_AVX512_4FMADDPS
     - Intel® AVX-512 DL floating-point single precision
     - 29
   * - 0x40000000
     - ippCPUID_AVX512_4VNNIW
     - Intel® AVX-512 DL enhanced word variable precision
     - 30
   * - 0x80000000
     - ippCPUID_KNC
     - Intel® Xeon Phi™ is supported
     - 31
   * - 0x100000000
     - ippCPUID_AVX512IFMA
     - Intel® AVX-512 IFMA (PMADD52) instruction set
     - 32
   * - 0x200000000
     - ippAVX512_ENABLEDBYOS
     - Intel® AVX-512 is supported by OS
     - 33
   * - 0x400000000
     - ippCPUID_AVX512GFNI
     - Intel® AVX-512 Bit Galois Field New Instructions
     - 34
   * - 0x800000000
     - ippCPUID_AVX512VAES
     - Intel® AVX-512 Bit Vector AES instructions
     - 35
   * - 0x1000000000
     - ippCPUID_AVX512VCLMUL
     - Intel® AVX-512 Bit Vector CLMUL instructions
     - 36
   * - 0x2000000000
     - ippCPUID_AVX512VBMI2
     - Intel® AVX-512 Bit Manipulation instructions 2
     - 37
   * - 0x4000000000
     - ippCPUID_AVX2VAES
     - Intel® AVX 256 Bit Vector AES instructions
     - 38
   * - 0x8000000000
     - ippCPUID_AVX2VCLMUL
     - Intel® instruction VPCLMULQDQ
     - 39
   * - 0x8000000000000000
     - ippCPUID_NOCHECK
     - Force ippSetCpuFeatures to set CPU features without check
     - 63

.. note::


   Intel\ :sup:`®` Itanium\ :sup:`®` processors are not supported.


.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201



Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error.
   * - ippStsNullPtrErr
     - Indicates an error condition when the pFeaturesMask pointer is NULL.
   * - ippStsNotSupportedCpu
     - Indicates that the processor is not supported.



