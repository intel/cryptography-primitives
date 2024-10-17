# Intel® Cryptography Primitives Library

This is a list of notable changes to Intel® Cryptography Primitives Library, in reverse chronological order.

## Intel(R) Cryptography Primitives Library 1.0.0
- Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) was renamed to Intel(R) Cryptography Primitives Library.
- Added IPPCP SM3 hash algorithm optimization with the new instruction set (SM3-NI) for Lunar Lake and Arrow Lake CPUs.
- Added Intel® AVX-IFMA RSA implementation to Crypto Multi buffer library.
- Fixed bug in IceLake optimization (`k1` branch) of ECDSA signature function caused by incorrect processing of R and S component's size and sign.
- Added FIPS selftest for Leighton-Micali Hash-Based Signatures(LMS) verification algorithm.
- Added examples for SM3 Hash / LMS post-quantum verification / NIST Curve P-256 ECDSA signature generation algorithms.
- Changed `-DBABASSL:BOOL=on` CMake build option to `-DTONGSUO:BOOL=on` for Tongsuo library.
- Removed API that were deprecated in Intel® Integrated Performance Primitives Cryptography 2020 Update1. More details can be found in [DEPRECATION_NOTES.md](./DEPRECATION_NOTES.md). Please note that `ippsHash<GetSize/Init/Duplicate/Pack/Unpack/Update/GetTag/Final/HashMessage>` API still remain in the library.
- Removed support for SSSE3(`s8` for ia32 and `n8` for intel64) and AVX(`g9` for ia32 and `e9` for intel64) code-paths. Execution was moved to SSE3(`w7` for ia32 and `m7` for intel64) and SSE4.2(`p8` for ia32 and `y8` for intel64) respectively. There is still the possibility to use 1cpu headers and 1cpu libraries without breaking change for 1 year but some performance drops are expected.

## Intel(R) IPP Cryptography 2021.12.1
- Added `FIPS_CUSTOM_IPPCP_API_HEADER` build flag to support FIPS self-tests for a specific use case when Custom Library Tool is used with custom prefix for IPPCP API.

## Intel(R) IPP Cryptography 2021.12
- Added single-buffer implementation of Leighton-Micali Hash-Based Signatures(LMS) algorithm, verification part.
- Added support of Clang 16.0 compiler for Linux.
- Added examples of AES-GCM Encryption/Decryption usage.
- AES-GCM algorithm with Intel® Advanced Vector Extensions 2 (Intel® AVX2) vector extensions of Intel® AES New Instructions (Intel® AES-NI) was optimized.

## Intel(R) IPP Cryptography 2021.11
- Minimal supported BoringSSL version was increased to [45cf810d](https://github.com/google/boringssl/archive/45cf810dbdbd767f09f8cb0b0fcccd342c39041f.tar.gz) tag.

## Intel(R) IPP Cryptography 2021.10
- Added the verification part of eXtended Merkle Signature Scheme (XMSS) algorithm.
- Added FIPS-compliance mode for the library. More information can be found in the [Intel(R) IPP Cryptography FIPS Guide](./README_FIPS.md).

## Intel(R) IPP Cryptography 2021.9
- Added optimized RSA-2048 code for multi-buffer (8 buffers) Intel® AVX-512 implementation.
- Added Intel® Advanced Vector Extensions 2 (Intel® AVX2) vector extensions of Intel® AES New Instructions (Intel® AES-NI) optimization for AES-GCM algorithm.
- Changed the minimal supported OpenSSL version to 3.0.8 since 1.1.1 is not supported since September 2023.
- Raised the minimal CMake version to 3.18 since this is the minimal version that supports OpenSSL 3.0.8: https://cmake.org/cmake/help/latest/module/FindOpenSSL.html.

## Intel(R) IPP Cryptography 2021.8
- Crypto Multi-buffer library was extended with XTS mode of SM4 algorithm.

## Intel(R) IPP Cryptography 2021.7.1
- Added re-initialization API for AES-GCM context - ippsAES_GCMReinit. The use-case of this function is very specific, please, refer to the documentation for more details.

## Intel(R) IPP Cryptography 2021.7
- Mitigation for Frequency Throttling Side-Channel Attack ([Frequency Throttling Side Channel Software Guidance for Cryptography Implementations](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/frequency-throttling-side-channel-guidance.html)) was added for ECB, CMAC and GCM modes of AES (for more details refer to ippsAESSetupNoise, ippsAES_GCMSetupNoise and ippsAES_CMACSetupNoise).
- Crypto Multi-buffer library was extended with CCM and GCM modes of SM4 algorithm.
- In Crypto Multi-buffer library in-place mode of executing (when pa_out == pa_inp) was fixed for SM4 CBC and CFB modes.
- New API that updates pointer to IppsHashMethod context inside the IppsHashState_rmf state was added (please, refer to ippsHashStateMethodSet_ API).
- ippsHMAC_Pack(_rmf), ippsHMAC_Unpack(_rmf) APIs were fixed - context id is set up properly now during the packing-unpacking process.

## Intel(R) IPP Cryptography 2021.6
- EC cryptography functionality for the NIST curves p256r1, p384r1, p521r1 and SM2 curve was enabled with Intel® Advanced Vector Extensions 512 (Intel® AVX-512) IFMA instructions.
- EC cryptography functionality input parameters checking was improved by adding keys boundaries check.
- AES-GCM input parameters checking was improved by adding input text boundary check.
- An issue in AES-CTR Intel® Advanced Vector Extensions 512 (Intel® AVX-512) code path related to handling of last partial block was fixed.
- The ability to build Intel® IPP Cryptography library and Crypto Multi buffer library with Microsoft Visual C++ Compiler\* version 19.30 provided by Microsoft Visual Studio\* 2022 version 17.0 was added.

## Intel(R) IPP Cryptography 2021.5
- AES-GCM small packets processing was optimized for Intel® Advanced Vector Extensions 512 (Intel® AVX-512) code path.
- The ability to build Intel® IPP Cryptography library and Crypto Multi buffer library with GCC\* 10, GCC\* 11, Clang\* 9, Clang\* 12 and Intel® C++ Compiler Classic 2021.3 was added.
- The ability to build Crypto Multi buffer library with OpenSSL\* 3.0 was added.

## Intel(R) IPP Cryptography 2021.4
- Crypto Multi buffer library was extended with ECB, CBC, CTR, OFB and CFB modes of SM4 algorithm.
- Crypto Multi buffer library was extended with EC SM2 public key generation, ECDHE and ECDSA (Sign and Verify) algorithms.
- Crypto Multi buffer library extended with ECDSA Ed25519 verify algorithm.
- Crypto Multi buffer library extended with modular exponent algorithm.

## Intel(R) IPP Cryptography 2021.3
- Enabled ECDSA Ed25519sign crypto multi buffer API within Intel® IPP Cryptography for 3rd Generation Intel® Xeon® Processor Scalable and 10th Gen Intel® Core™ Processors.
- Enabled RSA single buffer 3k, 4k within Intel® IPP Cryptography for 3rd Generation Intel® Xeon® Processor Scalable and 10th Gen Intel® Core™ Processors.
- Fixed Intel® IPP Cryptography AES-GCM decryption incorrect tag issue while dispatching on processors supported with Intel® Advanced Vector Extensions 512 (Intel® AVX-512).

## Intel(R) IPP Cryptography 2021.2
- Crypto Multi buffer library was extended with ECDSA (Sign) and ECDHE for the NIST curves p521r1.
- Added ECDSA verify with new Instruction Set Architecture(ISA) for the NIST curve p384r1, p256r1 and p521r1.
- Added SM3 multi buffer with new Instruction Set Architecture(ISA).
- Added new Intel® IPP Cryptography pre-defined hash algorithm APIs ippsHashMethodGetSize and ippsHashMethodInit.
- RSA-2048 decryption (CRT) was enabled for Intel(R) Microarchitecture Code Named Ice Lake.
- Crypto Multi buffer library was extended with ECDSA (Sign) and ECDHE for the NIST curves p256r1 and p384r1.
- Fixed a build issue that affect build of the Intel(R) IPP Cryptography library with MSVC\* compiler on Windows\* OS.
- Duplicated APIs of HASH, HMAC, MGF, RSA, ECCP functionality were marked as deprecated. For more information see [Deprecation notes](./DEPRECATION_NOTES.md)
- Added examples demonstrating usage of SMS4-CBC encryption and decryption.

## Intel(R) IPP Cryptography 2020 Update 3
- Refactoring of Crypto Multi buffer library, added build and installation of crypto_mb dynamic library and CPU features detection.
- Added multi buffer implementation of AES-CFB optimized with Intel(R) AES New Instructions (Intel(R) AES-NI) and vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI) instruction sets.
- Fixed compatibility issue with x64 ABI (restored non-volatile registers after function call in Intel® Advanced Vector Extensions (Intel® AVX)/Intel® Advanced Vector Extensions 2 (Intel® AVX2) assembly code).
- Updated Intel IPP Custom Library Tool.

## Intel(R) IPP Cryptography 2020 Update 2
- AES-GCM algorithm was optimized for Intel(R) Microarchitecture Code Named Cascade Lake with Intel(R) AES New Instructions (Intel(R) AES-NI).
- Crypto Multi buffer library installation instructions update. The Readme file of Crypto Multi buffer Library was updated by information about possible installation fails in specific environment.
- Position Independent Execution (PIE) option was added to Crypto Multi buffer Library build scripts.
- AES-XTS optimization for Intel(R) Microarchitecture Code Named Ice Lake with vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI) was improved.
- SM4-ECB, SM4-CBC and SM4-CTR were enabled for Intel(R) Microarchitecture Code Named Ice Lake with Intel(R) Advanced Vector Extensions 512 (Intel(R) AVX-512) GFNI instructions.
- Added support of Clang 9.0 for Linux and Clang 11.0 for MacOS compilers.
- Added example of RSA Multi Buffer Encryption/Decryption usage.
- The library was enabled with  Intel® Control-Flow Enforcement Technology (Intel® CET) on Linux and Windows.
- Changed API of ippsGFpECSignDSA, ippsGFpECSignNR and ippsGFpECSignSM2 functions: const-ness requirement of private ephemeral keys is removed and now the ephemeral keys are cleaned up after signing.

## Intel(R) IPP Cryptography 2020 Update 1
- Added RSA IFMA Muti-buffer Library.
- Added RSA PSS multi buffer signature generation and verification.
- Added RSA PKCS#1 v1.5 multi buffer signature generation and verification.
- Removed Android support. Use Linux libraries instead.
- Fixed all build warnings for supported GCC\* and MSVC\* compilers.
- Assembler sources were migrated to NASM\* assembler.

## Intel(R) IPP Cryptography 2020
- Added RSA multi buffer encryption and decryption.
- Added Intel(R) IPP Cryptography library examples: AES-CTR, RSA-OAEP, RSA-PSS.
- Fixed code generation for kernel code model in Linux* Intel(R) 64 non-PIC builds.
- Fixes in Intel IPP Custom Library Tool.
- Added Microsoft\* Visual Studio\* 2019 build support.
- A dynamic dispatcher library and a set of CPU-optimized dynamic libraries were replaced by a single merged dynamic library with an internal dispatcher.
- Removed deprecated multi-threaded version of the library.
- Removed Supplemental Streaming SIMD Extensions 3 (SSSE3) support on macOS.

## Intel(R) IPP Cryptography 2019 Update 5
- 1024, 2048, 3072 and 4096 bit RSA were enabled with AVX512 IFMA instructions.
- AES-GCM was enabled with vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI).
- AES-XTS was enabled with vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI).
- Fixed GCC\* and MSVC\* builds of IA32 generic CPU code (pure C) with -DMERGED_BLD:BOOL=off option.
- Added single-CPU headers generation.
- Aligned structure of the build output directory across all supported operation systems.
- AES-CFB was enabled with vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI).
- ippsGFpECGetPointOctString and ippsGFpECSetPointOctString now support elliptic curves over both prime and extended finite fields.
- Added the ability to build the Intel(R) IPP Cryptography library with GCC\* 8.2.

## Intel(R) IPP Cryptography 2019 Update 4
- AES-ECB, AES-CBC and AES-CTR were enabled with vector extensions of Intel(R) AES New Instructions (Intel(R) AES-NI).
- Improved optimization of Intel(R) AES-NI based CMAC.
- Added the ippsGFpGetInfo function, which returns information about a finite field.
- Added the ippsHashGetInfo_rmf function, which returns information about a hash algorithm.
- Fixed selection of CPU-specific code in dynamic/shared libraries.

## Intel(R) IPP Cryptography 2019 Update 3
- Added the ability to build the Intel(R) IPP Cryptography library with the Intel(R) C++ Compiler 19.
- Added Intel IPP Custom Library Tool based on Python.

## Intel(R) IPP Cryptography 2019 Update 1
- Added the ability to build the Intel(R) IPP Cryptography library with the Microsoft\* Visual C++ Compiler 2017.
- Added the new SM2 encryption scheme.
- Changed the range of the message being signed or verified by EC and DLP.
- Deprecated the ARCFour functionality.
- Fixed a potential security problem in the signing functions over elliptic curves.
- Fixed a potential security problem in the key expansion function for AES Encryption.
- Fixed a potential security problem in the AES-CTR cipher functions.
- Fixed a potential security problem in the AES-GCM cipher functions.
- Fixed a potential security problem in the DLP signing and key generation functions.
- Fixed minor issues with DLP functions.
- Fixed some of the compilation warnings observed when building the static dispatcher on Windows\* OS.

------------------------------------------------------------------------
Intel is a trademark of Intel Corporation or its subsidiaries in the U.S. and/or other countries.
\* Other names and brands may be claimed as the property of others.
