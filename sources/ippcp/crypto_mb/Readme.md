# Crypto Multi-buffer Library

Currently, the library provides optimized version of the following algorithms:
1. RSA, ECDSA, ECDH, x25519, SM2 multi-buffer algorithms based on Intel® Advanced Vector Extensions 512 (Intel® AVX-512) integer fused multiply-add (IFMA) operations. This CPU feature is introduced with Intel® Microarchitecture Code Named Ice Lake.
2. SM4 based on Intel(R) Advanced Vector Extensions 512 (Intel(R) AVX-512) GFNI instructions.
3. SM3 based on Intel® Advanced Vector Extensions 512 (Intel® AVX-512) instructions.

## Multiple Buffers Processing Overview

Some of the cryptography algorithms cannot be parallelized due to their specificity. For example, the RSA algorithm consists of big-number (multi-digit) arithmetic: multi-precision modular multiplications and squaring operations.

Digits of multi-digit numbers are dependent because of carry propagation during arithmetic operations. Therefore, single RSA computation based on general purpose mul/adc instructions is not efficient.

The way to get high-performance implementations of such cryptographic algorithms is a parallel processing using *single instruction, multiple data* (SIMD) architecture. The usage model implies presence of several independent and homogeneous (encryption or decryption) requests for RSA operations, using of SIMD leads to performance improvement.

Multi-buffer processing collects up to eight RSA operations. Each request is computed independently from the others, so it is possible to process several packets at the same time.

This library consists of highly-optimized kernels taking advantage of Intel’s multi-buffer processing and Intel® AVX-512 instruction set.

## Software Requirements

### Common

- CMake\* 3.10 or higher
- The Netwide Assembler (NASM) 2.14\*
- OpenSSL\* 3.0.8 or higher

### Linux* OS

- Intel® C++ Compiler Classic 2021.9 for Linux\* OS
- GCC 8.5
- GCC 11.4
- Clang 9.0
- Clang 12.0
- Clang 16.0
- GNU binutils 2.32

### Windows* OS

- Intel® C++ Compiler Classic 2021.9 for Windows\* OS
- Microsoft Visual C++ Compiler\* version 19.24 provided by Microsoft Visual Studio\* 2019 version 16.4
- Microsoft Visual C++ Compiler\* version 19.30 provided by Microsoft Visual Studio\* 2022 version 17.0
> **NOTE:** [CMake\*](https://cmake.org/download) 3.21 or higher is required to build using Microsoft Visual Studio\* 2022.

### macOS*

- Intel® C++ Compiler Classic 2021.9 for macOS\*

## Installation

You can install the Crypto Multi-buffer library in two different ways:
1. Installation to the default directories.
   > **Note**: To run this installation type, you need to have appropriate permissions to write to the installation directory.

   Default locations (default values of `CMAKE_INSTALL_PREFIX`):
   - Unix:  /usr/local
   - Windows: C:\Program Files\crypto_mb or C:\Program Files (x86)\crypto_mb

   To begin installation, run the command below in the project folder that was specified with `-B`:
   ``` bash
   make install
   ```
   > **Note**: Installation requires write permissions to the build directory to create the installation manifest file. If it is not feasible in your setup, copy the build to the local directory and change permissions accordingly.

2. Installation to your own directory.
   If you want to install the library not by default paths, specify the `CMAKE_INSTALL_PREFIX` variable at the configuration step, for example:
   ``` bash
   cmake . -B"../build" -DCMAKE_INSTALL_PREFIX=path/to/libcrypto_mb/installation
   ```

You can find the installed files in:

``` bash

├── ${CMAKE_INSTALL_PREFIX}
    ├── include
    |    └── crypto_mb
    |        ├── cpu_features.h
    │        ├── defs.h
    │        ├── ec_nistp256.h
    │        ├── ec_nistp384.h
    │        ├── ec_nistp521.h
    │        ├── ec_sm2.h
    │        ├── ed25519.h
    │        ├── exp.h
    │        ├── fips_cert.h
    │        ├── rsa.h
    │        ├── sm3.h
    │        ├── sm4_ccm.h
    │        ├── sm4_gcm.h
    │        ├── sm4.h
    │        ├── status.h
    |        ├── version.h
    │        └── x25519.h
    └── lib
        └── libcrypto_mb.so
```
> **Note**: This project uses the default `RPATH` settings:
>
> CMake is linking the executables and shared libraries with full `RPATH` to all used
> libraries in the build tree. When installing, CMake will clear the `RPATH` of these
> targets so they are installed with an empty `RPATH`.
> In this case to resolve the Crypto Multi-buffer Library dependency on OpenSSL it is
> necessary to update `LD_LIBRARY_PATH` with the path to the target OpenSSL library.


## How to Build

1. Clone the repository from GitHub\* as follows:

   ``` bash
   git clone --recursive https://github.com/intel/ipp-crypto
   ```
   and navigate to the `sources/ippcp/crypto_mb` folder.
2. Set the environment variables for one of the supported C/C++ compilers.

   *Example for Intel® Compiler:*

   ```bash
   source /opt/intel/bin/compilervars.sh intel64
   ```

   For details, refer to the [Intel® C++ Compiler Developer Guide and Reference](https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/current/specifying-the-location-of-compiler-components.html)

3. Run CMake on the command line. Use `-B` to specify path to the resulting project.
4. Go to the project folder that was specified with `-B` and run `make` to build the library  (`crypto_mb` target).

### Building with Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography)

The Crypto Multi-buffer library will be built automatically with Intel® IPP Cryptography if optimization for Intel® Microarchitecture Code Named Ice Lake is available. For more information see [Intel IPP Cryptography Build Instructions](../../../BUILD.md)

### CMake Build Options

- Use `OPENSSL_INCLUDE_DIR`,     `OPENSSL_LIBRARIES` and `OPENSSL_ROOT_DIR` to   override path to OpenSSL\*:

   ``` bash
   cmake . -B"../build"
   -DOPENSSL_INCLUDE_DIR=/path/to/openssl/include
   -DOPENSSL_LIBRARIES=/path/to/openssl/lib
   -DOPENSSL_ROOT_DIR=/path/to/openssl/installation/dir
   ```

- Set `-DOPENSSL_USE_STATIC_LIBS=TRUE` if static OpenSSL libraries are preferred.
