# How to Build Intel® Cryptography Primitives Library <!-- omit in toc -->

- [Software Requirements](#software-requirements)
  - [Common tools](#common-tools)
  - [Linux\* OS](#linux-os)
  - [Windows\* OS](#windows-os)
- [Building Intel® Cryptography Primitives Library on Linux\* OS](#building-intel-cryptography-primitives-library-on-linux-os)
- [Building Intel® Cryptography Primitives Library on Windows\* OS](#building-intel-cryptography-primitives-library-on-windows-os)
- [CMake Build Options](#cmake-build-options)
  - [Common for all operating systems](#common-for-all-operating-systems)
  - [Windows\* OS](#windows-os-1)
  - [Linux\* OS](#linux-os-1)
- [CMake Commands FAQ](#cmake-commands-faq)
  - [How to build a 64-bit generic library without any CPU-specific optimizations?](#how-to-build-a-64-bit-generic-library-without-any-cpu-specific-optimizations)
  - [How to build two libraries with optimizations for Intel® Advanced Vector Extensions 2 and Intel® Advanced Vector Extensions 512 instruction sets?](#how-to-build-two-libraries-with-optimizations-for-intel-advanced-vector-extensions-2-and-intel-advanced-vector-extensions-512-instruction-sets)
  - [How to build a library to work in a kernel space?](#how-to-build-a-library-to-work-in-a-kernel-space)
  - [How to specify path to OpenSSL\*](#how-to-specify-path-to-openssl)
  - [How to run Intel® Cryptography Primitives Library with clang-tidy?](#how-to-run-intel-cryptography-primitives-library-with-clang-tidy)
- [Incorporating Intel® Cryptography Primitives Library sources into custom build system](#incorporating-intel-cryptography-primitives-library-sources-into-custom-build-system)


## Software Requirements
> **NOTE:** The tools configurations specified below are tested by Intel or known to work; other configurations may or may not work and are not recommended.

### Common tools
- [CMake\*](https://cmake.org/download) 3.18 or higher
- Python 3.12.0
- The Netwide Assembler (NASM\*) 3.01
- OpenSSL\* 3.5.5 or higher **OR** BoringSSL* [0.20250114.0](https://github.com/google/boringssl/releases/tag/0.20250114.0) **OR** Tongsuo* 8.3.3

### Linux* OS
- [Common tools](#common-tools)
- Intel® oneAPI DPC++/C++ Compiler 2026.0.0 for Linux\* OS
- GCC 8.5
- GCC 11.5
- GCC 14.3
- GCC 15.2
- Clang 16.0
- Clang 18.1
- Clang 21.1
- GNU binutils 2.32
> **NOTE:** [CMake\*](https://cmake.org/download) 3.22 or higher is required to build using Intel® oneAPI DPC++/C++ Compiler.

### Windows* OS
- [Common tools](#common-tools)
- Intel® oneAPI DPC++/C++ Compiler 2026.0.0 for Windows\* OS
- Microsoft Visual C++ Compiler\* version 19.44 provided by Microsoft Visual Studio\* 2022 version 17.14
- Microsoft Visual C++ Compiler\* version 19.50 provided by Microsoft Visual Studio\* 2026 version 18.3
> **NOTE:** [CMake\*](https://cmake.org/download) 3.21 or higher is required to build using Microsoft Visual Studio\* 2022.

> **NOTE:** [CMake\*](https://cmake.org/download) 4.2 or higher is required to build using Microsoft Visual Studio\* 2026.

> **NOTE:** [CMake\*](https://cmake.org/download) 3.22 or higher is required to build using Intel® oneAPI DPC++/C++ Compiler.

## Building Intel® Cryptography Primitives Library on Linux\* OS

The software was validated on:

- Red Hat\* Enterprise Linux\* 8
> **NOTE:** Support of Red Hat\* Enterprise Linux\* 8 was deprecated and will be removed in the future. Testing will be migrated to Red Hat\* Enterprise Linux\* 9.

> **NOTE:** Additionally, the k1 code path of the multi-buffer library is validated on the FreeBSD operating system with the GNU 13.2 compiler.

> **NOTE:** [CMake\*](https://cmake.org/download) 3.22 or higher is required to build using Intel® oneAPI DPC++/C++ Compiler.

To build the Intel® Cryptography Primitives Library on Linux\* OS, complete the following steps:
1. Clone the source code from GitHub\* as follows:

    ``` bash
    git clone --recursive https://github.com/intel/cryptography-primitives
    ```

2. Set the environment for one of the supported C/C++ compilers.

   *example for Intel® oneAPI DPC++/C++ Compiler:*

    ```bash
    source /opt/intel/oneapi/setvars.sh intel64
    ```

    For details, refer to the [Intel® oneAPI DPC++/C++ Compiler Developer Guide and Reference](https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/current/specifying-the-location-of-compiler-components.html).

3. Run CMake\* in the command line.

    *Examples*:

    for Intel® oneAPI DPC++/C++ Compiler:

    ``` bash
    CC=icx CXX=icpx cmake CMakeLists.txt -B_build -DARCH=intel64
    ```

    For GCC:

    ``` bash
    CC=gcc CXX=g++ cmake CMakeLists.txt -B_build -DARCH=intel64
    ```

    For the complete list of supported CMake options, refer to the [CMake Build Options](#cmake-build-options) section.

4. Navigate to the build folder specified in the CMake command line and start the build:

    ```bash
    cd _build
    make all
    ```

    You can find the built libraries in the `<build_dir>/.build/<RELEASE|DEBUG>/lib` directory.

## Building Intel® Cryptography Primitives Library on Windows\* OS

The software was validated on:

- Windows Server\* 2022

To build the Intel® Cryptography Primitives Library on Windows* OS, complete the following steps:

1. Clone the source code from GitHub\* as follows:

    ``` bash
    git clone --recursive https://github.com/intel/cryptography-primitives
    ```

2. Set the environment variables for one of the supported C/C++ compilers.

    For Intel® oneAPI DPC++/C++ Compiler instructions, refer to the [Intel® oneAPI DPC++/C++ Compiler Developer Guide and Reference](https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/current/specifying-the-location-of-compiler-components.html).
    For MSVC* Compiler, refer to [Use the MSVC toolset from the command line](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-160).

3. Run CMake\* in the command line.

    *Examples*:

    For Intel® oneAPI DPC++/C++ Compiler and Visual Studio\* 2022:

    ``` bash
    cmake CMakeLists.txt -B_build -G"Visual Studio 17 2022" -T"Intel C++ Compiler 2024" -Ax64
    ```

    For MSVC\* Compiler and Visual Studio\* 2022:

    ``` bash
    cmake CMakeLists.txt -B_build -G"Visual Studio 17 2022" -Ax64
    ```

    For the complete list of supported CMake options, please refer to the [CMake Build Options](#cmake-build-options) section.

4. Navigate to the build folder, specified in the CMake command line and start build either from Visual Studio\* or in the command line.

    *Build from command line:*

    ```bash
    cmake --build . --parallel 4 --target ALL_BUILD --config Release
    ```

    *Build from Visual Studio\*:*
    Open the Microsoft Visual Studio\* solution `Intel(R) IPP Crypto.sln`, choose project (build target) from the Solution Explorer and run the build.

## CMake Build Options

### Common for all operating systems

- `-B<build-dir>` - defines the build directory. This is the directory where CMake puts the generated Microsoft Visual Studio\* solution or makefiles.

- `-DARCH=<ia32|intel64>` - on Linux* OS defines the target architecture for the build of the Intel® Cryptography Primitives Library.
    > **NOTE:** On Windows* OS, use `-G`/`-A`  instead. See the description of these options [below](#windows-os-1).

    > **NOTE:** Due to the significant shift in the industry towards 64-bit architecture, the support of 32-bit libraries is deprecated in the Intel® Integrated Performance Primitives Cryptography 2021.9 release and targeted to be removed after one year deprecation notice period.

- `-DMERGED_BLD:BOOL=<on|off>` - optional. Defines the configuration of the Intel® Cryptography Primitives Library to build:

  - `-DMERGED_BLD:BOOL=on`: default configuration. It includes the following steps:
    - Build of a dispatched static library with all available optimizations
    - Build of a dispatched dynamic library with all available optimizations
    - Generation of the single-CPU headers (for details, refer to [this](./OVERVIEW.md) section)

  - `-DMERGED_BLD:BOOL=off`: build of one static library per optimization; build of one dynamic library per optimization.

- `-DPLATFORM_LIST="<platform list>"` - optional, works only if `-DMERGED_BLD:BOOL=off` is set. Sets target platforms for the code to be compiled. See the supported platforms list [here](./OVERVIEW.md).

    - Example for Linux\* OS and the IA-32 architecture:
        `-DPLATFORM_LIST="p8;h9"`

    - Example for Linux\* OS and the Intel® 64 architecture:
        `-DPLATFORM_LIST="y8;l9;k0;k1;d1"`
- `-DMBX_PLATFORM_LIST="<platform list>"` - optional, works only if `-DMERGED_BLD:BOOL=off` is set. Sets target platforms for the code to be compiled for [Crypto Multi Buffer library](./sources/ippcp/crypto_mb/Readme.md). Please, refer to [Crypto Multi Buffer library target platforms list](./sources/ippcp/crypto_mb/Readme.md/#target-optimization-codes-in-function-names) to check the supported platforms.
    - Example:
        `-DMBX_PLATFORM_LIST="k1;l9"`
- `-DNO_CRYPTO_MB:BOOL=TRUE` - optional, turns off the build of [Crypto Multi Buffer library](./sources/ippcp/crypto_mb/Readme.md) and, as a consequence, removes all dependencies on OpenSSL library.
- `-DTONGSUO:BOOL=on`, `-DBORINGSSL:BOOL=on` - required only if forks of OpenSSL library are used to resolve OpenSSL dependencies - Tongsuo and BoringSSL respectively. These flags make sense when [Crypto Multi Buffer library](./sources/ippcp/crypto_mb/Readme.md) is built.
> **NOTE:** -DBABASSL:BOOL=on flag is deprecated and targeted to be removed in the future releases. Please use -DTONGSUO:BOOL=on instead.\*.
- `-DIPPCP_CUSTOM_BUILD="<CPU features list>"` - optional, works only if `-DMERGED_BLD:BOOL=off` is set, i.e. only for 1CPU libraries. Enables the CPU feature dispatching mask at compile-time based on the provided list.

   - Currently supported by the library custom features dispatching:
        1. Intel® Advanced Encryption Standard New Instructions (Intel® AES-NI) code-path enabling: `IPPCP_AES_ON;IPPCP_CLMUL_ON`
        2. Intel® Advanced Vector Extensions 512 (Intel® AVX-512) / Intel® Advanced Vector Extensions 2 (Intel® AVX2) vector extensions of Intel® AES New Instructions (Intel® AES-NI) code-paths enabling: `IPPCP_VAES_ON;IPPCP_VCLMUL_ON`.
    - Example:
        `-DIPPCP_CUSTOM_BUILD="IPPCP_AES_ON;IPPCP_CLMUL_ON"` - this combination enables Intel® AES-NI in all 1CPU libraries, which contains this code path.
    - Example of using a combination of CPU features:
        `-DIPPCP_CUSTOM_BUILD="IPPCP_AES_ON;IPPCP_CLMUL_ON;IPPCP_VAES_ON;IPPCP_VCLMUL_ON"` - in this combination the highest available feature in each 1CPU library will be enabled (e.g. for `"y8"` it’s Intel® AES-NI, for `"l9"` it's Intel® AVX2 VAES, and for `"k1"` - Intel® AVX-512 VAES)
- `-DIPPCP_FIPS_MODE:BOOL=<on|off>` - optional. Regulates the build of FIPS-compliant Intel® Cryptography Primitives Library.

  - `-DIPPCP_FIPS_MODE:BOOL=on`: enables all FIPS-compliance changes in Intel® Cryptography Primitives Library.
  - `-DIPPCP_FIPS_MODE:BOOL=off`: default configuration. Intel® Cryptography Primitives Library build with such option is not FIPS-compliant.
- `-DIPPCP_SELFTEST_USE_MALLOC:BOOL=<on|off>` - optional. Enables internal memory allocation and release using `malloc()` and `free()` functions inside Intel® Cryptography Primitives Library selftests.
  - `-DIPPCP_SELFTEST_USE_MALLOC:BOOL=on`: memory management is held by FIPS selftests, all processing APIs should be called with input parameters equal to `NULL`.
  - `-DIPPCP_SELFTEST_USE_MALLOC:BOOL=off`: default configuration. Memory management is held by customer's application, all processing APIs should be called with work buffers of the valid length.
- `-DMBX_FIPS_MODE:BOOL=<on|off>` - optional. Regulates the build of FIPS-compliant  Crypto Multi-buffer Library.

  - `-DMBX_FIPS_MODE:BOOL=on`: enables all FIPS-compliance changes in Crypto Multi-buffer Library.
  - `-DMBX_FIPS_MODE:BOOL=off`: default configuration. Crypto Multi-buffer Library build with such option is not FIPS-compliant.

- `-DFIPS_CUSTOM_IPPCP_API_HEADER=<redefined_ippcp_api.h>` - optional flag which allows to use FIPS self-tests with IPPCP API with a different prefix to support capabilities of the custom dispatcher generated by Custom Library Tool (Please, note that it is only intended for a very specific use case of [Custom Library](./OVERVIEW.md/#static-library-with-custom-functionality)).The header should contain redefinitions of IPPCP public API, e.g. `#define ippcpGetLibVersion custom_prefix_ippcpGetLibVersion`. The flag is applicable only when IPPCP FIPS mode is enabled (`-DIPPCP_FIPS_MODE:BOOL=on`).

### Windows\* OS

- `-G"<tool-chain-generator>"` - defines the native build system CMake will generate from the input files.
  Refer to CMake [documentation](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#visual-studio-generators) for the Visual Studio\* generators options.

- `-A<x64|Win32>` - for Visual Studio\* 2022+, defines the target architecture for the build of the Intel® Cryptography Primitives Library.

- `-T<Compiler>` - defines the compiler for building.
  For example, to use Intel® oneAPI DPC++/C++ Compiler, specify `-T"Intel C++ Compiler 2024"`.

> **NOTE:** Refer to CMake [documentation](https://cmake.org/cmake/help/latest/manual/ccmake.1.html) for more information on these options.

### Linux\* OS

- `-DNONPIC_LIB:BOOL=<off|on>` - optional. Defines whether the built library is position-dependent or not.

  - `-DNONPIC_LIB:BOOL=off:` default. Position-independent code.

  - `-DNONPIC_LIB:BOOL=on:` position-dependent code.

## CMake Commands FAQ

### How to build a 64-bit generic library without any CPU-specific optimizations?

`cmake CMakeLists.txt -B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DPLATFORM_LIST=mx`

### How to build two libraries with optimizations for Intel® Advanced Vector Extensions 2 and Intel® Advanced Vector Extensions 512 instruction sets?

`cmake CMakeLists.txt -B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DPLATFORM_LIST="l9;k0"`

### How to build a library to work in a kernel space?

`cmake CMakeLists.txt -B_build -DARCH=intel64 -DNONPIC_LIB:BOOL=on`

### How to specify path to OpenSSL\*

`cmake CMakeLists.txt -B_build -DARCH=intel64 -DOPENSSL_INCLUDE_DIR=/path/to/openssl/include -DOPENSSL_LIBRARIES=/path/to/openssl/lib -DOPENSSL_ROOT_DIR=/path/to/openssl`

### How to run Intel® Cryptography Primitives Library with clang-tidy?

`CC=clang CXX=clang++ cmake CMakeLists.txt -B_build -DARCH=intel64 -DCRYPTO_USE_CLANG_TIDY:BOOL=on`

## Incorporating Intel® Cryptography Primitives Library sources into custom build system

You can include Intel® Cryptography Primitives Library sources into some arbitrary project's CMake build system and build them with it.

Here is the minimal working example:

``` bash
cmake_minimum_required(VERSION 3.18)

project("test_proj")

# `crypto` is the repository root folder of Intel® Cryptography Primitives Library
add_subdirectory(crypto)
include_directories(crypto/include)

# 'main.cpp' is some arbitrary project's source file
add_executable("test_proj" main.cpp)
# `ippcp_s` is the target name of static library in the Intel® Cryptography Primitives Library build system.
# This static library will be built automatically, when you build your project.
target_link_libraries("test_proj" "ippcp_s")
```

Also you can use the CMake module to find the Intel® Cryptography Primitives Library installed on the system. The module location is `examples/FindIPPCrypto.cmake` and here is the example of its usage:

``` bash
find_package(IPPCrypto REQUIRED MODULE)

if (NOT IPPCRYPTO_FOUND)
   message(FATAL_ERROR "No Intel® Cryptography Primitives Library found on the system.")
endif()

# If Intel® Cryptography Primitives Library is found, the following variables will be defined:
#     `IPPCRYPTO_LIBRARIES` - static library name
#     `IPPCRYPTO_INCLUDE_DIRS` - path to Intel® Cryptography Primitives Library headers
#     `IPPCRYPTO_ROOT_DIR` - library root dir (a folder with 'include' and 'lib' directories)
```
