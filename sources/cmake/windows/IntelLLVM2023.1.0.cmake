#===============================================================================
# Copyright 2024 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#===============================================================================

#
# Intel® Cryptography Primitives Library
#

# linker
set(LINK_FLAG_STATIC_WINDOWS "/ignore:4221") # ignore warnings about empty obj files
# Suppresses the display of the copyright banner when the compiler starts up and display of informational messages during compiling.
set(LINK_FLAG_DYNAMIC_WINDOWS "/nologo")
# Displays information about modules that are incompatible with safe structured exception handling when /SAFESEH isn't specified.
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /VERBOSE:SAFESEH")
# Disable incremental linking
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /INCREMENTAL:NO")
# The /NODEFAULTLIB option tells the linker to remove one or more default libraries from the list of libraries it searches when resolving external references.
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /NODEFAULTLIB")
# Indicates that an executable was tested to be compatible with the Windows Data Execution Prevention feature.
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /NXCOMPAT")
# Specifies whether to generate an executable image that can be randomly rebased at load time.
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /DYNAMICBASE")
# Enable Intel® Control-Flow Enforcement Technology (Intel® CET) protection
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /CETCOMPAT")
# Linker option to mitigate DLL hijacking vulnerability - removes CWD from the DLL search order
set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /DEPENDENTLOADFLAG:0x2000")

if(${ARCH} MATCHES "ia32")
  # When /SAFESEH is specified, the linker will only produce an image if it can also produce a table of the image's safe exception handlers.
  set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /SAFESEH")
else()
  # The /LARGEADDRESSAWARE option tells the linker that the application can handle addresses larger than 2 gigabytes.
  set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /LARGEADDRESSAWARE")
  # This option modifies the header of an executable image, a .dll file or .exe file, to indicate whether ASLR with 64-bit addresses is supported.
  set(LINK_FLAG_DYNAMIC_WINDOWS "${LINK_FLAG_DYNAMIC_WINDOWS} /HIGHENTROPYVA")
endif(${ARCH} MATCHES "ia32")

# Link to universal C runtime and MSVC runtime. Used in dlls.
set(LINK_LIB_STATIC_RELEASE libcmt libucrt libvcruntime)
set(LINK_LIB_STATIC_DEBUG libcmtd libucrtd libvcruntime)

# compiler
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBRARY_DEFINES}")

# Suppresses the display of the copyright banner when the compiler starts up and display of informational messages during compiling.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /nologo")
# Warning level = 4
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 -Wall -Wformat -Wformat-security -Werror=format-security")
# Changes all warnings to errors.
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
# Detects some buffer overruns that overwrite a function's return address, exception handler address, or certain types of parameters.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS")
# Controls how the members of a structure are packed into memory and specifies the same packing for all structures in a module.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Zp16")
# Allows the compiler to package individual functions in the form of packaged functions. Smaller resulting size.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Gy")
# C std
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qstd=c99")
# Enable Intel® Control-Flow Enforcement Technology (Intel® CET) protection
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcf-protection:full")
# Suppress some warnings
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Wno-null-pointer-arithmetic /Wno-unused-function /Wno-static-in-inline /Qno-intel-lib")

# Causes the application to use the multithread, static version of the run-time library (debug version).
set(CMAKE_C_FLAGS_DEBUG "/MTd")
# The /Zi option produces a separate PDB file that contains all the symbolic debugging information for use with the debugger.
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi")
# Turns off all optimizations in the program and speeds compilation.
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od")
# Debug macro
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /DDEBUG")

# Causes the application to use the multithread, static version of the run-time library.
set(CMAKE_C_FLAGS_RELEASE "/MT")
# Omits the default C runtime library name from the .obj file.
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /Zl")
# "Maximize Speed". Selects a predefined set of options that affect the size and speed of generated code.
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O3")
# No-debug macro
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /DNDEBUG")

set(w7_opt "${w7_opt} /arch:SSE2")
set(s8_opt "${s8_opt} /arch:SSSE3")
set(p8_opt "${p8_opt} /arch:SSE4.2 -maes -mpclmul -msha")
set(g9_opt "${g9_opt} /arch:AVX -maes -mpclmul -msha -mrdrnd -mrdseed")
set(h9_opt "${h9_opt} /arch:AVX2 -maes -mpclmul -msha -mrdrnd -mrdseed -mvaes -mvpclmulqdq")
set(m7_opt "${m7_opt} /arch:SSE3")
set(n8_opt "${n8_opt} /arch:SSSE3")
set(y8_opt "${y8_opt} /arch:SSE4.2 -maes -mpclmul -msha")
set(e9_opt "${e9_opt} /arch:AVX -maes -mpclmul -msha -mrdrnd -mrdseed")
set(l9_opt "${l9_opt} /arch:CORE-AVX2 -maes -mpclmul -msha -mrdrnd -mrdseed -mvaes -mvpclmulqdq")
set(n0_opt "${n0_opt} /arch:CORE-AVX2 -maes -mavx512f -mavx512cd -mavx512pf -mavx512er -mpclmul -msha -mrdrnd -mrdseed")
set(k0_opt "${k0_opt} /arch:SKYLAKE-AVX512 -maes -mavx512f -mavx512cd -mavx512vl -mavx512bw -mavx512dq -mpclmul -mrdrnd -mrdseed -madx")
set(k1_opt "${k1_opt} /arch:ICELAKE-SERVER -maes -mavx512f -mavx512cd -mavx512vl -mavx512bw -mavx512dq -mavx512ifma -mpclmul -msha -mrdrnd -mrdseed -madx -mgfni -mvaes -mvpclmulqdq -mavx512vbmi -mavx512vbmi2")
