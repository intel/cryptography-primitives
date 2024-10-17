#=========================================================================
# Copyright (C) 2019 Intel Corporation
#
# Licensed under the Apache License,  Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law  or agreed  to  in  writing,  software
# distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the  specific  language  governing  permissions  and
# limitations under the License.
#=========================================================================

# Security Linker flags

set(LINK_FLAG_SECURITY "")
# Data relocation and protection (RELRO)
set(LINK_FLAG_SECURITY "${LINK_FLAG_SECURITY} -Wl,-z,relro -Wl,-z,now")
# Stack execution protection
set(LINK_FLAG_SECURITY "${LINK_FLAG_SECURITY} -Wl,-z,noexecstack")

# Security Compiler flags

set(CMAKE_C_FLAGS_SECURITY "")
# Format string vulnerabilities
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -Wformat -Wformat-security -Werror=format-security")

# Stack-based Buffer Overrun Detection
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fstack-protector")
# Stack-based Buffer Overrun Detection
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fstack-clash-protection")
# Position Independent Execution (PIE)
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fpic -fPIC")
# Enable Intel® Control-Flow Enforcement Technology (Intel® CET) protection
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fcf-protection=full")
# Enables important warning and error messages relevant to security during compilation
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -Wall")
# Warnings=errors
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -Werror")

# Linker flags

# Create shared library
set(LINK_FLAGS_DYNAMIC " -Wl,-shared")
# Add export files
set(DLL_EXPORT_DIR "${CRYPTO_MB_SOURCES_DIR}/cmake/dll_export/")
set(LINK_FLAGS_DYNAMIC "${LINK_FLAGS_DYNAMIC} ${DLL_EXPORT_DIR}/crypto_mb.linux.lib-export")
if (MBX_FIPS_MODE)
  set(LINK_FLAGS_DYNAMIC "${LINK_FLAGS_DYNAMIC} ${DLL_EXPORT_DIR}/fips_selftests.linux.lib-export")
endif()
# Compiler flags

# Tells the compiler to align functions and loops
set(CMAKE_C_FLAGS " -falign-functions=32 -falign-loops=32")
# Ensures that compilation takes place in a freestanding environment
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffreestanding")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

# Tells the compiler to conform to a specific language standard.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

# Suppress warnings from casts from a pointer to an integer type of a different size
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-to-int-cast")

# Optimization level = 3, no-debug definition (turns off asserts)
set(CMAKE_C_FLAGS_RELEASE " -O3 -DNDEBUG")
if(NOT DEFINED NO_FORTIFY_SOURCE)
  # Security flag that adds compile-time and run-time checks
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

# Optimisation dependent flags

# Add Intel® AVX-IFMA specific compiler options only for compilers that support them
if(MBX_CC_AVXIFMA_SUPPORT)
    set(l9_opt "-march=sierraforest -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -msha -mrdrnd -mrdseed -mgfni -mavxifma")
else()
    set(l9_opt "-mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -msha -mrdrnd -mrdseed -mgfni")
endif()
set(k1_opt "-march=icelake-server -maes -mavx512f -mavx512cd -mavx512vl -mavx512bw -mavx512dq -mavx512ifma -mpclmul -msha -mrdrnd -mrdseed -madx -mgfni -mvaes -mvpclmulqdq -mavx512vbmi -mavx512vbmi2")
