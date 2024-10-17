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
# Enable Intel® Control-Flow Enforcement Technology (Intel® CET) protection
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fcf-protection=full")

# Stack-based Buffer Overrun Detection
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fstack-protector")
# Position Independent Execution (PIE)
set(CMAKE_C_FLAGS_SECURITY "${CMAKE_C_FLAGS_SECURITY} -fpic -fPIC")
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
set(CMAKE_C_FLAGS " -falign-functions=32")

# -ffreestanding flag removed for clang because it causes compilation error in combination with -D_FORTIFY_SOURCE=2
# and limits.h and stdlib.h headers because of wrong value of MB_LEN_MAX defined in limits.h and checked in stdlib.h
# This issue is reprodusable with clang9. Flag is not removed for other compilers to prevent other possible issues. 

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

# Build with sanitizers
# FIXME: so far it can be enabled from the IPPCP build only. Change it once crypto_mb build is separated.
if(SANITIZERS)
  include(${CMAKE_SOURCE_DIR}/sources/cmake/linux/SanitizersSettings.cmake)
  set_sanitizers_flags("C")
  set_sanitizers_flags("CXX")
endif(SANITIZERS)
