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

cmake_minimum_required(VERSION 3.18)

project("crypto_mb" C)

include("${CMAKE_CURRENT_SOURCE_DIR}/src/cmake/crypto_mb-utils.cmake")
mbx_getlibversion("${CMAKE_CURRENT_SOURCE_DIR}/include/crypto_mb/version.h")

if ((NOT DEFINED MBX_VER_MAJOR) OR
    (NOT DEFINED MBX_VER_MINOR) OR
    (NOT DEFINED MBX_VER_PATCH)   OR
    (NOT DEFINED MBX_INTERFACE_VERSION_MAJOR) OR
    (NOT DEFINED MBX_INTERFACE_VERSION_MINOR))
    message(WARNING "Cannot parse version from crypto_mb/version.h file. The project might be corrupted.")
endif()

set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)
if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message(STATUS "CMAKE_BUILD_TYPE is not set to Debug explicitly, defaulting to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if(NOT DEFINED MB_STANDALONE)
  set(MB_STANDALONE true)
endif()

set(CRYPTO_MB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CRYPTO_MB_SOURCES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

set(MBX_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CRYPTO_MB_DISPATCHER_DIR "${MBX_DIR}/dispatcher")

set(MB_DYN_LIB_TARGET    "crypto_mb")   # Dynamic library
set(MB_STATIC_LIB_TARGET "crypto_mb_s") # Static library

# Define public headers
file(GLOB MB_PUBLIC_HEADERS "${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/*.h*")
# remove fips_cert.h header if fips-mode is not chosen
if(NOT DEFINED MBX_FIPS_MODE)
    list(REMOVE_ITEM MB_PUBLIC_HEADERS "${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/fips_cert.h")
endif()

# Platform-specific definitions
set(l9_def "_L9" "SIMD_LEN=256")
set(k1_def "_K1" "USE_AMS_5x" "SIMD_LEN=512")

# Check MERGED_BLD flag for the standalone build case (otherwise it is set in the parent project)
if(MB_STANDALONE)
  if("${MERGED_BLD}" STREQUAL "") # MERGED_BLD is on by default
    set(MERGED_BLD ON)
  endif()
  if(MERGED_BLD) # MERGED_BLD is on by default or by user settings
    set(MBX_MERGED_BLD ON)
    message (STATUS "MERGED_BLD ............................ on")
  else()
    message (STATUS "MERGED_BLD ............................ off")
  endif()
endif()

# Proper dispatching requires several optimization paths
# Set platform list (order is important for dispacther generation!!!)
set(MBX_BASE_PLATFORM_LIST k1 l9)

if(MBX_PLATFORM_LIST) # MBX_PLATFORM_LIST may be set by user
  if (NOT MBX_MERGED_BLD)
    foreach(opt ${MBX_PLATFORM_LIST})
      set(FOUND_PLATFORM false)
      foreach(base_opt ${MBX_BASE_PLATFORM_LIST})
        string(STRIP "${opt}" opt_strip)
        if(opt_strip STREQUAL base_opt)
          set(FOUND_PLATFORM true)
        endif()
      endforeach(base_opt ${MBX_BASE_PLATFORM_LIST})
      if(NOT FOUND_PLATFORM)
        message (FATAL_ERROR "Incorrect platform: " ${opt})
      endif()
    endforeach(opt ${MBX_PLATFORM_LIST})
    if (MBX_PLATFORM_LIST STREQUAL "")
      message (FATAL_ERROR "MBX_PLATFORM_LIST cannot be empty")
    endif(MBX_PLATFORM_LIST STREQUAL "")
    message (STATUS "MBX Platform list ..................... " ${MBX_PLATFORM_LIST})
  else()
    message (FATAL_ERROR "MBX_PLATFORM_LIST cannot be set, when MERGED_BLD is on")
  endif(NOT MBX_MERGED_BLD)
else()
  set(MBX_PLATFORM_LIST ${MBX_BASE_PLATFORM_LIST})
endif()

if (NOT MB_STANDALONE)
  if (NOT MBX_MERGED_BLD)
    set(MBX_PLATFORM_LIST ${MBX_PLATFORM_LIST} PARENT_SCOPE)
  endif()
endif()

# check if L9 is supported by the compiler
set(MBX_CC_AVXIFMA_SUPPORT 0)

set(DEFAULT_AVXIFMA_GNU_COMPILER_VER 13.0.0)
set(DEFAULT_AVXIFMA_CLANG_COMPILER_VER 16.0.0)
set(DEFAULT_AVXIFMA_MSVC_COMPILER_VER 19.37)
if(WIN32)
  set(DEFAULT_AVXIFMA_ICX_COMPILER_VER 2025.0.0)
else()
  set(DEFAULT_AVXIFMA_ICX_COMPILER_VER 2024.2.0)
endif()

if((("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")       AND (CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL DEFAULT_AVXIFMA_GNU_COMPILER_VER))   OR
   (("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")     AND (CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL DEFAULT_AVXIFMA_CLANG_COMPILER_VER)) OR
   (("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")      AND (CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL DEFAULT_AVXIFMA_MSVC_COMPILER_VER))  OR
   (("${CMAKE_C_COMPILER_ID}" STREQUAL "IntelLLVM") AND (CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL DEFAULT_AVXIFMA_ICX_COMPILER_VER)))
    set(MBX_CC_AVXIFMA_SUPPORT 1)
endif()

if(MBX_CC_AVXIFMA_SUPPORT)
  message(STATUS "Intel® AVX-IFMA ....................... on")
else()
  if(WIN32)
    message(STATUS "Intel® AVX-IFMA ....................... off, compiler version GCC >= 13.0.0, CLANG >= 16.0.0, Intel ICX >= 2025.0.0 or MSVC >= 17.7 is required")
  else()
    message(STATUS "Intel® AVX-IFMA ....................... off, compiler version GCC >= 13.0.0, CLANG >= 16.0.0, Intel ICX >= 2024.2.0 or MSVC >= 17.7 is required")
  endif()
endif()

if(MB_STANDALONE)
    foreach( OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES} )
        string( TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG )
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/bin")
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/bin")
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/bin")
    endforeach( OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES )
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    set(INTERNAL_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include/autogen_1cpu")
else()
    # Make variables below accessible in parent CMakeLists.txt
    set(MBX_INTERFACE_VERSION ${MBX_INTERFACE_VERSION} PARENT_SCOPE)
    set(MB_PUBLIC_HEADERS ${MB_PUBLIC_HEADERS} PARENT_SCOPE)
    set(MB_DYN_LIB_TARGET    "${MB_DYN_LIB_TARGET}" PARENT_SCOPE)
    set(MB_STATIC_LIB_TARGET "${MB_STATIC_LIB_TARGET}" PARENT_SCOPE)
endif()

if(MB_STANDALONE)
    find_package(Python REQUIRED)
    if(Python_Interpreter_FOUND)
        message (STATUS "PYTHON_VERSION_STRING ................. " ${Python_VERSION})
        else()
        message (STATUS "PYTHON_VERSION_STRING ................. Python not found" )
    endif()
    if(NOT CMAKE_OUTPUT_DIR)
        set(CMAKE_OUTPUT_DIR              "${CMAKE_BINARY_DIR}/.build")
    endif()
endif()

if(BORINGSSL OR BABASSL OR TONGSUO) # off by default
    # BoringSSL doesn't appear to have version information found
    # Tongsuo has own versioning
    # by find_package(OpenSSL)
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL 3.0.8 REQUIRED) # set -DOPENSSL_INCLUDE_DIR= -DOPENSSL_LIBRARIES= -DOPENSSL_ROOT_DIR= to use patched
endif()

if(BABASSL) # off by default
    message(WARNING "-DBABASSL:BOOL=on flag is deprecated and targeted to be removed in the future releases. Please use -DTONGSUO:BOOL=on instead.")
endif()

if(BN_OPENSSL_PATCH)
    # Link static OpenSSL only for patched version
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

include_directories(
    ${CRYPTO_MB_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${INTERNAL_INCLUDE_DIR}
    ${INTERNAL_INCLUDE_DIR}/single_cpu/crypto_mb
    $<$<C_COMPILER_ID:Intel>:$ENV{ROOT}/compiler/include $ENV{ROOT}/compiler/include/icc>
    $<$<NOT:$<C_COMPILER_ID:Intel>>:${CMAKE_SYSTEM_INCLUDE_PATH}>
    $<$<OR:$<C_COMPILER_ID:Intel>,$<BOOL:${MSVC_IDE}>>:$ENV{INCLUDE}>
)

add_subdirectory(src)
