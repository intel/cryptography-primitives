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

# Define defaults for every supported compiler
set(DEFAULT_GNU_COMPILER_VER 8.2.0)
set(DEFAULT_CLANG_COMPILER_VER 9.0.0)
set(DEFAULT_Intel_COMPILER_VER 19.0.0)

# Check compiler version
if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") AND (CMAKE_C_COMPILER_VERSION VERSION_LESS DEFAULT_GNU_COMPILER_VER))
    message(FATAL_ERROR "GNU C Compiler version must be 8.2 or higher")
endif()
if(("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang") AND (CMAKE_C_COMPILER_VERSION VERSION_LESS DEFAULT_CLANG_COMPILER_VER))
  message(FATAL_ERROR "Clang C Compiler version must be 9.0 or higher")
endif()
if(("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel") AND (CMAKE_C_COMPILER_VERSION VERSION_LESS DEFAULT_Intel_COMPILER_VER))
    message(FATAL_ERROR "Compiler version must be 19.0 or higher")
endif()

include("${CRYPTO_MB_SOURCES_DIR}/cmake/common.cmake")
include(${COMPILER_OPTIONS_FILE}) # Get ${CMAKE_C_FLAGS}, ${CMAKE_CXX_FLAGS} and ${AVX512_CFLAGS}

# Sources
file(GLOB RSA_AVX512_SOURCES    "${CRYPTO_MB_SOURCES_DIR}/rsa/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/rsa/internal_avx512/*.c")

file(GLOB COMMON_SOURCES        "${CRYPTO_MB_SOURCES_DIR}/common/*.c")

file(GLOB X25519_SOURCES        "${CRYPTO_MB_SOURCES_DIR}/x25519/*.c" 
                                "${CRYPTO_MB_SOURCES_DIR}/x25519/internal_avx512/*.c")

file(GLOB ECNIST_SOURCES        "${CRYPTO_MB_SOURCES_DIR}/ecnist/*.c" 
                                "${CRYPTO_MB_SOURCES_DIR}/ecnist/internal_avx512/*.c")

file(GLOB SM2_SOURCES           "${CRYPTO_MB_SOURCES_DIR}/sm2/*.c" 
                                "${CRYPTO_MB_SOURCES_DIR}/sm2/internal_avx512/*.c")

file(GLOB SM3_SOURCES           "${CRYPTO_MB_SOURCES_DIR}/sm3/*.c" 
                                "${CRYPTO_MB_SOURCES_DIR}/sm3/internal_avx512/*.c")

# SM4 Sources
file(GLOB SM4_SOURCES           "${CRYPTO_MB_SOURCES_DIR}/sm4/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/sm4/internal_avx512/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/sm4/gcm/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/sm4/gcm/internal_avx512/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/sm4/ccm/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/sm4/ccm/internal_avx512/*.c")

file(GLOB ED25519_SOURCES       "${CRYPTO_MB_SOURCES_DIR}/ed25519/*.c"
                                "${CRYPTO_MB_SOURCES_DIR}/ed25519/internal_avx512/*.c")

file(GLOB EXP_SOURCES           "${CRYPTO_MB_SOURCES_DIR}/exp/*.c")

file(GLOB FIPS_CERT_SOURCES     "${CRYPTO_MB_SOURCES_DIR}/fips_cert/*.c")

# Headers
file(GLOB MB_PRIVATE_HEADERS   "${CRYPTO_MB_INCLUDE_DIR}/internal/common/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/ecnist/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/rsa/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/sm2/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/sm3/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/sm4/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/ed25519/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/exp/*.h"
                               "${CRYPTO_MB_INCLUDE_DIR}/internal/fips_cert/*.h")
file(GLOB OPENSSL_HEADERS      "${OPENSSL_INCLUDE_DIR}/openssl/*.h")

set(CRYPTO_MB_SOURCES_ORIGINAL ${RSA_AVX512_SOURCES} ${COMMON_SOURCES} ${X25519_SOURCES} ${ECNIST_SOURCES} ${SM2_SOURCES} ${SM3_SOURCES} ${SM4_SOURCES} ${ED25519_SOURCES} ${EXP_SOURCES})
set(CRYPTO_MB_HEADERS ${MB_PUBLIC_HEADERS} ${MB_PRIVATE_HEADERS} ${OPENSSL_HEADERS})

set(WIN_RESOURCE_FILE ${CRYPTO_MB_SOURCES_DIR}/common/crypto_mb_ver.rc)
set(CPU_FEATURES_FILE ${CRYPTO_MB_SOURCES_DIR}/common/cpu_features.c)
set(MBX_VERSION_FILE ${CRYPTO_MB_SOURCES_DIR}/common/ifma_version.c)

# Disable compiler optimizations for this file, as compiler adds some ISA specific code
# which is unwanted for functions that are aimed to work on any CPU
list(REMOVE_ITEM CRYPTO_MB_SOURCES_ORIGINAL ${CPU_FEATURES_FILE} ${MBX_VERSION_FILE})
if("${OS_STRING}" STREQUAL "windows")
    set_source_files_properties(${CPU_FEATURES_FILE} ${MBX_VERSION_FILE} PROPERTIES  COMPILE_FLAGS  "${CMAKE_C_FLAGS_SECURITY} /Od")
else()
    set_source_files_properties(${CPU_FEATURES_FILE} ${MBX_VERSION_FILE} PROPERTIES  COMPILE_FLAGS  "${CMAKE_C_FLAGS_SECURITY} -O0")
endif()

if(BN_OPENSSL_PATCH) # Off by default
    list(APPEND AVX512_LIBRARY_DEFINES "BN_OPENSSL_PATCH")
endif()

set(CRYPTO_MB_API ${MB_PUBLIC_HEADERS})
list(REMOVE_ITEM CRYPTO_MB_API ${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/cpu_features.h 
                               ${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/defs.h 
                               ${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/status.h
                               ${CRYPTO_MB_INCLUDE_DIR}/crypto_mb/version.h)

# Generate single-CPU headers
set(MBX_ONE_CPU_FOLDER ${INTERNAL_INCLUDE_DIR}/single_cpu/crypto_mb)
set(MBX_ONE_CPU_GENERATOR   ${MBX_DIR}/gen_cpu_spc_header/gen_cpu_spc_1cpu_header_crypto_mb.py)
set(MBX_INTERNAL_GENERATOR  ${MBX_DIR}/gen_cpu_spc_header/gen_cpu_spc_header_crypto_mb.py)
foreach( header ${CRYPTO_MB_API})
    execute_process(COMMAND ${Python_EXECUTABLE} ${MBX_ONE_CPU_GENERATOR} ${header} ${MBX_ONE_CPU_FOLDER})
    execute_process(COMMAND ${Python_EXECUTABLE} ${MBX_INTERNAL_GENERATOR} ${header} ${INTERNAL_INCLUDE_DIR})
endforeach()

file(GLOB MBX_ONE_CPU_HEADERS "${MBX_ONE_CPU_FOLDER}/*.h")
file(GLOB MBX_CPU_SPC_HEADERS "${INTERNAL_INCLUDE_DIR}/*.h")

# Copy headers to the output directory
foreach( OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
   string( TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG )
   file(COPY ${MBX_ONE_CPU_FOLDER}
        DESTINATION "${CMAKE_OUTPUT_DIR}/${OUTPUTCONFIG}/include/single_cpu")
endforeach( OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES )

foreach(opt ${MBX_PLATFORM_LIST})
    # Populate C source files in to corresponding folders per library 'letter'
    set(mbx_c_cache_dir "${CMAKE_BINARY_DIR}/c_sources/crypto_mb/${opt}/c_${ARCH}")
    file(MAKE_DIRECTORY ${mbx_c_cache_dir})
    # Add a prefix to the source files, so that corresponding object files in the merged library are unique named
    foreach (file ${CRYPTO_MB_SOURCES_ORIGINAL})
        get_filename_component(basename ${file} NAME)
        configure_file(${file} ${mbx_c_cache_dir}/${opt}_${basename} COPYONLY)
    endforeach()
    file (GLOB MBX_C_SOURCES_${opt}
        ${mbx_c_cache_dir}/*.c
    )
    set(OPT_FLAGS_${opt} ${${opt}_opt})
    set_source_files_properties(${MBX_C_SOURCES_${opt}} PROPERTIES COMPILE_DEFINITIONS  "${${opt}_def}"
                                                            COMPILE_FLAGS        "${OPT_FLAGS_${opt}} ${CMAKE_C_FLAGS_SECURITY}")
endforeach()

# build object libraries
set(MBX_TARGET_NAME ${MB_STATIC_LIB_TARGET})

foreach(opt ${MBX_PLATFORM_LIST})
    set(MBX_ST_ITER ${MBX_TARGET_NAME}_${opt})
    add_library(${MBX_ST_ITER} OBJECT ${CRYPTO_MB_HEADERS} ${MBX_C_SOURCES_${opt}})
    set(MBX_MERGED_DEPENDENCY ${MBX_MERGED_DEPENDENCY} $<TARGET_OBJECTS:${MBX_ST_ITER}>)
    list(APPEND MBX_LIB_STATIC ${MBX_ST_ITER})
endforeach()

set(DISPATCHER ${CMAKE_BINARY_DIR}/dispatcher/crypto_mb)
file(MAKE_DIRECTORY ${DISPATCHER})
set(DISPATCHER_GENERATOR ${CRYPTO_MB_DISPATCHER_DIR}/gen_disp_crypto_mb.py)
foreach(incl ${CRYPTO_MB_API})
    execute_process(COMMAND ${Python_EXECUTABLE} ${DISPATCHER_GENERATOR} -i ${incl} -o ${DISPATCHER} -l "${MBX_PLATFORM_LIST}" -c ${CMAKE_C_COMPILER_ID}
        RESULT_VARIABLE result
        )
endforeach()

file(GLOB DISPATCHER_HEADERS
${CMAKE_BINARY_DIR}/dispatcher/crypto_mb/*.h
)

file(GLOB DISPATCHER_C_SOURCES
${CMAKE_BINARY_DIR}/dispatcher/crypto_mb/*.c
)

if(MBX_FIPS_MODE)
    set_source_files_properties(${FIPS_CERT_SOURCES} PROPERTIES COMPILE_DEFINITIONS "MBX_FIPS_MODE")
    set(DISPATCHER_C_SOURCES ${DISPATCHER_C_SOURCES} ${FIPS_CERT_SOURCES})
endif()

set(MB_LIB_TARGET ${MB_DYN_LIB_TARGET})

set_source_files_properties(${DISPATCHER_C_SOURCES} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_SECURITY}")

# Static library
if(WIN32)
    add_library(${MB_STATIC_LIB_TARGET} STATIC ${DISPATCHER_HEADERS} ${DISPATCHER_C_SOURCES} ${MBX_MERGED_DEPENDENCY} ${CPU_FEATURES_FILE} ${MBX_VERSION_FILE} ${WIN_RESOURCE_FILE})
else()
    add_library(${MB_STATIC_LIB_TARGET} STATIC ${DISPATCHER_HEADERS} ${DISPATCHER_C_SOURCES} ${MBX_MERGED_DEPENDENCY} ${CPU_FEATURES_FILE} ${MBX_VERSION_FILE})
endif()

set_target_properties(${MB_STATIC_LIB_TARGET} PROPERTIES C_VISIBILITY_PRESET hidden
                                                        VISIBILITY_INLINES_HIDDEN ON
                                                        PUBLIC_HEADER "${MB_PUBLIC_HEADERS}"
                                                        PRIVATE_HEADER "${MBX_ONE_CPU_HEADERS}")

if(WIN32)
    set_target_properties(${MB_STATIC_LIB_TARGET} PROPERTIES OUTPUT_NAME "${MB_LIB_TARGET}mt")
else()
    set_target_properties(${MB_STATIC_LIB_TARGET} PROPERTIES OUTPUT_NAME "${MB_LIB_TARGET}")
endif()

target_link_libraries(${MB_STATIC_LIB_TARGET} OpenSSL::Crypto)

# Static lib installation
if(MB_STANDALONE)
    install(TARGETS ${MB_STATIC_LIB_TARGET}
            ARCHIVE DESTINATION "lib"
            PUBLIC_HEADER DESTINATION "include/crypto_mb"
            PRIVATE_HEADER DESTINATION "tools/staticlib/crypto_mb")
else()
    install(TARGETS ${MB_STATIC_LIB_TARGET}
            ARCHIVE DESTINATION "lib/intel64"
            PUBLIC_HEADER DESTINATION "include/crypto_mb"
            PRIVATE_HEADER DESTINATION "tools/intel64/staticlib/crypto_mb")
endif()


# Create shared library
if(DYNAMIC_LIB OR MB_STANDALONE)

    add_library(${MB_DYN_LIB_TARGET} SHARED common/emptyfile.c) # emptyfile.c to suppress the cmake warning

    set_target_properties(${MB_DYN_LIB_TARGET} PROPERTIES C_VISIBILITY_PRESET hidden
                                                          VISIBILITY_INLINES_HIDDEN ON
                                                          LINK_FLAGS "${LINK_FLAGS_DYNAMIC} ${LINK_FLAG_SECURITY}"
                                                          PUBLIC_HEADER "${MB_PUBLIC_HEADERS}"
                                                          PRIVATE_HEADER "${MBX_ONE_CPU_HEADERS}"
                                                          )

    if(UNIX)
        set_target_properties(${MB_DYN_LIB_TARGET} PROPERTIES  VERSION   ${MBX_INTERFACE_VERSION}
                                                               SOVERSION ${MBX_INTERFACE_VERSION_MAJOR})
    endif()

    target_link_libraries(${MB_DYN_LIB_TARGET} ${MB_STATIC_LIB_TARGET}) # link to the static merged    

endif(DYNAMIC_LIB OR MB_STANDALONE)

# Installation of the shared library
if (MB_STANDALONE) # standalone crypto_mb's cmake run
    install(TARGETS ${MB_DYN_LIB_TARGET}
            LIBRARY DESTINATION "lib"
            RUNTIME DESTINATION "lib"
            PUBLIC_HEADER DESTINATION "include/crypto_mb"
            PRIVATE_HEADER DESTINATION "tools/staticlib/crypto_mb")
elseif (DYNAMIC_LIB) # build from ippcp's cmake
    install(TARGETS ${MB_DYN_LIB_TARGET}
            LIBRARY DESTINATION "lib/intel64"
            RUNTIME DESTINATION "lib/intel64"
            PUBLIC_HEADER DESTINATION "include/crypto_mb"
            PRIVATE_HEADER DESTINATION "tools/intel64/staticlib/crypto_mb")
endif()
