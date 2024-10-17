#=========================================================================
# Copyright (C) 2021 Intel Corporation
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

#
# Intel® Cryptography Primitives Library
#

# Linker flags

# Security Linker flags
set(LINK_FLAG_SECURITY "")
# Disallows undefined symbols in object files. Undefined symbols in shared libraries are still allowed
set(LINK_FLAG_SECURITY "${LINK_FLAG_SECURITY} -Wl,-z,defs")
# Stack execution protection
set(LINK_FLAG_SECURITY "${LINK_FLAG_SECURITY} -Wl,-z,noexecstack")
# Data relocation and protection (RELRO)
set(LINK_FLAG_SECURITY "${LINK_FLAG_SECURITY} -Wl,-z,relro -Wl,-z,now")

# Prevents the compiler from using standard libraries and startup files when linking.
set(LINK_FLAG_DYNAMIC_LINUX "${LINK_FLAG_SECURITY} -nostdlib")
# Create a shared library
set(LINK_FLAG_DYNAMIC_LINUX "${LINK_FLAG_DYNAMIC_LINUX} -Wl,-shared")
# Dynamically link lib c (libdl is for old apps)
set(LINK_FLAG_DYNAMIC_LINUX "${LINK_FLAG_DYNAMIC_LINUX} -Wl,-call_shared,-lc")

if(${ARCH} MATCHES "ia32")
  # Emulate elf_i386 linker
  set(LINK_FLAG_DYNAMIC_LINUX "${LINK_FLAG_DYNAMIC_LINUX} -Wl,-m,elf_i386")
endif(${ARCH} MATCHES "ia32")

set(LINK_FLAG_PCS_LINUX "${LINK_FLAG_DYNAMIC_LINUX}")

# Compiler flags
# Enables the use of blocks and entire functions of assembly code within a C or C++ file
set(CC_FLAGS_INLINE_ASM_UNIX "-fasm-blocks")

# Disables all warning messages
set(CC_FLAGS_INLINE_ASM_UNIX_IA32 "${CC_FLAGS_INLINE_ASM_UNIX} -w")
# Tells the compiler to generate code for a specific architecture (32)
set(CC_FLAGS_INLINE_ASM_UNIX_IA32 "${CC_FLAGS_INLINE_ASM_UNIX_IA32} -m32")
# EBP is used as a general-purpose register in optimizations
set(CC_FLAGS_INLINE_ASM_UNIX_IA32 "${CC_FLAGS_INLINE_ASM_UNIX_IA32} -fomit-frame-pointer")

# Do not use the specified registers in dispatcher compilation
set(CC_FLAGS_INLINE_ASM_UNIX_INTEL64 "${CC_FLAGS_INLINE_ASM_UNIX} -ffixed-rdi -ffixed-rsi -ffixed-rbx -ffixed-rcx -ffixed-rdx -ffixed-rbp -ffixed-r8 -ffixed-r9 -ffixed-r12 -ffixed-r13 -ffixed-r14 -ffixed-r15")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBRARY_DEFINES}")

# Ensures that compilation takes place in a freestanding environment
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffreestanding")
# Tells the compiler to align functions and loops
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -falign-functions=32")
# C std and diag settings
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99  -diag-error 266  -diag-disable 13366")

# Security Compiler flags

# Stack-based Buffer Overrun Detection
if ((${ARCH} MATCHES "ia32") OR (NOT NONPIC_LIB))
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector")
endif()

# Format string vulnerabilities
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -Wunknown-pragmas")

# Enable Intel® Control-Flow Enforcement Technology (Intel® CET) protection
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcf-protection=full -O3")

if(NOT NONPIC_LIB)
  # Position Independent Execution (PIE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic -fPIC")
elseif(NOT ${ARCH} MATCHES "ia32")
  # NONPIC intel64: specify kernel code model
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mno-red-zone -mcmodel=kernel")
endif()

if(CODE_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -prof-gen:srcpos -prof-dir $ENV{PROF_DATA_DIR}")
endif()

# Optimization level = 3, no-debug definition (turns off asserts), warning level = 3, treat warnings as errors
set(CMAKE_C_FLAGS_RELEASE " -Ofast -DNDEBUG -Wall -Wno-unused-function -Werror")
# Security flag that adds compile-time and run-time checks
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2")

# Alignment for structures on byte boundaries (= 16)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Zp16")
if(${ARCH} MATCHES "ia32")
    # Tells the compiler to generate code for a specific architecture (32)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
endif(${ARCH} MATCHES "ia32")

set(px_opt "${px_opt} ") # note: no flags for the default version
set(w7_opt "${w7_opt} -msse2")
set(s8_opt "${s8_opt} -march=core2 -mssse3")
set(p8_opt "${p8_opt} -march=nehalem -msse4.2 -maes -mpclmul -msha")
set(g9_opt "${g9_opt} -march=sandybridge -mavx -maes -mpclmul -msha -mrdrnd -mrdseed")
set(h9_opt "${h9_opt} -march=haswell -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -msha -mrdrnd -mrdseed")
set(mx_opt "${mx_opt} ") # note: no flags for the default version
set(m7_opt "${m7_opt} -march=nocona -msse3")
set(n8_opt "${n8_opt} -march=core2 -mssse3")
set(y8_opt "${y8_opt} -march=nehalem -msse4.2 -maes -mpclmul -msha")
set(e9_opt "${e9_opt} -march=sandybridge -mavx -maes -mpclmul -msha -mrdrnd -mrdseed")
set(l9_opt "${l9_opt} -march=haswell -mavx2 -maes -mvaes -mpclmul -mvpclmulqdq -msha -mrdrnd -mrdseed")
set(k0_opt "${k0_opt} -march=skylake-avx512")
set(k0_opt "${k0_opt} -maes -mavx512f -mavx512cd -mavx512vl -mavx512bw -mavx512dq -mpclmul -mrdrnd -mrdseed -madx")
set(k0_opt "${k0_opt} -mprefer-vector-width=512")
set(k1_opt "${k1_opt} -march=icelake-server")
set(k1_opt "${k1_opt} -maes -mavx512f -mavx512cd -mavx512vl -mavx512bw -mavx512dq -mavx512ifma -mpclmul -msha -mrdrnd -mrdseed -madx -mgfni -mvaes -mvpclmulqdq -mavx512vbmi -mavx512vbmi2")
set(k1_opt "${k1_opt} -mprefer-vector-width=512")
