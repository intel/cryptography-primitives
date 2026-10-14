#=========================================================================
# Copyright (C) 2017 Intel Corporation
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

set(OS_DEFAULT_COMPILER Intel19.0.0)

if(${ARCH} MATCHES "ia32")
  set(LIBRARY_DEFINES "${LIBRARY_DEFINES} -Dlinux -DLINUX32 -D_ARCH_IA32") # 32bit linux
else()
  set(LIBRARY_DEFINES "${LIBRARY_DEFINES} -Dlinux -DLINUX32E -D_ARCH_EM64T") # 64bit linux
endif(${ARCH} MATCHES "ia32")

if(NOT NONPIC_LIB)
  set(LIBRARY_DEFINES "${LIBRARY_DEFINES} -DIPP_PIC")
endif()

# Optionally place each function and data item into its own section, so unused
# ones can be discarded by the linker (e.g. with --gc-sections).
if(IPPCP_ENABLE_FUNC_DATA_SECTIONS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
endif()

#set(LIBRARY_DEFINES "${LIBRARY_DEFINES} -DBN_OPENSSL_DISABLE")
