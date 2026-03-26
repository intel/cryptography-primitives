#=========================================================================
# Copyright (C) 2022 Intel Corporation
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

function(set_sanitizers_flags lang)
    if(NOT (${lang} STREQUAL "C") AND NOT (${lang} STREQUAL "CXX"))
        message (FATAL_ERROR "Invalid function argument. Expected values: \"C\", \"CXX\" ")
    endif()

    # Enable debug information for the precise analysis.
    set(FLAGS "${FLAGS} -g")

    if(ASAN)
        list(APPEND TYPES_OF_SANITIZERS_LIST "address")
        set(FLAGS "${FLAGS} -fno-omit-frame-pointer")
    endif(ASAN)

    if(UBSAN)
        list(APPEND TYPES_OF_SANITIZERS_LIST "undefined,float-divide-by-zero,unsigned-integer-overflow,implicit-conversion")
    endif(UBSAN)

    if(MSAN)
        list(APPEND TYPES_OF_SANITIZERS_LIST "memory")
        if(${CMAKE_${lang}_COMPILER_VERSION} VERSION_GREATER_EQUAL "13.0.0")
            set(FLAGS "${FLAGS} -fsanitize-ignorelist=${CMAKE_SOURCE_DIR}/sources/cmake/linux/sanitizers_ignorelist.txt")
        else()
            set(FLAGS "${FLAGS} -fsanitize-blacklist=${CMAKE_SOURCE_DIR}/sources/cmake/linux/sanitizers_ignorelist.txt")
        endif()
    endif(MSAN)

    if(TSAN)
        list(APPEND TYPES_OF_SANITIZERS_LIST "thread")
        set(FLAGS "${FLAGS} -fno-omit-frame-pointer")
    endif(TSAN)

    list(JOIN TYPES_OF_SANITIZERS_LIST "," TYPES_OF_SANITIZERS_STRING)
    set(FLAGS "${FLAGS} -fsanitize=${TYPES_OF_SANITIZERS_STRING}")

    set(CMAKE_${lang}_FLAGS "${CMAKE_${lang}_FLAGS} ${FLAGS}" PARENT_SCOPE)
    if(${lang} STREQUAL "CXX")
        # IPP_USE_LIBCXX macro is used in tsstream.h. It is needed to distinguish
        # libcxx build on Linux from the default platform build as libcxx uses
        # different streams API than libstdc++.
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAGS} -DIPP_USE_LIBCXX -stdlib=libc++ -lc++abi" PARENT_SCOPE)
    endif()
endfunction()
