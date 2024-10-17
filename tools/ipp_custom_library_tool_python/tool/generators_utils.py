"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

from tool.utils import INTEL64, IPP, IPPCP, LINUX, OPENMP, SINGLE_THREADED, TBB, WINDOWS

ENV_VAR = {WINDOWS: "%{env_var}%", LINUX: "${{{env_var}}}"}

CALL_ENV_SCRIPT_COMMAND = {
    WINDOWS: 'call "{env_script}" {arch} {force_flag}',
    LINUX: 'source "{env_script}" -arch {arch} {force_flag}',
}

SET_ENV_COMMAND = {
    WINDOWS: 'set "{env_var}={path}"',
    LINUX: 'export "{env_var}={path}"',
}

ADDITIONAL_ENV = {
    WINDOWS: "",
    LINUX: "export LIBRARY_PATH=$LD_LIBRARY_PATH:$LIBRARY_PATH",
}

COMPILERS = {WINDOWS: "cl.exe", LINUX: "g++"}

LINKERS = {WINDOWS: "link.exe", LINUX: "g++"}

COMPILERS_FLAGS = {
    WINDOWS: {INTEL64: "/c /MP /MT /GS /sdl /O2"},
    LINUX: {
        INTEL64: (
            "-c -m64 -fPIC -fPIE -fstack-protector-strong -fstack-protector -O2 -D_FORTIFY_SOURCE=2 "
            "-fcf-protection -Wformat -Wformat-security"
        ),
    },
}

LINKER_FLAGS = {
    WINDOWS: {
        INTEL64: "/MACHINE:X64 /NXCompat /DynamicBase /CETCOMPAT /DEPENDENTLOADFLAG:0x2000",
    },
    LINUX: {
        INTEL64: "-z noexecstack -z relro -z now -fcf-protection",
    },
}

COMPILE_COMMAND_FORMAT = {
    WINDOWS: "{compiler} {cmp_flags} " '/I "%{root_type}%\\include" ' "{c_files}",
    LINUX: "{compiler} {cmp_flags}" ' -I "${root_type}/include" ' "{c_files}",
}

LINK_COMMAND_FORMAT = {
    WINDOWS: "{linker} /DLL {link_flags} /VERBOSE:SAFESEH "
    '/DEF:"{export_file}" *.obj '
    '/OUT:"{custom_library}.dll" /IMPLIB:"{custom_library}.lib" '
    "{ipp_libraries} "
    "{exp_libs}",
    LINUX: "{linker} -shared {link_flags} "
    '"{export_file}" *.o '
    '-o "{custom_library}.so" '
    "{ipp_libraries} "
    '-L"{sys_libs_path}" -lc -lm {exp_libs}',
}

SYS_LIBS_PATH = {
    WINDOWS: {
        INTEL64: "",
    },
    LINUX: {INTEL64: "$SYSROOT/lib64"},
}

EXP_LIBS = {
    WINDOWS: {SINGLE_THREADED: "", TBB: "tbb.lib", OPENMP: "libiomp5md.lib"},
    LINUX: {SINGLE_THREADED: "", TBB: "-ltbb", OPENMP: "-liomp5"},
}

MAIN_FILE = {
    WINDOWS: r"""#include <Windows.h>
#include "{package_type}.h"

int WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{{
    switch (fdwReason)
    {{
    case DLL_PROCESS_ATTACH:
        {package_type}Init(); break;
    case DLL_THREAD_ATTACH: break;
    case DLL_THREAD_DETACH: break;
    case DLL_PROCESS_DETACH: break;
    default: break;
    }}
    return 1;
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);
}}
""",
    LINUX: r"""#include "{package_type}.h"

int _init(void)
{{
    {package_type}Init();
    return 1;
}}

void _fini(void)
{{
}}
""",
}

CUSTOM_DISPATCHER_FILE = r"""{include_lines}

#ifndef IPP_CALL
#   define IPP_CALL IPP_STDCALL
#endif

#define IPPFUN(type, name, arg) extern type IPP_CALL name arg

#ifndef NULL
#   ifdef __cplusplus
#       define NULL 0
#   else
#       define NULL ((void*)0)
#   endif
#endif

{architecture}

{features}{uninitialized_features_define}

#ifdef __cplusplus
extern "C" {{
#endif

{dispatcher}

#ifdef __cplusplus
}}
#endif

#endif
"""

RENAME_FORMAT = r"""
{declaration}
#define {function} {prefix}{function}
"""

RENAME_HEADER_SCHEME = r"""#ifndef {prefix}_RENAME_H
#define {prefix}_RENAME_H

{defines_header_statement}

#ifdef __cplusplus
extern "C" {{
#endif
{rename_statements}
#ifdef __cplusplus
}}
#endif

#endif // {prefix}_RENAME_H
"""

INCLUDE_STR = "#include <{header_name}>"

ARCHITECTURE_DEFINE = {
    INTEL64: "#if defined (_M_AMD64) || defined (__x86_64__)",
}

FEATURES = {
    INTEL64: r"""
#define AVX3I_FEATURES (ippCPUID_SHA | ippCPUID_AVX512VBMI | ippCPUID_AVX512VBMI2 | ippCPUID_AVX512IFMA | \
    ippCPUID_AVX512GFNI | ippCPUID_AVX512VAES | ippCPUID_AVX512VCLMUL)
#define AVX3X_FEATURES (ippCPUID_AVX512F | ippCPUID_AVX512CD | ippCPUID_AVX512VL | ippCPUID_AVX512BW | \
    ippCPUID_AVX512DQ)"""
}

UNINITIALIZED_FEATURES = {IPP: "(ippCPUID_MMX | ippCPUID_SSE | ippCPUID_SSE2)", IPPCP: "0"}

UNINITIALIZED_FEATURES_DEFINE = r"""
#define UNINITIALIZED_FEATURES {uninitialized_features}"""

FUNCTION_DISPATCHER = r"""{ippapi}
{ippfun}
{{
    Ipp64u _features = {package_type}GetEnabledCpuFeatures();
{dispatching_scheme}{init_check}{return_statement}
}}"""

INIT_CHECK_FORMAT = r"""
    if (_features == UNINITIALIZED_FEATURES)
    {{
        (void){package_type}Init();
        _features = {package_type}GetEnabledCpuFeatures();
        if (_features != UNINITIALIZED_FEATURES)
        {{
            {return_keyword}{function}({args});
        }}
    }}"""

DISPATCHING_SCHEME_FORMAT = r"""
    if ({cpuid} == (_features & {cpuid}))
    {{
        {return_keyword}{function}({args});
    }}"""

RETURN_VALUES = {
    "IppStatus": "ippStsCpuNotSupportedErr",
    "IppiRect": "(IppiRect) { IPP_MIN_32S / 2, IPP_MIN_32S / 2, IPP_MAX_32S, IPP_MAX_32S }",
    "void": "",
    "default": "NULL",
}

BUILD_SCRIPT = {
    WINDOWS: r""":: Generates {threading} dynamic library for {architecture} architecture
@echo off
set "OUTPUT_PATH={output_path}"
if not exist %OUTPUT_PATH% mkdir %OUTPUT_PATH%
if exist "{custom_library}.dll" del "{custom_library}.dll"

setlocal
{env_commands}
cd /d %OUTPUT_PATH%
{compile_command}
{link_command}
endlocal

if %ERRORLEVEL%==0 (
    echo Build completed!
    del /s /q /f *.obj > nul
    exit /b 0
) else (
    echo Build failed!
    exit /b 1
)
""",
    LINUX: r"""#!/bin/bash
# Generates {threading} dynamic library for {architecture} architecture
OUTPUT_PATH="{output_path}"
mkdir -m 744 -p $OUTPUT_PATH
cd $OUTPUT_PATH

rm -rf "{custom_library}.so"

{env_commands}
{compile_command}
{link_command}
if [ $? == 0 ]; then
    echo Build completed!
    rm -rf *.o
    exit 0
else
    echo Build failed!
    exit 1
fi
""",
}
