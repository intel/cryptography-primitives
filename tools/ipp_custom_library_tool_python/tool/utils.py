"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import enum
import os
import re
import sys
from collections import defaultdict
from platform import system

DirLayout = enum.Enum("DirLayout", ["NEW", "OLD"])


class DispatcherType(enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


WINDOWS = "Windows"
LINUX = "Linux"
HOST_SYSTEM = None
SUPPORTED_SYSTEMS = [WINDOWS, LINUX]

INTEL64 = "intel64"
ARCHITECTURES = [INTEL64]

LIB_ARCH_SUBDIR = {
    DirLayout.NEW: "lib",
    DirLayout.OLD: os.path.join("lib", "intel64"),
}

SINGLE_THREADED = "single-threaded"
THREAD_MODES = [SINGLE_THREADED]

TBB = "tbb"
OPENMP = "openmp"
TL_TYPES = [TBB, OPENMP]

PATH_TO_PACKAGE_REGEX = {
    DirLayout.NEW: r"(?P<path>.*)[\\/]opt[\\/]ipp(cp)?[\\/]tools[\\/].*",
    DirLayout.OLD: r"(?P<path>.*)[\\/]tools[\\/].*",
}

VERSION_REGEX = r".*VERSION_STR\s*(?P<ver>.*)\s*"
STR_MACROS_REGEX = r".*STR\((?P<macros>\S*)\).*"
C_STRING_REGEX = r'.*(\S|^)(?P<string>\s*".*"\s*)(\S|$).*'
C_STRING_VALUE_REGEX = r'.*"(?P<value>.*)".*'
FUNCTION_NAME_REGEX = (
    r"IPPAPI\s*\(\s*(?P<ret_type>.*?)\s*," r"\s*(?P<function_name>\S*)\s*," r"\s*\(?(?P<args>.*?)\s*\)?\s*\)?\s*$"
)
ARGUMENT_REGEX = r".*\W*\w+\W*\s+\W*(?P<arg>[^\W\d]+\w*)\W*?"

CUSTOM_LIBRARY_NAME = "Custom library name"
BUILD_SCRIPT_NAME = "Build script name"
OUTPUT_PATH = "Output path"
FUNCTIONS_LIST = "Functions list"
PACKAGE = "Package"
ARCHITECTURE = "Architecture"
THREAD_MODE = "Thread mode"
THREADING_LAYER = "Threading layer"
CUSTOM_CPU_SET = "Custom CPU set"
PREFIX = "Prefix"

CONFIGS = {
    CUSTOM_LIBRARY_NAME: "custom_library",
    BUILD_SCRIPT_NAME: "",
    OUTPUT_PATH: ".",
    FUNCTIONS_LIST: [],
    PACKAGE: "",
    ARCHITECTURE: "",
    THREAD_MODE: "",
    THREADING_LAYER: "",
    CUSTOM_CPU_SET: [],
    PREFIX: "",
}

IPP = "IPP"
IPPCP = "IPPCP"

IPPROOT = "IPPROOT"
IPPCRYPTOROOT = "IPPCRYPTOROOT"

PACKAGE_NAME = {
    IPP: "Intel(R) Integrated Performance Primitives",
    IPPCP: "Intel(R) Cryptography Primitives Library",
}

DOMAINS = {
    IPP: {
        "ippcc": "Color Conversion",
        "ippcv": "Computer Vision",
        "ippdc": "Data Compression",
        "ippe": "Embedded Functionality",
        "ippi": "Image Processing",
        "ipps": "Signal Processing",
        "ippvm": "Vector Math",
        "ippcore": "Core",
    },
    IPPCP: {"ippcp": "Cryptography"},
    THREADING_LAYER: {
        "ippcc": "Color Conversion TL",
        "ippcv": "Computer Vision TL",
        "ippi": "Image Processing TL",
        "ippcore": "Core TL",
    },
}

SSE3 = "sse3"
SSSE3 = "ssse3"
SSE42 = "sse42"
AVX = "avx"
AVX2 = "avx2"
AVX512BW = "avx512bw"
AVX512IFMA = "avx512ifma"

CPU = {
    SSE3: {INTEL64: "m7"},
    SSSE3: {INTEL64: "n8"},
    SSE42: {INTEL64: "y8"},
    AVX: {INTEL64: "e9"},
    AVX2: {INTEL64: "l9"},
    AVX512BW: {INTEL64: "k0"},
    AVX512IFMA: {INTEL64: "k1"},
}

SUPPORTED_CPUS = {
    IPP: {
        INTEL64: {
            WINDOWS: [SSE3, SSSE3, SSE42, AVX, AVX2, AVX512BW],
            LINUX: [SSE3, SSSE3, SSE42, AVX, AVX2, AVX512BW],
        },
    },
    IPPCP: {
        INTEL64: {
            WINDOWS: [SSE3, SSE42, AVX2, AVX512BW, AVX512IFMA],
            LINUX: [SSE3, SSE42, AVX2, AVX512BW, AVX512IFMA],
        },
    },
}

CPUID = {
    AVX512IFMA: "AVX3I_FEATURES",
    AVX512BW: "AVX3X_FEATURES",
    AVX2: "ippCPUID_AVX2",
    AVX: "ippCPUID_AVX",
    SSE42: "ippCPUID_SSE42",
    SSSE3: "ippCPUID_SSSE3",
    SSE3: "ippCPUID_SSE3",
}

LIB_THREAD_TYPE_SUBDIR = {
    DirLayout.NEW: {
        SINGLE_THREADED: "",
        TBB: "",
        OPENMP: "",
    },
    DirLayout.OLD: {
        SINGLE_THREADED: "",
        TBB: os.path.join("tl", TBB),
        OPENMP: os.path.join("tl", OPENMP),
    },
}

LIB_PREFIX = {WINDOWS: "", LINUX: "lib"}

LIB_POSTFIX = {SINGLE_THREADED: "", TBB: "_tl_tbb", OPENMP: "_tl_omp"}

STATIC_LIB_POSTFIX = {WINDOWS: "mt", LINUX: ""}

STATIC_LIB_EXTENSION = {WINDOWS: ".lib", LINUX: ".a"}

DYNAMIC_LIB_EXTENSION = {WINDOWS: ".dll", LINUX: ".so"}

BUILD_SCRIPT_NAME_FORMAT = {
    WINDOWS: "build_{name}_{arch}.bat",
    LINUX: "build_{name}_{arch}.sh",
}

BATCH_EXTENSIONS = {WINDOWS: ".bat", LINUX: ".sh"}

MAIN_FILE_NAME = "main.c"
RENAME_HEADER_NAME = "rename.h"

EXPORT_FILE = {WINDOWS: "export.def", LINUX: "export.def"}

PROJECT_EXTENSION = ".cltproj"

HAVE_PACKAGE = "package..."
HAVE_FUNCTIONS = "functions that has to be in dynamic library... "

ENABLE_GENERATION_RULES = {
    HAVE_PACKAGE: True,
    HAVE_FUNCTIONS: True,
}


def set_host_system():
    host_system = system()

    if host_system not in SUPPORTED_SYSTEMS:
        sys.exit(f"Error: Custom Library Tool doesn't support OS {host_system}")

    global HOST_SYSTEM
    HOST_SYSTEM = host_system


def set_configs_dict(
    package,
    functions_list,
    architecture,
    thread_mode,
    threading_layer_type,
    custom_library_name=CONFIGS[CUSTOM_LIBRARY_NAME],
    build_script_name=CONFIGS[BUILD_SCRIPT_NAME],
    output_path=CONFIGS[OUTPUT_PATH],
    custom_cpu_set=CONFIGS[CUSTOM_CPU_SET],
    prefix=CONFIGS[PREFIX],
):
    CONFIGS[CUSTOM_LIBRARY_NAME] = custom_library_name
    CONFIGS[OUTPUT_PATH] = output_path
    CONFIGS[FUNCTIONS_LIST] = functions_list
    CONFIGS[PACKAGE] = package
    CONFIGS[ARCHITECTURE] = architecture
    CONFIGS[THREAD_MODE] = thread_mode
    CONFIGS[THREADING_LAYER] = threading_layer_type
    CONFIGS[CUSTOM_CPU_SET] = custom_cpu_set
    CONFIGS[PREFIX] = prefix

    if not build_script_name:
        build_script_name = BUILD_SCRIPT_NAME_FORMAT[HOST_SYSTEM].format(name=custom_library_name, arch=architecture)
    CONFIGS[BUILD_SCRIPT_NAME] = build_script_name


def get_first_existing_path_in_list(paths_list):
    for path in paths_list:
        if os.path.exists(path):
            return path
    return ""


def get_lines_from_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return file.readlines()
    else:
        return []


def get_env(env_var):
    return os.environ[env_var] if os.getenv(env_var) and os.path.exists(os.environ[env_var]) else ""


def get_match(regex, string, group):
    return re.match(regex, string).group(group) if re.compile(regex).match(string) else ""


def nested_dict_init():
    return defaultdict(lambda: defaultdict())


def walk_dict(dictionary):
    for key, value in dictionary.items():
        if isinstance(value, dict) or isinstance(value, defaultdict):
            for entire in walk_dict(value):
                yield (key,) + entire
        elif isinstance(value, list):
            for elem in value:
                yield key, elem
        else:
            yield key, value


def get_dict_value(dictionary, key):
    return dictionary[key] if key in dictionary.keys() else dictionary["default"]
