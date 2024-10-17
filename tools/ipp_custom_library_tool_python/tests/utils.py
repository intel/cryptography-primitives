"""
Copyright (C) 2019 Intel Corporation

SPDX-License-Identifier: MIT
"""

HOST_SYSTEM = ""

WINDOWS = "Windows"
LINUX = "Linux"

TEMPORARY_FOLDER = "./tmp"

INTEL64 = "intel64"

BUILD_SCRIPT = {
    INTEL64: {WINDOWS: "intel64.bat", LINUX: "intel64.sh"},
}

EXPORT_FILES = {WINDOWS: "export.def", LINUX: "export.def"}

LIBRARIES_EXTENSIONS = {WINDOWS: ".dll", LINUX: ".so"}

LIBRARIES_PREFIX = {WINDOWS: "", LINUX: "lib"}
