"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import os
from collections import defaultdict
from pathlib import Path

from tool import utils


class Package:
    def __init__(self, path):
        self.root = path

        self.headers = utils.nested_dict_init()
        self.functions = utils.nested_dict_init()
        self.declarations = defaultdict()

        self.libraries = utils.nested_dict_init()
        self.features = utils.nested_dict_init()
        self.errors = utils.nested_dict_init()

        self.functions_without_dispatcher = []

        self.set_type_and_layout()
        self.set_env_script()

        self.set_headers_functions_declarations_dicts()
        self.set_libraries_features_errors_dicts(self.type, utils.THREAD_MODES)
        self.set_libraries_features_errors_dicts(utils.THREADING_LAYER, utils.TL_TYPES)

        self.package_validation()
        self.set_name()

    def set_type_and_layout(self):
        self.type = utils.IPP
        self.dir_layout = utils.DirLayout.NEW
        self.headers_dir = os.path.join(self.root, "include")
        for package_type in [utils.IPP, utils.IPPCP]:
            package_type_lower = package_type.lower()
            for dir_layout in utils.DirLayout:
                dir_layout_subdir = package_type_lower if dir_layout == utils.DirLayout.NEW else ""
                headers_dir = os.path.join(self.headers_dir, dir_layout_subdir)
                main_header = os.path.join(headers_dir, f"{package_type_lower}.h")
                if os.path.exists(main_header):
                    self.type = package_type
                    self.dir_layout = dir_layout
                    self.headers_dir = headers_dir
                    return

    def set_name(self):
        self.name = "None"
        version = self.get_version()

        if not self.broken:
            self.name = f"{utils.PACKAGE_NAME[self.type]} Version {version}"

    def get_version(self):
        version = ""
        header = os.path.join(self.headers_dir, "ippversion.h")

        for line in utils.get_lines_from_file(header):
            version = utils.get_match(utils.VERSION_REGEX, line, "ver")
            if version:
                break
        if not version:
            version = "None"

        version = self.parse_version_string(version, header)

        return version

    def parse_version_string(self, version, header):
        while True:
            macros = utils.get_match(utils.STR_MACROS_REGEX, version, "macros")
            if not macros:
                break

            macros_value = ""
            for line in utils.get_lines_from_file(header):
                if macros in line:
                    macros_value = line.split(macros, 1)[1].strip()
                    break

            version = version.replace(f"STR({macros})", macros_value)

        while True:
            c_string = utils.get_match(utils.C_STRING_REGEX, version, "string")
            if not c_string:
                break

            c_string_value = utils.get_match(utils.C_STRING_VALUE_REGEX, c_string, "value")
            version = version.replace(c_string, c_string_value)

        return version

    def set_env_script(self):
        paths_to_search = []
        batch_extension = utils.BATCH_EXTENSIONS[utils.HOST_SYSTEM]

        component_dir = Path(self.root).parent
        if component_dir.name == self.type.lower():
            oneapi_dir = component_dir.parent
            paths_to_search.append(os.path.join(oneapi_dir, f"setvars{batch_extension}"))
        paths_to_search.append(os.path.join(self.root, "env", f"vars{batch_extension}"))

        self.env_script = utils.get_first_existing_path_in_list(paths_to_search)

    def set_headers_functions_declarations_dicts(self):
        if not os.path.exists(self.headers_dir):
            return

        headers = [header for header in os.listdir(self.headers_dir) if ".h" in header]

        for header in headers:
            domain_type, domain = self.get_type_and_domain(header)
            if not domain:
                continue

            functions_list = []
            incomplete_function = ""
            for line in utils.get_lines_from_file(os.path.join(self.headers_dir, header)):
                if incomplete_function:
                    self.declarations[incomplete_function] += " " + " ".join(line.split())
                    incomplete_function = self.get_function_if_incomplete(incomplete_function)
                    continue

                function = utils.get_match(utils.FUNCTION_NAME_REGEX, line, "function_name")
                if not function:
                    continue
                functions_list.append(function)
                self.declarations[function] = " ".join(line.split())
                incomplete_function = self.get_function_if_incomplete(function)

            if not functions_list:
                continue

            self.headers[domain_type][domain] = header

            domain_name = utils.DOMAINS[domain_type][domain]
            if domain_name not in self.functions[domain_type]:
                self.functions[domain_type][domain_name] = functions_list
            else:
                self.functions[domain_type][domain_name] += functions_list

            if header == "ippcpdefs.h" or domain_type == utils.THREADING_LAYER or domain == "ippcore":
                self.functions_without_dispatcher += functions_list

    def set_libraries_features_errors_dicts(self, domains_type, thread_types):
        host = utils.HOST_SYSTEM

        for arch in utils.ARCHITECTURES:
            for thread_type in thread_types:
                self.libraries[arch][thread_type] = []
                path_to_libraries = self.get_path_to_libraries(arch, thread_type)

                for domain in utils.DOMAINS[domains_type].keys():
                    lib_name = (
                        utils.LIB_PREFIX[host]
                        + domain
                        + utils.STATIC_LIB_POSTFIX[host]
                        + utils.LIB_POSTFIX[thread_type]
                        + utils.STATIC_LIB_EXTENSION[host]
                    )

                    lib_path = os.path.join(path_to_libraries, lib_name)

                    if os.path.exists(lib_path):
                        self.libraries[arch][thread_type].append(lib_path)
                    elif not domain == "ippe":
                        self.libraries[arch][thread_type].clear()
                        break

                self.features[arch][thread_type] = bool(self.libraries[arch][thread_type])
                self.errors[arch][thread_type] = self.check_headers_and_libs(arch, domains_type, thread_type)

    def package_validation(self):
        self.broken = True
        self.error_message = self.errors[utils.INTEL64][utils.SINGLE_THREADED]

        for arch in utils.ARCHITECTURES:
            for thread in utils.THREAD_MODES:
                if self.features[arch][thread]:
                    self.broken = False
                    return

    def get_type_and_domain(self, header):
        domain_type = self.type if "_tl" not in header else utils.THREADING_LAYER
        for domain in utils.DOMAINS[domain_type].keys():
            if domain in header:
                return domain_type, domain
        return "", ""

    def get_function_if_incomplete(self, function):
        if self.declarations[function].count("(") != self.declarations[function].count(")"):
            return function
        return ""

    def get_path_to_libraries(self, arch, thread_type):
        lib_arch_subdir = utils.LIB_ARCH_SUBDIR[self.dir_layout]
        lib_thread_type_subdir = utils.LIB_THREAD_TYPE_SUBDIR[self.dir_layout][thread_type]
        return os.path.join(self.root, lib_arch_subdir, lib_thread_type_subdir)

    def check_headers_and_libs(self, arch, domains_type, thread_type):
        for domain in utils.DOMAINS[domains_type].keys():
            if domains_type not in self.headers.keys() or (
                domain not in self.headers[domains_type].keys() and not domain == "ippe"
            ):
                return f"Broken package - cannot find header files for {domains_type} functions"

        if not self.libraries[arch][thread_type]:
            return f"Cannot find {thread_type} libraries for {arch} architecture"

        return ""


def get_package_path():
    current_path = os.path.realpath(__file__)
    paths_to_search = [
        utils.get_match(utils.PATH_TO_PACKAGE_REGEX[utils.DirLayout.NEW], current_path, "path"),
        utils.get_match(utils.PATH_TO_PACKAGE_REGEX[utils.DirLayout.OLD], current_path, "path"),
        utils.get_env(utils.IPPROOT),
        utils.get_env(utils.IPPCRYPTOROOT),
    ]

    return utils.get_first_existing_path_in_list(paths_to_search)
