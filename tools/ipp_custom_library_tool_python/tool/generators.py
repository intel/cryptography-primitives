"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import os

from tool import utils
from tool.generators_utils import (
    ADDITIONAL_ENV,
    ARCHITECTURE_DEFINE,
    BUILD_SCRIPT,
    CALL_ENV_SCRIPT_COMMAND,
    COMPILE_COMMAND_FORMAT,
    COMPILERS,
    COMPILERS_FLAGS,
    CUSTOM_DISPATCHER_FILE,
    DISPATCHING_SCHEME_FORMAT,
    ENV_VAR,
    EXP_LIBS,
    FEATURES,
    FUNCTION_DISPATCHER,
    INCLUDE_STR,
    INIT_CHECK_FORMAT,
    LINK_COMMAND_FORMAT,
    LINKER_FLAGS,
    LINKERS,
    LINUX,
    MAIN_FILE,
    OPENMP,
    RENAME_FORMAT,
    RENAME_HEADER_SCHEME,
    RETURN_VALUES,
    SET_ENV_COMMAND,
    SYS_LIBS_PATH,
    UNINITIALIZED_FEATURES,
    UNINITIALIZED_FEATURES_DEFINE,
    WINDOWS,
)


def main_file_generator():
    return MAIN_FILE[utils.HOST_SYSTEM].format(package_type=utils.CONFIGS[utils.PACKAGE].type.lower())


def create_windows_export_file(export_file, functions_list):
    """
    Creates export file for Windows

    :param export_file: object that is returned by open function
    :param functions_list: list of functions for dynamic library
    """
    export_file.write("EXPORTS\n\n")
    export_file.writelines(map(lambda x: f"{x}\n", functions_list))


def create_linux_export_file(export_file, functions_list):
    """
    Creates Linux export file

    :param export_file:
    :param functions_list:
    :return:
    """
    export_file.writelines(map(lambda x: f"EXTERN({x})\n", functions_list))
    export_file.write(
        r"""
VERSION
{{
    {{
        global:
{functions_list}
        local:* ;
    }};
}}""".format(
            functions_list="".join(map(lambda x: f"        {x};\n", functions_list))
        )
    )


EXPORT_GENERATORS = {
    WINDOWS: create_windows_export_file,
    LINUX: create_linux_export_file,
}


def custom_dispatcher_generator(function, dispatcher_type: utils.DispatcherType = utils.DispatcherType.DYNAMIC):
    package = utils.CONFIGS[utils.PACKAGE]
    arch = utils.CONFIGS[utils.ARCHITECTURE]
    include_lines = INCLUDE_STR.format(header_name=package.type.lower() + ".h")

    dispatcher = ""
    dispatcher += func_dispatcher_generator(arch, function, dispatcher_type)

    ippe = utils.DOMAINS[utils.IPP]["ippe"]
    if ippe in package.functions[utils.IPP].keys() and function in package.functions[utils.IPP][ippe]:
        include_lines += "\n" + INCLUDE_STR.format(header_name="ippe.h")

    if dispatcher_type == utils.DispatcherType.STATIC:
        uninitialized_features_define = UNINITIALIZED_FEATURES_DEFINE.format(
            uninitialized_features=UNINITIALIZED_FEATURES[package.type]
        )
    else:
        uninitialized_features_define = ""

    return CUSTOM_DISPATCHER_FILE.format(
        include_lines=include_lines,
        architecture=ARCHITECTURE_DEFINE[arch],
        features=FEATURES[arch],
        uninitialized_features_define=uninitialized_features_define,
        dispatcher=dispatcher,
    )


def rename_header_generator(functions_list):
    package = utils.CONFIGS[utils.PACKAGE]
    prefix = utils.CONFIGS[utils.PREFIX]

    package_type_lower = package.type.lower()
    package_type_upper = package.type.upper()
    defs_header = "defs.h" if package.type == utils.IPP or package.type == utils.IPPCP else "base.h"
    defs_header_name = package_type_lower + defs_header
    if package.dir_layout == utils.DirLayout.NEW:
        defs_header_name = f"{package_type_lower}/{defs_header_name}"
    defines_header_statement = INCLUDE_STR.format(header_name=defs_header_name)
    rename_statements = ""
    for function in functions_list:
        declaration = package.declarations[function].replace(function, prefix + function)
        rename_statements += RENAME_FORMAT.format(declaration=declaration, function=function, prefix=prefix)
    return RENAME_HEADER_SCHEME.format(
        prefix=package_type_upper,
        defines_header_statement=defines_header_statement,
        rename_statements=rename_statements,
    )


def func_dispatcher_generator(arch, function, dispatcher_type: utils.DispatcherType = utils.DispatcherType.DYNAMIC):
    package_type = utils.CONFIGS[utils.PACKAGE].type
    declarations = utils.CONFIGS[utils.PACKAGE].declarations[function]
    function_with_prefix = utils.CONFIGS[utils.PREFIX] + function
    ippfun = declarations.replace("IPPAPI", "IPPFUN").replace(function, function_with_prefix)

    args = utils.get_match(utils.FUNCTION_NAME_REGEX, declarations, "args").split(",")
    args = [utils.get_match(utils.ARGUMENT_REGEX, arg, "arg") for arg in args]
    args = ", ".join(args)

    ret_type = utils.get_match(utils.FUNCTION_NAME_REGEX, declarations, "ret_type")
    ret_value = utils.get_dict_value(RETURN_VALUES, ret_type)
    if ret_value:
        return_keyword = "return "
    else:
        return_keyword = ""

    ippapi = ""
    dispatching_scheme = ""
    for cpu in utils.CPUID.keys():
        if cpu not in utils.CONFIGS[utils.CUSTOM_CPU_SET]:
            continue

        cpuid = utils.CPUID[cpu]
        cpu_code = utils.CPU[cpu][arch]

        function_with_cpu_code = f"{cpu_code}_{function}"
        ippapi += declarations.replace(function, function_with_cpu_code) + "\n"

        dispatching_scheme += DISPATCHING_SCHEME_FORMAT.format(
            cpuid=cpuid, return_keyword=return_keyword, function=function_with_cpu_code, args=args
        )

    if dispatcher_type == utils.DispatcherType.STATIC:
        init_check = INIT_CHECK_FORMAT.format(
            package_type=package_type.lower(), return_keyword=return_keyword, function=function_with_prefix, args=args
        )
    else:
        init_check = ""

    return_statement = f"\n    return {ret_value};" if ret_value else ""

    return FUNCTION_DISPATCHER.format(
        ippapi=ippapi,
        ippfun=ippfun,
        package_type=package_type.lower(),
        dispatching_scheme=dispatching_scheme,
        init_check=init_check,
        return_statement=return_statement,
    )


def build_script_generator():
    """
    Generates script for building custom dynamic library
    :return: String that represents script
    """
    host = utils.HOST_SYSTEM
    configs = utils.CONFIGS

    package = configs[utils.PACKAGE]
    output_path = configs[utils.OUTPUT_PATH]

    arch = configs[utils.ARCHITECTURE]
    thread = configs[utils.THREAD_MODE]
    tl = configs[utils.THREADING_LAYER]

    root_type = utils.IPPROOT if package.type == utils.IPP else utils.IPPCRYPTOROOT

    if package.env_script:
        force_flag = ""
        if "setvars" in package.env_script:
            force_flag = "--force"

        env_commands = CALL_ENV_SCRIPT_COMMAND[host].format(
            env_script=package.env_script, arch=arch, force_flag=force_flag
        )
    else:
        env_commands = SET_ENV_COMMAND[host].format(env_var=root_type, path=package.root)
    if ADDITIONAL_ENV[host]:
        env_commands += "\n" + ADDITIONAL_ENV[host]

    compiler = COMPILERS[host]

    cmp_flags = COMPILERS_FLAGS[host][arch]
    if tl == OPENMP and host == WINDOWS:
        cmp_flags += " /openmp"

    c_files = utils.MAIN_FILE_NAME
    if configs[utils.CUSTOM_CPU_SET]:
        c_files += " " + os.path.join("custom_dispatcher", arch, "*.c")

    compile_command = COMPILE_COMMAND_FORMAT[host].format(
        compiler=compiler, cmp_flags=cmp_flags, root_type=root_type, c_files=c_files
    )

    linker = LINKERS[host]
    link_flags = LINKER_FLAGS[host][arch]
    custom_library = utils.LIB_PREFIX[host] + configs[utils.CUSTOM_LIBRARY_NAME]
    export_file = utils.EXPORT_FILE[host]

    ipp_libraries = package.libraries[arch][thread]
    if tl:
        ipp_libraries = package.libraries[arch][tl] + ipp_libraries
    ipp_libraries = [lib.replace(package.root, ENV_VAR[host].format(env_var=root_type)) for lib in ipp_libraries]
    ipp_libraries = " ".join(f'"{lib}"' for lib in ipp_libraries)

    exp_libs = EXP_LIBS[host][thread]
    if tl and EXP_LIBS[host][tl] not in exp_libs:
        exp_libs += " " + EXP_LIBS[host][tl]

    sys_libs_path = SYS_LIBS_PATH[host][arch]

    link_command = LINK_COMMAND_FORMAT[host].format(
        linker=linker,
        link_flags=link_flags,
        custom_library=custom_library,
        export_file=export_file,
        ipp_libraries=ipp_libraries,
        exp_libs=exp_libs,
        sys_libs_path=sys_libs_path,
    )

    return BUILD_SCRIPT[host].format(
        architecture=arch,
        threading=thread.lower(),
        output_path=output_path,
        custom_library=custom_library,
        env_commands=env_commands,
        compile_command=compile_command,
        link_command=link_command,
    )
