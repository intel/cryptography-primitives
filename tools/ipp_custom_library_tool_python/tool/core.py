"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import os
from subprocess import call  # nosec

from tool import utils
from tool.generators import (
    EXPORT_GENERATORS,
    build_script_generator,
    custom_dispatcher_generator,
    main_file_generator,
    rename_header_generator,
)


def generate_script(dispatcher_type: utils.DispatcherType = utils.DispatcherType.DYNAMIC):
    """
    Generates build script
    """

    host = utils.HOST_SYSTEM
    configs = utils.CONFIGS

    package = configs[utils.PACKAGE]
    functions_list = configs[utils.FUNCTIONS_LIST]
    output_path = configs[utils.OUTPUT_PATH]

    if not os.path.exists(output_path):
        os.makedirs(output_path, 0o744)

    with open(os.path.join(output_path, utils.MAIN_FILE_NAME), "w") as main_file:
        main_file.write(main_file_generator())

    if configs[utils.CUSTOM_CPU_SET]:
        disp_folder = os.path.join(output_path, "custom_dispatcher", configs[utils.ARCHITECTURE])
        if not os.path.exists(disp_folder):
            os.makedirs(disp_folder, 0o744)

        functions_with_custom_disp = []
        for function in functions_list:
            if function not in package.functions_without_dispatcher:
                disp_file_path = os.path.join(disp_folder, f"{function}.c")
                functions_with_custom_disp.append(function)

                with open(disp_file_path, "w") as disp_file:
                    disp_file.write(custom_dispatcher_generator(function, dispatcher_type))

        if configs[utils.PREFIX]:
            with open(os.path.join(disp_folder, utils.RENAME_HEADER_NAME), "w") as rename_header:
                rename_header.write(rename_header_generator(functions_with_custom_disp))

            functions_list = [
                configs[utils.PREFIX] + func if func in functions_with_custom_disp else func for func in functions_list
            ]

    with open(os.path.join(output_path, utils.EXPORT_FILE[host]), "w") as export_file:
        EXPORT_GENERATORS[host](export_file, functions_list)

    script_path = os.path.join(output_path, configs[utils.BUILD_SCRIPT_NAME])
    with open(script_path, "w") as build_script:
        build_script.write(build_script_generator())
    os.chmod(script_path, 0o744)

    return os.path.exists(script_path)


def build():
    """
    Builds dynamic library

    :return: True if build was successful and False in the opposite case
    """
    success = generate_script()
    if not success:
        return False

    error = call([os.path.join(utils.CONFIGS[utils.OUTPUT_PATH], utils.CONFIGS[utils.BUILD_SCRIPT_NAME])])
    return False if error else True
