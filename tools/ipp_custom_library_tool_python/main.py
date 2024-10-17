"""
Copyright (C) 2018 Intel Corporation

SPDX-License-Identifier: MIT
"""

import os
import sys
from argparse import ArgumentParser, RawTextHelpFormatter

import tool.package
from tool import utils
from tool.core import build, generate_script

if __name__ == "__main__":
    utils.set_host_system()

    ipp_package_name = utils.PACKAGE_NAME[utils.IPP]
    ippcp_package_name = utils.PACKAGE_NAME[utils.IPPCP]

    args_parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    args_parser.add_argument(
        "-c",
        "--console",
        help="Turns on console version.\nCustom Library Tool is running in GUI mode by default",
        action="store_true",
    )

    console_args = args_parser.add_argument_group("Console mode options")
    console_args.add_argument(
        "-g",
        "--generate",
        help="Generate build script without building custom dynamic library",
        default="none",
        const="dynamic",
        nargs="?",
        choices=("static", "dynamic"),
    )
    console_args.add_argument(
        "-n", "--name", help="Name of custom dynamic library", default=utils.CONFIGS[utils.CUSTOM_LIBRARY_NAME]
    )
    console_args.add_argument(
        "-p", "--output_path", help="Path to output directory", default=utils.CONFIGS[utils.OUTPUT_PATH]
    )
    console_args.add_argument(
        "-root",
        help=f"Path to specified {ipp_package_name}\nor {ippcp_package_name} package",
    )
    console_args.add_argument(
        "-f",
        "--functions",
        help="Functions that has to be in dynamic library (appendable)",
        nargs="+",
        metavar="FUNCTION",
    )
    console_args.add_argument("-ff", "--functions_file", help="Load custom functions list from text file")
    console_args.add_argument(
        "-arch", "--architecture", help="Target architecture", choices=utils.ARCHITECTURES, default="intel64"
    )
    console_args.add_argument(
        "-tl",
        "--threading_layer_type",
        help="Build dynamic library with selected threading layer type",
        choices=utils.TL_TYPES,
    )
    ipp_supported_cpus = " ".join(utils.SUPPORTED_CPUS[utils.IPP][utils.INTEL64][utils.HOST_SYSTEM])
    ippcp_supported_cpus = " ".join(utils.SUPPORTED_CPUS[utils.IPPCP][utils.INTEL64][utils.HOST_SYSTEM])
    console_args.add_argument(
        "-d",
        "--custom_dispatcher",
        help=rf"""Build dynamic library with custom dispatcher.
Set of CPUs can be any combination of the following:
{ipp_package_name}:
    Intel 64 architecture - {ipp_supported_cpus}
{ippcp_package_name}:
    Intel 64 architecture - {ippcp_supported_cpus}""",
        nargs="+",
        metavar="CPU",
    )
    console_args.add_argument(
        "--prefix", help="Rename functions in custom dispatcher with specified prefix", default=""
    )

    args = args_parser.parse_args()

    if args.console:
        print("Custom Library Tool console version is on...")

        functions_list = []
        if args.functions_file:
            with open(args.functions_file, "r") as functions_file:
                functions_list += functions_file.read().splitlines()
        if args.functions:
            functions_list += args.functions
        if not functions_list:
            sys.exit("Please, specify functions that has to be in dynamic library by using -f or -ff options")

        if args.root:
            root = args.root
            if not os.path.exists(root):
                sys.exit(f"Error: specified package path {args.root} doesn't exist")
        else:
            root = tool.package.get_package_path()
            if not os.path.exists(root):
                sys.exit(
                    f"Error: cannot find {ipp_package_name} or {ippcp_package_name} package. "
                    "Please, specify IPPROOT or IPPCRYPTOROOT by using -root option"
                )

        package = tool.package.Package(root)
        print(f"Current package: {package.name}")

        architecture = args.architecture
        thread_mode = utils.SINGLE_THREADED
        threading_layer_type = args.threading_layer_type

        error = package.errors[architecture][thread_mode]
        if error:
            sys.exit(f"Error: {error}")
        if threading_layer_type:
            error = package.errors[architecture][threading_layer_type]
            if error:
                sys.exit(f"Error: {error}")

        custom_cpu_set = []
        if args.custom_dispatcher:
            for cpu in args.custom_dispatcher:
                if cpu not in utils.SUPPORTED_CPUS[package.type][architecture][utils.HOST_SYSTEM]:
                    full_package_name = f"{utils.PACKAGE_NAME[package.type]} {utils.HOST_SYSTEM} {architecture}"
                    sys.exit(f"Error: {cpu} isn't supported for {full_package_name}")
            custom_cpu_set = args.custom_dispatcher
        prefix = args.prefix

        custom_library_name = args.name
        output_path = os.path.abspath(args.output_path)
        if not os.path.exists(output_path):
            os.makedirs(output_path, 0o744)

        utils.set_configs_dict(
            package=package,
            functions_list=functions_list,
            architecture=architecture,
            thread_mode=thread_mode,
            threading_layer_type=threading_layer_type,
            custom_library_name=custom_library_name,
            output_path=output_path,
            custom_cpu_set=custom_cpu_set,
            prefix=prefix,
        )

        if args.generate != "none":
            dispatcher_type = utils.DispatcherType(args.generate)
            success = generate_script(dispatcher_type)
            print("Generation", "completed!" if success else "failed!")
        else:
            success = build()

        if not success:
            exit(1)
    else:
        from PyQt5.QtWidgets import QApplication

        from gui.app import MainAppWindow

        app = QApplication(sys.argv)
        ex = MainAppWindow()
        sys.exit(app.exec_())
