#=========================================================================
# Copyright (C) 2024 Intel Corporation
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
# Generates jmp_ files necessary for the dispatcher
#

import re
import sys
import os
import hashlib
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--header', action='store', required=True, help='Crypto Multi-buffer Library dispatcher will be generated for functions in Header')
parser.add_argument('-o', '--out-directory', action='store', required=True, help='Output folder for generated files')
parser.add_argument('-l', '--cpu-list', action='store', required=True, help='Actual CPU list: semicolon separated string')
parser.add_argument('-c', '--compiler', action='store', required=True, help='Compiler')
args = parser.parse_args()
Header = args.header
OutDir = args.out_directory
cpulist = args.cpu_list.split(';')
compiler = args.compiler

headerID= False      ## Header ID define to avoid multiple include like: #if !defined( __IPPCP_H__ )

from gen_disp_common_crypto_mb import readNextFunction

HDR= open( Header, 'r' )
h= HDR.readlines()
HDR.close()


## keep filename only
(incdir, Header)= os.path.split(Header)

## original header name to declare external functions as internal for dispatcher
OrgH= Header

isFunctionFound = True
curLine = 0
FunType = ""
FunName = ""
FunArg = ""

while (isFunctionFound == True):

    result = readNextFunction(h, curLine, headerID)

    curLine          = result['curLine']
    FunType          = result['FunType']
    FunName          = result['FunName']
    FunArg           = result['FunArg']
    FunArgCall       = result['FunArgCall']
    isFunctionFound  = result['success']

    if (isFunctionFound == True):

        ##################################################
        ## create dispatcher C file
        ##################################################
        DISP= open( os.sep.join([OutDir, "jmp_"+FunName+"_" + hashlib.sha512(FunName.encode('utf-8')).hexdigest()[:8] + ".c"]), 'w' )

        DISP.write(f"#include <crypto_mb/{OrgH}>\n\n")
        DISP.write(f"#include <internal/common/ifma_defs.h>\n\n")

        DISP.write(f"typedef {FunType} (*MBX_FUNC_PTR){FunArg};\n\n")
        DISP.write(f"static int {FunName}_index = -1;\n")
        DISP.write(f"static int *p_{FunName}_index = &{FunName}_index;\n\n")

        DISP.write(f"extern int* _mbx_own_get_index();\n")

        DISP.write(f"extern {FunType} ini_{FunName}{FunArg};\n")

        for cpu in cpulist:
            DISP.write(f"extern {FunType} {cpu}_{FunName}{FunArg};\n")

        DISP.write(f"static MBX_FUNC_PTR arraddr[] =\n{{\n	ini_{FunName}")

        for cpu in cpulist:
            DISP.write(f",\n    {cpu}_{FunName}")

        DISP.write(f"\n}};")

        DISP.write(f"""

DLL_PUBLIC
{FunType} {FunName}{FunArg}
{{
    return (arraddr[*p_{FunName}_index + 1]){FunArgCall};
}}

{FunType} ini_{FunName}{FunArg}
{{
    p_{FunName}_index = _mbx_own_get_index();
    return (arraddr[*p_{FunName}_index + 1]{FunArgCall});
}}
""")

        DISP.close()
