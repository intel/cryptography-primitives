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
# Intel(R) Cryptography Primitives Library
#

import sys
import os
import datetime

sys.path.append(os.path.join(sys.path[0], '../dispatcher'))

from gen_disp_common import readNextFunction

Header  = sys.argv[1]
OutDir  = sys.argv[2]

Header = os.path.abspath(Header)
Filename = ""

HDR= open(Header, 'r')
h= HDR.readlines()
HDR.close()

headerID= False
FunName = ""


if not os.path.exists(OutDir):
  os.makedirs(OutDir)


Filename="ippcp"
Filenames=["h9", "p8", "s8", "w7", "e9", "k0", "k1", "l9", "m7", "n8", "y8", "g9"]

DeprecatedCodePaths= {
  "n8" : "m7", # SSSE3 -> SSE3 64-bit
  "e9" : "y8", # AVX -> SSE4.2 64-bit
  "s8" : "w7", # SSSE3 -> SSE2 32-bit
  "g9" : "p8" # AVX -> SSE4.2 32-bit
}

for name in Filenames:
  OutFile  = os.sep.join([OutDir, Filename + "_"+ name + ".h"])

  OUT= open( OutFile, 'w' )
  OUT.write("""/*******************************************************************************
  * Copyright {year} Intel Corporation
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *     http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *******************************************************************************/

  """.format(year=datetime.datetime.today().year))

  if name in DeprecatedCodePaths:
    OUT.write(f"""
#if !defined(_NO_IPP_DEPRECATED)
#pragma message (\"code path {name} is deprecated, lower optimizations level {DeprecatedCodePaths[name]} is used\")
#endif
""")
    name = DeprecatedCodePaths[name]


  curLine = 0
  isFunctionFound = True

  while (isFunctionFound):

    result = readNextFunction(h, curLine, headerID)

    curLine         = result['curLine']
    FunName         = result['FunName']
    isFunctionFound = result['success']

    if (isFunctionFound):
      OUT.write(f"#define {FunName} {name}_{FunName}\n")
  OUT.close()
