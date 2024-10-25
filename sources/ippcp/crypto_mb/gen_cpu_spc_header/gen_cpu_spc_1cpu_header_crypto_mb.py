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
# Generates headers for 1cpu library. func -> ${opt}_func
#

import sys
import os
import datetime
import ntpath
import re

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

sys.path.append(os.path.join(sys.path[0], '../dispatcher'))

from gen_disp_common_crypto_mb import readNextFunction

Header  = sys.argv[1]
OutDir  = sys.argv[2]

Header = os.path.abspath(Header)
Filename = ""

HDR= open(Header, 'r')
h= HDR.readlines()
HDR.close()

headerID= False
FunName = ""

Filename = re.sub(r'.h','',path_leaf(Header))

if not os.path.exists(OutDir):
  os.makedirs(OutDir)

Filenames=["k1", "l9"]

year = datetime.datetime.today()

for name in Filenames:
  OutFile  = os.sep.join([OutDir, Filename + "_"+ name + ".h"])
  
  OUT= open( OutFile, 'w' )
  OUT.write(f"""/*******************************************************************************
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

  """)

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
