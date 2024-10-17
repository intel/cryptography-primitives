/*************************************************************************
* Copyright (C) 2002 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

/*
// Montgomery engine preparation (GetSize/init/Set)
*/

/*
//     Intel(R) Cryptography Primitives Library
//
//     Context:
//        gsMethod_RSA_gpr_private()
//
*/

#include "owncp.h"
#include "pcpngmontexpstuff.h"
#include "gsscramble.h"
#include "pcpngrsamethod.h"
#include "pcpngrsa.h"

/*
// definition of RSA exponentiation (PX/GPR based)
*/

IPP_OWN_DEFN (gsMethod_RSA*, gsMethod_RSA_gpr_private, (void))
{
   static gsMethod_RSA m = {
      MIN_RSA_SIZE, MAX_RSA_SIZE,   /* RSA range */

      /* private key exponentiation: private, window, gpr */
      gsMontExpWinBuffer,
      #if !defined(_USE_WINDOW_EXP_)
      gsModExpBin_BNU_sscm
      #else
      gsModExpWin_BNU_sscm
      #endif
      , NULL
   };
   return &m;
}
