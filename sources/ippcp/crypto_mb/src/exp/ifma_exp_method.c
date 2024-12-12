/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#include <crypto_mb/exp.h>
#include <internal/common/ifma_defs.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/exp/ifma_exp_method.h>

/* map exp modulus bit size to exp modulus range */
int bits_range(int modulusBits)
{
    int modulusLen     = (NUMBER_OF_DIGITS(modulusBits, DIGIT_SIZE));
    int modulusLen_top = (NUMBER_OF_DIGITS(modulusBits + 2, DIGIT_SIZE));

    if (modulusLen != modulusLen_top)
        return EXP_MODULUS_UNSUPPORT;

    switch (modulusLen) {
    case NUMBER_OF_DIGITS(EXP_MODULUS_1024, DIGIT_SIZE):
        return EXP_MODULUS_1024;
    case NUMBER_OF_DIGITS(EXP_MODULUS_2048, DIGIT_SIZE):
        return EXP_MODULUS_2048;
    case NUMBER_OF_DIGITS(EXP_MODULUS_3072, DIGIT_SIZE):
        return EXP_MODULUS_3072;
    case NUMBER_OF_DIGITS(EXP_MODULUS_4096, DIGIT_SIZE):
        return EXP_MODULUS_4096;
    default:
        return EXP_MODULUS_UNSUPPORT;
    }
}

/* size of scratch buffer */
DLL_PUBLIC
int OWNAPI(mbx_exp_BufferSize)(int modulusBits)
{
#if (_MBX >= _MBX_K1)
    int modulusRange = bits_range(modulusBits);

    if (modulusRange) {
        int len52      = NUMBER_OF_DIGITS(modulusRange, DIGIT_SIZE);
        int len64      = NUMBER_OF_DIGITS(modulusRange, 64);
        int bufferSize = (8 /* alignment*/

                          /* ifma_mont_exp_mb */
                          + 1 * 8                      /* k0 */
                          + (len64 + 1 + 1) * 8        /* expz */
                          + len52 * 8                  /* rr */
                          + len52 * 8                  /* inp_out */
                          + MULTIPLE_OF(len52, 10) * 8 /* modulus */

                          /* ifma_exp1/2/3/4k_mb */
                          + len52 * 8                       /* Y */
                          + len52 * 8                       /* X */
                          + (1 << EXP_WIN_SIZE) * len52 * 8 /* pre-computed table*/

                          ) *
                         sizeof(int64u);
        return bufferSize;
    } else
        return 0;
#else
    return 0;
#endif /* #if (_MBX>=_MBX_K1) */
}
