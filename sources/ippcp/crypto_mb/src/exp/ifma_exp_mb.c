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

#include <internal/common/internal_defs.h>

#include <crypto_mb/status.h>
#include <crypto_mb/exp.h>

#include <internal/common/ifma_defs.h>
#include <internal/exp/ifma_exp_method.h>
#include <internal/common/ifma_math.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/common/ifma_cvt52.h>

#if (_MBX >= _MBX_K1)

mbx_status ifma_exp_mb(int64u* const out_pa[8],
                       const int64u* const base_pa[8],
                       const int64u* const exp_pa[8],
                       int exp_bits,
                       const int64u* const mod_pa[8],
                       int mod_bits,
                       exp_mb8 expfunc,
                       int8u* pBuffer,
                       int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test input pointers */
    if (NULL == out_pa || NULL == base_pa || NULL == exp_pa || NULL == mod_pa || NULL == expfunc ||
        NULL == pBuffer) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* test exp length */
    if (exp_bits > mod_bits) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

    /* test length of buffer */
    int bufferMinLen = mbx_exp_BufferSize(mod_bits);
    if (bufferLen < bufferMinLen) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    int buf_no;
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int64u* out        = out_pa[buf_no];
        const int64u* base = base_pa[buf_no];
        const int64u* exp  = exp_pa[buf_no];
        const int64u* mod  = mod_pa[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == out || NULL == base || NULL == exp || NULL == mod) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    /*
    // processing
    */
    if (MBX_IS_ANY_OK_STS(status)) {
        int len52 = NUMBER_OF_DIGITS(mod_bits, DIGIT_SIZE);
        int len64 = NUMBER_OF_DIGITS(mod_bits, 64);

        /* 64-byte aligned buffer of int64[8] */
        pint64u_x8 pBuffer_x8 = (pint64u_x8)IFMA_ALIGNED_PTR(pBuffer, 64);

        /* allocate mb8 buffers */
        pint64u_x8 k0_mb8    = pBuffer_x8;
        pint64u_x8 expz_mb8  = k0_mb8 + 1;
        pint64u_x8 rr_mb8    = expz_mb8 + (len64 + 1);
        pint64u_x8 inout_mb8 = rr_mb8 + len52;
        pint64u_x8 mod_mb8   = inout_mb8 + len52;
        /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb8() implementation specific */
        pint64u_x8 work_buffer = mod_mb8 + MULTIPLE_OF(len52, 10);

        /* convert modulus to ifma fmt */
        zero_mb8(mod_mb8, MULTIPLE_OF(len52, 10));
        ifma_BNU_to_mb8(mod_mb8, mod_pa, mod_bits);

        /* compute k0[] */
        ifma_montFactor52_mb8(k0_mb8[0], mod_mb8[0]);

        /* compute to_Montgomery domain converters */
        ifma_montRR52x_mb8(rr_mb8, mod_mb8, mod_bits);

        /* convert input to ifma fmt */
        ifma_BNU_to_mb8(inout_mb8, base_pa, mod_bits);

        /* re-arrange exps to ifma */
        zero_mb8(expz_mb8, len64 + 1);
        ifma_BNU_transpose_copy(expz_mb8, exp_pa, exp_bits);

        /* exponentiation */
        expfunc(inout_mb8,
                (const int64u(*)[8])inout_mb8,
                (const int64u(*)[8])expz_mb8,
                exp_bits,
                (const int64u(*)[8])mod_mb8,
                (const int64u(*)[8])rr_mb8,
                k0_mb8[0],
                (int64u(*)[8])work_buffer);

        /* convert result from ifma fmt */
        ifma_mb8_to_BNU(out_pa, (const int64u(*)[8])inout_mb8, mod_bits);

        /* clear exponents */
        zero_mb8(expz_mb8, len64);
    }

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */

DLL_PUBLIC
mbx_status OWNAPI(mbx_exp1024_mb8)(int64u* const out_pa[8],
                                   const int64u* const base_pa[8],
                                   const int64u* const exp_pa[8],
                                   int exp_bits,
                                   const int64u* const mod_pa[8],
                                   int mod_bits,
                                   int8u* pBuffer,
                                   int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test exp modulus range */
    if (EXP_MODULUS_1024 != bits_range(mod_bits)) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

#if (_MBX >= _MBX_K1)
    /* 1k exponentiation */
    status |= ifma_exp_mb(out_pa,
                          base_pa,
                          exp_pa,
                          exp_bits,
                          mod_pa,
                          mod_bits,
                          ifma_modexp1024_mb,
                          pBuffer,
                          bufferLen);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_exp2048_mb8)(int64u* const out_pa[8],
                                   const int64u* const base_pa[8],
                                   const int64u* const exp_pa[8],
                                   int exp_bits,
                                   const int64u* const mod_pa[8],
                                   int mod_bits,
                                   int8u* pBuffer,
                                   int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test exp modulus range */
    if (EXP_MODULUS_2048 != bits_range(mod_bits)) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

#if (_MBX >= _MBX_K1)
    /* 2k exponentiation */
    status |= ifma_exp_mb(out_pa,
                          base_pa,
                          exp_pa,
                          exp_bits,
                          mod_pa,
                          mod_bits,
                          ifma_modexp2048_mb,
                          pBuffer,
                          bufferLen);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_exp3072_mb8)(int64u* const out_pa[8],
                                   const int64u* const base_pa[8],
                                   const int64u* const exp_pa[8],
                                   int exp_bits,
                                   const int64u* const mod_pa[8],
                                   int mod_bits,
                                   int8u* pBuffer,
                                   int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test exp modulus range */
    if (EXP_MODULUS_3072 != bits_range(mod_bits)) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

#if (_MBX >= _MBX_K1)
    /* 3k exponentiation */
    status |= ifma_exp_mb(out_pa,
                          base_pa,
                          exp_pa,
                          exp_bits,
                          mod_pa,
                          mod_bits,
                          ifma_modexp3072_mb,
                          pBuffer,
                          bufferLen);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_exp4096_mb8)(int64u* const out_pa[8],
                                   const int64u* const base_pa[8],
                                   const int64u* const exp_pa[8],
                                   int exp_bits,
                                   const int64u* const mod_pa[8],
                                   int mod_bits,
                                   int8u* pBuffer,
                                   int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test exp modulus range */
    if (EXP_MODULUS_4096 != bits_range(mod_bits)) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

#if (_MBX >= _MBX_K1)
    /* 4k exponentiation */
    status |= ifma_exp_mb(out_pa,
                          base_pa,
                          exp_pa,
                          exp_bits,
                          mod_pa,
                          mod_bits,
                          ifma_modexp4096_mb,
                          pBuffer,
                          bufferLen);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_exp_mb8)(int64u* const out_pa[8],
                               const int64u* const base_pa[8],
                               const int64u* const exp_pa[8],
                               int exp_bits,
                               const int64u* const mod_pa[8],
                               int mod_bits,
                               int8u* pBuffer,
                               int bufferLen)
{
    mbx_status status = MBX_STATUS_OK;

    /* test exp modulus range */
    int modulus_range = bits_range(mod_bits);
    if (0 == modulus_range) {
        status = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

    //
    // processing
    //

#if (_MBX >= _MBX_K1)
    exp_mb8 expfunc = NULL;
    switch (modulus_range) {
    case EXP_MODULUS_1024:
        expfunc = ifma_modexp1024_mb;
        break;
    case EXP_MODULUS_2048:
        expfunc = ifma_modexp2048_mb;
        break;
    case EXP_MODULUS_3072:
        expfunc = ifma_modexp3072_mb;
        break;
    case EXP_MODULUS_4096:
        expfunc = ifma_modexp4096_mb;
        break;
    default:
        break;
    }

    status |= ifma_exp_mb(
        out_pa, base_pa, exp_pa, exp_bits, mod_pa, mod_bits, expfunc, pBuffer, bufferLen);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
