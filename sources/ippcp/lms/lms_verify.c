/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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
#include "lms_internal/lms.h"

/*F*
//    Name: ippsLMSVerify
//
// Purpose: LMS signature verification.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pSign == NULL
//                            pIsSignValid == NULL
//                            pKey == NULL
//                            pBuffer == NULL
//    ippStsBadArgErr         wrong LMS or LMOTS parameters
//                            inside pSign and pKey
//                            OR q is incorrect
//    ippStsContextMatchErr   pSign or pKey contexts are invalid
//    ippStsLengthErr         msgLen < 1
//    ippStsNoErr             no errors
//
// Parameters:
//    pMsg           pointer to the message data buffer
//    msgLen         message buffer length, bytes
//    pSign          pointer to the LMS signature state
//    pIsSignValid   1 if signature is valid, 0 - vice versa
//    pKey           pointer to the LMS public key state
//    pBuffer        pointer to the temporary memory
//
*F*/

IPPFUN(IppStatus, ippsLMSVerify, (const Ipp8u* pMsg, const Ipp32s msgLen,
                                  const IppsLMSSignatureState* pSign,
                                  int*  pIsSignValid,
                                  const IppsLMSPublicKeyState* pKey,
                                  Ipp8u* pBuffer))
{
    IppStatus ippcpSts = ippStsNoErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR4_RET(pMsg, pSign, pIsSignValid, pKey)
    /* Check if temporary buffer is NULL */
    IPP_BAD_PTR1_RET(pBuffer)
    /* Check msg length */
    IPP_BADARG_RET(msgLen < 1, ippStsLengthErr)
    IPP_BADARG_RET( !CP_LMS_VALID_CTX_ID(pSign), ippStsContextMatchErr );
    IPP_BADARG_RET( !CP_LMS_VALID_CTX_ID(pKey), ippStsContextMatchErr );
    *pIsSignValid = 0;

    /*              Parse public key(Pk)             */
    /* --------------------------------------------- */
    IppsLMSAlgo lmsTypePk = pKey->lmsOIDAlgo;
    IppsLMOTSAlgo lmotsTypePk = pKey->lmotsOIDAlgo;

    // Set LMOTS and LMS parameters
    cpLMOTSParams lmotsParams;
    cpLMSParams lmsParams;
    ippcpSts = setLMOTSParams(lmotsTypePk, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    ippcpSts = setLMSParams(lmsTypePk, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    Ipp32u nParam = lmotsParams.n;
    Ipp32u wParam = lmotsParams.w;
    Ipp32u pParam = lmotsParams.p;
    Ipp32u hParam = lmsParams.h;
    Ipp32u mParam = lmsParams.m;

    /*                    Parse signature                   */
    /* ---------------------------------------------------- */
    Ipp32u q = pSign->_q;
    _cpLMOTSSignatureState lmotsSig = pSign->_lmotsSig;
    IppsLMOTSAlgo lmotsTypeSig = lmotsSig._lmotsOIDAlgo;
    IppsLMSAlgo lmsTypeSig = pSign->_lmsOIDAlgo;
    Ipp8u* pAuthPath = pSign->_pAuthPath;

    // Check the validity of the parsed signature parameters
    Ipp32u qLimit = 1 << hParam;
    if((lmsTypePk != lmsTypeSig) || (lmotsTypePk != lmotsTypeSig) || (q >= qLimit))
    {
        return ippStsBadArgErr;
    }

    /* Compute LMS pub key candidate (Algorithms 6a and 4b) */
    /* ---------------------------------------------------- */
    Ipp8u* tmpQBuf = pBuffer;
    Ipp32u total_size = 0;
    // Buffer's invariant for alg correctness - first 16 bytes is always pubKey->I
    CopyBlock(pKey->I, tmpQBuf, CP_PK_I_BYTESIZE); total_size+=CP_PK_I_BYTESIZE;
    toByte(tmpQBuf+total_size, /*q byteLen*/ 4, q); total_size += /*q byteLen*/ 4;
    toByte(tmpQBuf+total_size, /*D_MESG byteLen*/ 2, D_MESG); total_size += /*D_MESG byteLen*/ 2;
    CopyBlock(lmotsSig.pC, tmpQBuf+total_size, (cpSize)nParam); total_size += nParam;
    CopyBlock(pMsg, tmpQBuf+total_size, msgLen); total_size += (Ipp32u)msgLen;

    // Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    Ipp8u Q_CksmQ[CP_LMS_MAX_HASH_BYTESIZE+CP_CKSM_BYTESIZE];
    ippcpSts = ippsHashMessage_rmf(tmpQBuf, (int)total_size, Q_CksmQ, lmsParams.hash_method);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Calculate checksum Cksm(Q) and append it to Q */
    Ipp32u cksmQ = cpCksm(Q_CksmQ, lmotsParams);
    toByte(Q_CksmQ+nParam, /*cksmQ byteLen*/2, cksmQ);

    Ipp8u z[CP_SIG_MAX_Y_WORDSIZE+1][CP_LMS_MAX_HASH_BYTESIZE];
    Ipp8u* pZ = z[0];

    for(Ipp32u i = 0; i < pParam; i++) {
        // a = coef(Q || Cksm(Q), i, w)
        Ipp32u a = cpCoef(Q_CksmQ, i, wParam);
        //tmp = y[i]
        Ipp8u tmp[CP_LMS_MAX_HASH_BYTESIZE];
        CopyBlock(lmotsSig.pY + i*nParam, tmp, (cpSize)nParam);

        // I || u32str(q)
        Ipp8u* tmpBuff = pBuffer;
        // I || u32str(q) || u16str(i)
        toByte(tmpBuff+CP_PK_I_BYTESIZE+/*q byteLen*/4,/*i byteLen*/2,i);
        for(Ipp32u j = a; j < (Ipp32u)((1 << wParam) - 1); j++) {
            // I || u32str(q) || u16str(i) || u8str(j)
            toByte(tmpBuff+CP_PK_I_BYTESIZE+/*q byteLen*/4+/*i byteLen*/2,/*j byteLen*/1,j);
            // I || u32str(q) || u16str(i) || u8str(j) || tmp
            CopyBlock(tmp, tmpBuff+CP_PK_I_BYTESIZE+/*q byteLen*/4+/*i byteLen*/2+/*j byteLen*/1, (cpSize)nParam);
            // tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
            ippcpSts = ippsHashMessage_rmf(tmpBuff,
                                           (int)(CP_PK_I_BYTESIZE+/*q byteLen*/4+/*i byteLen*/2+/*j byteLen*/1+nParam),
                                           tmp,
                                           lmsParams.hash_method);
            IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
        }
        CopyBlock(tmp, pZ+(i+1)*nParam, (cpSize)nParam);
    }
    //                                              I           u32str(q)   u16str(D_PBLC)
    Ipp32s zStartOffset = (Ipp32s)(nParam - (CP_PK_I_BYTESIZE +     4     +      2        ));
    //                                            I          u16str(D_PBLC)
    CopyBlock(tmpQBuf, pZ + zStartOffset, CP_PK_I_BYTESIZE +       4       );
    // Conduct operation u16str(D_PBLC)
    toByte(pZ + nParam - /*D_PBLC byteLen*/2, /*D_PBLC byteLen*/2, D_PBLC);
    // tmp = Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || z[1] || ... || z[p-1])
    Ipp8u Kc[CP_LMS_MAX_HASH_BYTESIZE];
    ippcpSts = ippsHashMessage_rmf(pZ+zStartOffset,
                                   (int)(pParam*nParam+CP_PK_I_BYTESIZE+/*q byteLen*/4+/*D_PBLC byteLen*/2),
                                   Kc,
                                   lmsParams.hash_method);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /*    Compute the candidate LMS root value Tc    */
    /* --------------------------------------------- */
    Ipp32u node_num = (1 << hParam) + q;
    Ipp8u* tmpBuffKc = pBuffer;
    // I || u32str(node_num)
    toByte(tmpBuffKc+CP_PK_I_BYTESIZE, /*node_num byteLen*/4, node_num);
    // I || u32str(node_num) || u16str(D_LEAF)
    toByte(tmpBuffKc+CP_PK_I_BYTESIZE+/*node_num byteLen*/4, /*D_LEAF byteLen*/2, D_LEAF);
    // I || u32str(node_num) || u16str(D_LEAF) || Kc
    CopyBlock(Kc, tmpBuffKc+CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_LEAF byteLen*/2, (cpSize)mParam);
    Ipp8u tmp[CP_LMS_MAX_HASH_BYTESIZE];
    ippcpSts = ippsHashMessage_rmf(tmpBuffKc,
                                   (int)(CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_LEAF byteLen*/2+mParam),
                                   tmp,
                                   lmsParams.hash_method);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    Ipp32u i = 0;
    Ipp8u* locTmp = pBuffer;
    // I || u32str(node_num/2) || u16str(D_INTR)
    toByte(locTmp+CP_PK_I_BYTESIZE+/*node_num byteLen*/4, /*D_INTR byteLen*/2, D_INTR);
    while (node_num > 1) {
        // I || u32str(node_num/2)
        toByte(locTmp+CP_PK_I_BYTESIZE, /*node_num byteLen*/4, node_num/2);

        if((node_num & 1) == 1) {
            // I || u32str(node_num/2) || u16str(D_INTR) || path[i]
            CopyBlock(pAuthPath+i*mParam,
                      locTmp+CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_INTR byteLen*/2,
                      (cpSize)mParam);
            // I || u32str(node_num/2) || u16str(D_INTR) || path[i] || tmp
            CopyBlock(tmp,
                      locTmp+CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_INTR byteLen*/2+mParam,
                      (cpSize)mParam);
        }
        else {
            // I || u32str(node_num/2) || u16str(D_INTR) || tmp
            CopyBlock(tmp,
                      locTmp+CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_INTR byteLen*/2,
                      (cpSize)mParam);
            // I || u32str(node_num/2) || u16str(D_INTR) || tmp || path[i]
            CopyBlock(pAuthPath+i*mParam,
                      locTmp+CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_INTR byteLen*/2+mParam,
                      (cpSize)mParam);
        }

        ippcpSts = ippsHashMessage_rmf(locTmp,
                                       (int)(CP_PK_I_BYTESIZE+/*node_num byteLen*/4+/*D_INTR byteLen*/2+2*mParam),
                                       tmp,
                                       lmotsParams.hash_method);
        IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

        node_num = node_num >> 1;
        i++;
    }

    /*          Verify with given public key         */
    /* --------------------------------------------- */
    BNU_CHUNK_T is_equal = cpIsEquBlock_ct(pKey->T1, tmp, (int)mParam);
    if(is_equal) {
        *pIsSignValid = 1;
    }

    return ippcpSts;
}
