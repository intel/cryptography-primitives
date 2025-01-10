;=========================================================================
; Copyright (C) 2024 Intel Corporation
;
; Licensed under the Apache License,  Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
; 	http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law  or agreed  to  in  writing,  software
; distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the  specific  language  governing  permissions  and
; limitations under the License.
;=========================================================================

;
;     Purpose:  Cryptography Primitive.
;               SHA512 Message block processing with SHA512 instructions
;
;     Content:
;        UpdateSHA512ni
;

%include "asmdefs.inc"
%include "ia_emm.inc"
%include "pcpvariant.inc"

%if (_ENABLE_ALG_SHA512_)
%if (_SHA512_ENABLING_ == _FEATURE_ON_) || (_SHA512_ENABLING_ == _FEATURE_TICKTOCK_)
%if (_IPP >= _IPP_H9)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

segment .text align=IPP_ALIGN_FACTOR

align IPP_ALIGN_FACTOR
SHA512_SHUFF_MASK_AVX dq 0x0001020304050607, 0x08090a0b0c0d0e0f

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; UpdateSHA512ni(Ipp64u digest[], Ipp8u dataBlock[], int datalen, Ipp64u K_512[])
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM UpdateSHA512ni,PUBLIC
        USES_GPR esi,edi,ebx,ebp

        mov   ebp, esp ; save original esp to use it to reach parameters

        %xdefine pDigest [ebp + ARG_1 + 0*sizeof(dword)] ; pointer to the in/out digest
        %xdefine pMsg    [ebp + ARG_1 + 1*sizeof(dword)] ; pointer to the inp message
        %xdefine msgLen  [ebp + ARG_1 + 2*sizeof(dword)] ; message length
        %xdefine pTbl    [ebp + ARG_1 + 3*sizeof(dword)] ; pointer to SHA512 table of constants

        %xdefine arg_hash       edi  ; 1st arg
        %xdefine arg_msg        esi  ; 2nd arg
        %xdefine arg_num_blks   edx  ; 3rd arg
        %xdefine arg_sha512_k   ebx  ; 4th arg

;
; stack frame
;
%xdefine abef_save  eax
%xdefine cdgh_save  eax+sizeof(yword)
%xdefine frame_size sizeof(yword)+sizeof(yword)

        ; get a 16-byte aligned pointer inside the local stack
        sub      esp, (frame_size+16)
        lea      eax, [esp+16]
        and      eax, -16

        mov      arg_num_blks, msgLen

        ;; hash infrastructure (caller) sends the block size in bytes
        ;; the algorithm requires the number of 2^7=128 byte blocks
        shr             arg_num_blks, 7
        or              arg_num_blks, arg_num_blks
        je              .done_hash

        mov      arg_hash, pDigest
        mov      arg_msg, pMsg
        mov      arg_sha512_k, pTbl

        LD_ADDR ecx, SHA512_SHUFF_MASK_AVX

;; ===========================================================
;; NOTE about comment format:
;;
;;      ymm = a b c d
;;           ^       ^
;;           |       |
;;      MSB--+       +--LSB
;;
;;      a - most significant word in `ymm`
;;      d - least significant word in `ymm`
;; ===========================================================

        ;; load current hash value and transform
        vmovdqu         ymm4, [arg_hash]
        vmovdqu         ymm5, [arg_hash + 32]
        ;; ymm4 = D C B A, ymm5 = H G F E
        vperm2i128      ymm6, ymm4, ymm5, 0x20
        vperm2i128      ymm7, ymm4, ymm5, 0x31
        ;; ymm6 = F E B A, ymm7 = H G D C
        vpermq          ymm1, ymm6, 0x1b
        vpermq          ymm2, ymm7, 0x1b
        ;; ymm1 = A B E F, ymm2 = C D G H

align IPP_ALIGN_FACTOR
.block_loop:

        vbroadcasti128  ymm7, [ecx]

        vmovdqu [abef_save], ymm1    ;; ABEF
        vmovdqu [cdgh_save], ymm2    ;; CDGH

        ;; R0 - R3
        vmovdqu         ymm0, [arg_msg + 0 * 32]
        vpshufb         ymm3, ymm0, ymm7                ;; ymm0/ymm3 = W[0..3]
        vpaddq          ymm0, ymm3, [arg_sha512_k + 0 * 32]
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0

        ;; R4 - R7
        vmovdqu         ymm0, [arg_msg + 1 * 32]
        vpshufb         ymm4, ymm0, ymm7                ;; ymm0/ymm4 = W[4..7]
        vpaddq          ymm0, ymm4, [arg_sha512_k + 1 * 32]
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[0..3] + S0(W[1..4])

        ;; R8 - R11
        vmovdqu         ymm0, [arg_msg + 2 * 32]
        vpshufb         ymm5, ymm0, ymm7                ;; ymm0/ymm5 = W[8..11]
        vpaddq          ymm0, ymm5, [arg_sha512_k + 2 * 32]
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[4..7] + S0(W[5..8])

        ;; R12 - R15
        vmovdqu         ymm0, [arg_msg + 3 * 32]
        vpshufb         ymm6, ymm0, ymm7                ;; ymm0/ymm6 = W[12..15]
        vpermq          ymm0, ymm6, 0x1b                ;; ymm0 = W[12] W[13] W[14] W[15]
        vpermq          ymm7, ymm5, 0x39                ;; ymm7 = W[8]  W[11] W[10] W[9]
        vpblendd        ymm0, ymm0, ymm7, 0x3f          ;; ymm0 = W[12] W[11] W[10] W[9]
        vpaddq          ymm3, ymm3, ymm0                ;; ymm3 = W[0..3] + S0(W[1..4]) + W[9..12]
        vsha512msg2     ymm3, ymm6                      ;; W[16..19] = ymm3 + S1(W[14..17])
        vpaddq          ymm0, ymm6, [arg_sha512_k + 3 * 32]
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[8..11] + S0(W[9..12])

%assign I 4

%rep 3
        ;; R16 - R19, R32 - R35, R48 - R51
        vpermq          ymm0, ymm3, 0x1b                ;; ymm0 = W[16] W[17] W[18] W[19]
        vpermq          ymm7, ymm6, 0x39                ;; ymm7 = W[12] W[15] W[14] W[13]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[16] W[15] W[14] W[13]
        vpaddq          ymm0, ymm3, [arg_sha512_k + I * 32]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[4..7] + S0(W[5..8]) + W[13..16]
        vsha512msg2     ymm4, ymm3                      ;; W[20..23] = ymm4 + S1(W[18..21])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[12..15] + S0(W[13..16])
%assign I (I + 1)

        ;; R20 - R23, R36 - R39, R52 - R55
        vpermq          ymm0, ymm4, 0x1b                ;; ymm0 = W[20] W[21] W[22] W[23]
        vpermq          ymm7, ymm3, 0x39                ;; ymm7 = W[16] W[19] W[18] W[17]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[20] W[19] W[18] W[17]
        vpaddq          ymm0, ymm4, [arg_sha512_k + I * 32]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[8..11] + S0(W[9..12]) + W[17..20]
        vsha512msg2     ymm5, ymm4                      ;; W[24..27] = ymm5 + S1(W[22..25])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[16..19] + S0(W[17..20])
%assign I (I + 1)

        ;; R24 - R27, R40 - R43, R56 - R59
        vpermq          ymm0, ymm5, 0x1b                ;; ymm0 = W[24] W[25] W[26] W[27]
        vpermq          ymm7, ymm4, 0x39                ;; ymm7 = W[20] W[23] W[22] W[21]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[24] W[23] W[22] W[21]
        vpaddq          ymm0, ymm5, [arg_sha512_k + I * 32]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[12..15] + S0(W[13..16]) + W[21..24]
        vsha512msg2     ymm6, ymm5                      ;; W[28..31] = ymm6 + S1(W[26..29])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[20..23] + S0(W[21..24])
%assign I (I + 1)

        ;; R28 - R31, R44 - R47, R60 - R63
        vpermq          ymm0, ymm6, 0x1b                ;; ymm0 = W[28] W[29] W[30] W[31]
        vpermq          ymm7, ymm5, 0x39                ;; ymm7 = W[24] W[27] W[26] W[25]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[28] W[27] W[26] W[25]
        vpaddq          ymm0, ymm6, [arg_sha512_k + I * 32]
        vpaddq          ymm3, ymm3, ymm7                ;; ymm3 = W[16..19] + S0(W[17..20]) + W[25..28]
        vsha512msg2     ymm3, ymm6                      ;; W[32..35] = ymm3 + S1(W[30..33])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[24..27] + S0(W[25..28])
%assign I (I + 1)
%endrep

        ;; R64 - R67
        vpermq          ymm0, ymm3, 0x1b                ;; ymm0 = W[64] W[65] W[66] W[67]
        vpermq          ymm7, ymm6, 0x39                ;; ymm7 = W[60] W[63] W[62] W[61]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[64] W[63] W[62] W[61]
        vpaddq          ymm0, ymm3, [arg_sha512_k + 16 * 32]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[52..55] + S0(W[53..56]) + W[61..64]
        vsha512msg2     ymm4, ymm3                      ;; W[64..67] = ymm4 + S1(W[62..65])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[60..63] + S0(W[61..64])

        ;; R68 - R71
        vpermq          ymm0, ymm4, 0x1b                ;; ymm0 = W[68] W[69] W[70] W[71]
        vpermq          ymm7, ymm3, 0x39                ;; ymm7 = W[64] W[67] W[66] W[65]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[68] W[67] W[66] W[65]
        vpaddq          ymm0, ymm4, [arg_sha512_k + 17 * 32]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[56..59] + S0(W[57..60]) + W[65..68]
        vsha512msg2     ymm5, ymm4                      ;; W[68..71] = ymm5 + S1(W[66..69])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0

        ;; R72 - R75
        vpermq          ymm0, ymm5, 0x1b                ;; ymm0 = W[72] W[73] W[74] W[75]
        vpermq          ymm7, ymm4, 0x39                ;; ymm7 = W[68] W[71] W[70] W[69]
        vpblendd        ymm7, ymm0, ymm7, 0x3f          ;; ymm7 = W[72] W[71] W[70] W[69]
        vpaddq          ymm0, ymm5, [arg_sha512_k + 18 * 32]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[60..63] + S0(W[61..64]) + W[69..72]
        vsha512msg2     ymm6, ymm5                      ;; W[72..75] = ymm6 + S1(W[70..73])
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0

        ;; R76 - R79
        vpaddq          ymm0, ymm6, [arg_sha512_k + 19 * 32]
        vsha512rnds2    ymm2, ymm1, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm1, ymm2, xmm0

        ;; update hash value
        vpaddq          ymm1, ymm1, [abef_save]
        vpaddq          ymm2, ymm2, [cdgh_save]
        add             arg_msg, 4 * 32
        dec             arg_num_blks
        jnz             .block_loop

        ;; store the hash value back in memory
        ;;     ymm1 = ABEF
        ;;     ymm2 = CDGH
        vperm2i128      ymm6, ymm1, ymm2, 0x31
        vperm2i128      ymm7, ymm1, ymm2, 0x20
        vpermq          ymm6, ymm6, 0xb1                ;; ymm6 = D C B A
        vpermq          ymm7, ymm7, 0xb1                ;; ymm7 = H G F E
        vmovdqu         [arg_hash + 0*32], ymm6
        vmovdqu         [arg_hash + 1*32], ymm7

.done_hash:
        add   esp, (frame_size+16)
        REST_GPR
        ret
ENDFUNC UpdateSHA512ni

%endif    ;; _IPP >= _IPP_H9
%endif    ;; _FEATURE_ON_ / _FEATURE_TICKTOCK_
%endif    ;; _ENABLE_ALG_SHA512_
