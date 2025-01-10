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
%include "ia_32e.inc"
%include "ia_32e_regs.inc"
%include "pcpvariant.inc"

%if (_ENABLE_ALG_SHA512_)
%if (_ENABLE_ALG_SHA512_ == _FEATURE_ON_) || (_ENABLE_ALG_SHA512_ == _FEATURE_TICKTOCK_)
%if (_IPP32E >= _IPP32E_L9 )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

segment .data align=IPP_ALIGN_FACTOR

align IPP_ALIGN_FACTOR
SHA512_SHUFF_MASK_AVX:
       dq 0x0001020304050607, 0x08090a0b0c0d0e0f

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

segment .text align=IPP_ALIGN_FACTOR

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; UpdateSHA512ni(Ipp64u digest[], Ipp8u dataBlock[], int datalen, Ipp64u K_512[])
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM UpdateSHA512ni,PUBLIC

        ;; "COMP_ABI 4" definitely overwrites rdi, rsi, rdx, rcx
        ;; rsi, rdi : non volatile on Windows x64, must be saved/restored before return
        ;; rdx, rcx : volatile on both Windows and Linux (System V) x64
        USES_GPR rsi,rdi,rdx,rcx

        ;; xmm6-xmm15 are non volatile on Windows x64
        ;; ymm10 is not used by UpdateSHA512ni, xmm10 is skipped
        USES_XMM_AVX xmm6,xmm7,xmm8,xmm9,xmm11,xmm12,xmm13,xmm14,xmm15

        ;; 4 arguments
        COMP_ABI 4
        ;;
        ;; rdi = pointer to the updated hash
        ;; rsi = pointer to the data block
        ;; rdx = data block length in bytes
        ;; rcx = pointer to the SHA512 constant
        ;;
        ;; "COMP_ABI >=4" makes sure these registers are always correct
        %define arg_hash        rdi
        %define arg_msg         rsi
        %define arg_num_blks    rdx
        %define arg_sha512_k    rcx

        ;; hash infrastructure (caller) sends the block size in bytes
        ;; the algorithm requires the number of 2^7=128 byte blocks
        shr             arg_num_blks, 7
        or              arg_num_blks, arg_num_blks
        je              .done_hash

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

        vbroadcasti128  ymm15, [rel SHA512_SHUFF_MASK_AVX]

        ;; load current hash value and transform
        vmovdqu         ymm0, [arg_hash]
        vmovdqu         ymm1, [arg_hash + 32]
        ;; ymm0 = D C B A, ymm1 = H G F E
        vperm2i128      ymm2, ymm0, ymm1, 0x20
        vperm2i128      ymm3, ymm0, ymm1, 0x31
        ;; ymm2 = F E B A, ymm3 = H G D C
        vpermq          ymm13, ymm2, 0x1b
        vpermq          ymm14, ymm3, 0x1b
        ;; ymm13 = A B E F, ymm14 = C D G H

        mov             rax, arg_sha512_k

align IPP_ALIGN_FACTOR
.block_loop:
        vmovdqa         ymm11, ymm13    ;; ABEF
        vmovdqa         ymm12, ymm14    ;; CDGH

        ;; R0 - R3
        vmovdqu         ymm0, [arg_msg + 0 * 32]
        vpshufb         ymm3, ymm0, ymm15               ;; ymm0/ymm3 = W[0..3]
        vpaddq          ymm0, ymm3, [rax + 0 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R4 - R7
        vmovdqu         ymm0, [arg_msg + 1 * 32]
        vpshufb         ymm4, ymm0, ymm15               ;; ymm0/ymm4 = W[4..7]
        vpaddq          ymm0, ymm4, [rax + 1 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[0..3] + S0(W[1..4])

        ;; R8 - R11
        vmovdqu         ymm0, [arg_msg + 2 * 32]
        vpshufb         ymm5, ymm0, ymm15               ;; ymm0/ymm5 = W[8..11]
        vpaddq          ymm0, ymm5, [rax + 2 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[4..7] + S0(W[5..8])

        ;; R12 - R15
        vmovdqu         ymm0, [arg_msg + 3 * 32]
        vpshufb         ymm6, ymm0, ymm15               ;; ymm0/ymm6 = W[12..15]
        vpaddq          ymm0, ymm6, [rax + 3 * 32]
        vpermq          ymm8, ymm6, 0x1b                ;; ymm8 = W[12] W[13] W[14] W[15]
        vpermq          ymm9, ymm5, 0x39                ;; ymm9 = W[8]  W[11] W[10] W[9]
        vpblendd        ymm8, ymm8, ymm9, 0x3f          ;; ymm8 = W[12] W[11] W[10] W[9]
        vpaddq          ymm3, ymm3, ymm8                ;; ymm3 = W[0..3] + S0(W[1..4]) + W[9..12]
        vsha512msg2     ymm3, ymm6                      ;; W[16..19] = ymm3 + S1(W[14..17])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[8..11] + S0(W[9..12])

%assign I 4

%rep 3
        ;; R16 - R19, R32 - R35, R48 - R51
        vpaddq          ymm0, ymm3, [rax + I * 32]
        vpermq          ymm8, ymm3, 0x1b                ;; ymm8 = W[16] W[17] W[18] W[19]
        vpermq          ymm9, ymm6, 0x39                ;; ymm9 = W[12] W[15] W[14] W[13]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[16] W[15] W[14] W[13]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[4..7] + S0(W[5..8]) + W[13..16]
        vsha512msg2     ymm4, ymm3                      ;; W[20..23] = ymm4 + S1(W[18..21])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[12..15] + S0(W[13..16])
%assign I (I + 1)

        ;; R20 - R23, R36 - R39, R52 - R55
        vpaddq          ymm0, ymm4, [rax + I * 32]
        vpermq          ymm8, ymm4, 0x1b                ;; ymm8 = W[20] W[21] W[22] W[23]
        vpermq          ymm9, ymm3, 0x39                ;; ymm9 = W[16] W[19] W[18] W[17]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[20] W[19] W[18] W[17]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[8..11] + S0(W[9..12]) + W[17..20]
        vsha512msg2     ymm5, ymm4                      ;; W[24..27] = ymm5 + S1(W[22..25])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm3, xmm4                      ;; ymm3 = W[16..19] + S0(W[17..20])
%assign I (I + 1)

        ;; R24 - R27, R40 - R43, R56 - R59
        vpaddq          ymm0, ymm5, [rax + I * 32]
        vpermq          ymm8, ymm5, 0x1b                ;; ymm8 = W[24] W[25] W[26] W[27]
        vpermq          ymm9, ymm4, 0x39                ;; ymm9 = W[20] W[23] W[22] W[21]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[24] W[23] W[22] W[21]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[12..15] + S0(W[13..16]) + W[21..24]
        vsha512msg2     ymm6, ymm5                      ;; W[28..31] = ymm6 + S1(W[26..29])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm4, xmm5                      ;; ymm4 = W[20..23] + S0(W[21..24])
%assign I (I + 1)

        ;; R28 - R31, R44 - R47, R60 - R63
        vpaddq          ymm0, ymm6, [rax + I * 32]
        vpermq          ymm8, ymm6, 0x1b                ;; ymm8 = W[28] W[29] W[30] W[31]
        vpermq          ymm9, ymm5, 0x39                ;; ymm9 = W[24] W[27] W[26] W[25]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[28] W[27] W[26] W[25]
        vpaddq          ymm3, ymm3, ymm7                ;; ymm3 = W[16..19] + S0(W[17..20]) + W[25..28]
        vsha512msg2     ymm3, ymm6                      ;; W[32..35] = ymm3 + S1(W[30..33])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm5, xmm6                      ;; ymm5 = W[24..27] + S0(W[25..28])
%assign I (I + 1)
%endrep

        ;; R64 - R67
        vpaddq          ymm0, ymm3, [rax + 16 * 32]
        vpermq          ymm8, ymm3, 0x1b                ;; ymm8 = W[64] W[65] W[66] W[67]
        vpermq          ymm9, ymm6, 0x39                ;; ymm9 = W[60] W[63] W[62] W[61]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[64] W[63] W[62] W[61]
        vpaddq          ymm4, ymm4, ymm7                ;; ymm4 = W[52..55] + S0(W[53..56]) + W[61..64]
        vsha512msg2     ymm4, ymm3                      ;; W[64..67] = ymm4 + S1(W[62..65])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0
        vsha512msg1     ymm6, xmm3                      ;; ymm6 = W[60..63] + S0(W[61..64])

        ;; R68 - R71
        vpaddq          ymm0, ymm4, [rax + 17 * 32]
        vpermq          ymm8, ymm4, 0x1b                ;; ymm8 = W[68] W[69] W[70] W[71]
        vpermq          ymm9, ymm3, 0x39                ;; ymm9 = W[64] W[67] W[66] W[65]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[68] W[67] W[66] W[65]
        vpaddq          ymm5, ymm5, ymm7                ;; ymm5 = W[56..59] + S0(W[57..60]) + W[65..68]
        vsha512msg2     ymm5, ymm4                      ;; W[68..71] = ymm5 + S1(W[66..69])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R72 - R75
        vpaddq          ymm0, ymm5, [rax + 18 * 32]
        vpermq          ymm8, ymm5, 0x1b                ;; ymm8 = W[72] W[73] W[74] W[75]
        vpermq          ymm9, ymm4, 0x39                ;; ymm9 = W[68] W[71] W[70] W[69]
        vpblendd        ymm7, ymm8, ymm9, 0x3f          ;; ymm7 = W[72] W[71] W[70] W[69]
        vpaddq          ymm6, ymm6, ymm7                ;; ymm6 = W[60..63] + S0(W[61..64]) + W[69..72]
        vsha512msg2     ymm6, ymm5                      ;; W[72..75] = ymm6 + S1(W[70..73])
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; R76 - R79
        vpaddq          ymm0, ymm6, [rax + 19 * 32]
        vsha512rnds2    ymm12, ymm11, xmm0
        vperm2i128      ymm0, ymm0, ymm0, 0x01
        vsha512rnds2    ymm11, ymm12, xmm0

        ;; update hash value
        vpaddq          ymm14, ymm14, ymm12
        vpaddq          ymm13, ymm13, ymm11
        add             arg_msg, 4 * 32
        dec             arg_num_blks
        jnz             .block_loop

        ;; store the hash value back in memory
        ;;     ymm13 = ABEF
        ;;     ymm14 = CDGH
        vperm2i128      ymm1, ymm13, ymm14, 0x31
        vperm2i128      ymm2, ymm13, ymm14, 0x20
        vpermq          ymm1, ymm1, 0xb1                ;; ymm1 = D C B A
        vpermq          ymm2, ymm2, 0xb1                ;; ymm2 = H G F E
        vmovdqu         [arg_hash + 0*32], ymm1
        vmovdqu         [arg_hash + 1*32], ymm2

.done_hash:
   REST_XMM_AVX
   REST_GPR
   ret
ENDFUNC UpdateSHA512ni

%endif    ;; _IPP32E_L9 and above
%endif    ;;  %if (_ENABLE_ALG_SHA512_ == _FEATURE_ON_) || (_ENABLE_ALG_SHA512_ == _FEATURE_TICKTOCK_)
%endif    ;; _ENABLE_ALG_SHA512_
