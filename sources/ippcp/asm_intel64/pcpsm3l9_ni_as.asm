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
;
;     Purpose:  Cryptography Primitive.
;               Message block processing according to SM3 with SM3 instructions
;
;     Content:
;        UpdateSM3ni
;

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%if (_ENABLE_ALG_SM3_)
%if (_IPP32E >= _IPP32E_L9)

%xdefine hPtr    rdi
%xdefine mPtr    rsi
%xdefine mLen    rdx

segment .data align=IPP_ALIGN_FACTOR

align 16
SHUFF_MASK:
    db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

segment .text align=IPP_ALIGN_FACTOR

; ***************************************************************************
; Create 4 x 32-bit new words of message schedule W[] using SM3 instructions
; ***************************************************************************
%macro SM3MSG 7
%define %%W03_00        %1      ;; [in] XMM register with W[0..3]
%define %%W07_04        %2      ;; [in] XMM register with W[4..7]
%define %%W11_08        %3      ;; [in] XMM register with W[8..11]
%define %%W15_12        %4      ;; [in] XMM register with W[12..15]
%define %%W19_16        %5      ;; [out] XMM register with W[19..16]
%define %%T1            %6      ;; [clobbered] XMM register
%define %%T2            %7      ;; [clobbered] XMM register

%define %%T3 %%W19_16

    vpalignr        %%T3, %%W11_08, %%W07_04, 3*4   ;; xmm8 = W10 W9 W8 W7
    vpsrldq         %%T1, %%W15_12, 4               ;; xmm9 = 0 W15 W14 W13
    vsm3msg1        %%T3, %%T1, %%W03_00            ;; xmm8 = WTMP3 WTMP2 WTMP1 WTMP0
    vpalignr        %%T1, %%W07_04, %%W03_00, 3*4   ;; xmm9 = W6 W5 W4 W3
    vpalignr        %%T2, %%W15_12, %%W11_08, 2*4   ;; xmm1 = W13 W12 W11 W10
    vsm3msg2        %%T3, %%T1, %%T2                ;; xmm8 = W19 W18 W17 W16
%endmacro

; ***************************************************************************
; Performs 4 rounds of SM3 algorithm
; - consumes 4 words of message schedule W[]
; - updates SM3 state registers: ABEF and CDGH
; ***************************************************************************
%macro SM3ROUNDS4 6
%define %%ABEF          %1      ;; [in/out] XMM register with ABEF registers
%define %%CDGH          %2      ;; [in/out] XMM register with CDGH registers
%define %%W03_00        %3      ;; [in] XMM register with W[8..11]
%define %%W07_04        %4      ;; [in] XMM register with W[12..15]
%define %%T1            %5      ;; [clobbered] XMM register
%define %%R             %6      ;; [in] round number

    vpunpcklqdq     %%T1, %%W03_00, %%W07_04        ;; T1 = W5 W4 W1 W0
    vsm3rnds2       %%CDGH, %%ABEF, %%T1, %%R       ;; CDGH = updated ABEF // 2 rounds
    vpunpckhqdq     %%T1, %%W03_00, %%W07_04        ;; T1 = W7 W6 W3 W2
    vsm3rnds2       %%ABEF, %%CDGH, %%T1, (%%R + 2) ;; ABEF = updated CDGH // 2 rounds
%endmacro

;********************************************************************
;* void UpdateSM3ni(uint32_t hash[8],
;                const uint32_t msg[16], int msgLen, const uint32_t* K_SM3)
;********************************************************************
align IPP_ALIGN_FACTOR
IPPASM UpdateSM3ni,PUBLIC
        USES_GPR rsi,rdi,rdx,rcx
        USES_XMM
        COMP_ABI 4

;; rdi = hash
;; rsi = data buffer
;; rdx = data buffer length (bytes)
;; rcx = address of SM3 constants (not used)

%xdefine MBS_SM3    (64)

    movsxd   rdx, edx

    vmovdqu         xmm6, [hPtr]
    vmovdqu         xmm7, [hPtr + 16]
    ;; xmm6 = D C B A, xmm7 = H G F E

    vpshufd         xmm0, xmm6, 0x1B        ;; xmm0 = A B C D
    vpshufd         xmm1, xmm7, 0x1B        ;; xmm1 = E F G H
    vpunpckhqdq     xmm6, xmm1, xmm0        ;; xmm6 = A B E F
    vpunpcklqdq     xmm7, xmm1, xmm0        ;; xmm7 = C D G H
    vpsrld          xmm2, xmm7, 9
    vpslld          xmm3, xmm7, 23
    vpxor           xmm1, xmm2, xmm3        ;; xmm1 = xmm2 ^ xmm3 = ROL32(CDGH, 23)
    vpsrld          xmm4, xmm7, 19
    vpslld          xmm5, xmm7, 13
    vpxor           xmm0, xmm4, xmm5        ;; xmm0 = xmm2 ^ xmm3 = ROL32(CDGH, 13)
    vpblendd        xmm7, xmm1, xmm0, 0x3   ;; xmm7 = ROL32(C, 23) ROL32(D, 23) ROL32(G, 13) ROL32(H, 13)

    vmovdqa         xmm12, [rel SHUFF_MASK]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; process data block
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align IPP_ALIGN_FACTOR
.main_loop:
    vmovdqa         xmm10, xmm6
    vmovdqa         xmm11, xmm7

    ;; prepare W[0..15] - read and shuffle the data
    vmovdqu         xmm2, [mPtr + 0*16]
    vmovdqu         xmm3, [mPtr + 1*16]
    vmovdqu         xmm4, [mPtr + 2*16]
    vmovdqu         xmm5, [mPtr + 3*16]
    vpshufb         xmm2, xmm2, xmm12                               ;; xmm2 = W03 W02 W01 W00
    vpshufb         xmm3, xmm3, xmm12                               ;; xmm3 = W07 W06 W05 W04
    vpshufb         xmm4, xmm4, xmm12                               ;; xmm4 = W11 W10 W09 W08
    vpshufb         xmm5, xmm5, xmm12                               ;; xmm5 = W15 W14 W13 W12

    SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W19 W18 W17 W16
    SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 0

    vmovdqa         xmm2, xmm8
    SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W23 W22 W21 W20
    SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 4

    vmovdqa         xmm3, xmm8
    SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W27 W26 W25 W24
    SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 8

    vmovdqa         xmm4, xmm8
    SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W31 W30 W29 W28
    SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 12

    vmovdqa         xmm5, xmm8
    SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W35 W34 W33 W32
    SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 16

    vmovdqa         xmm2, xmm8
    SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W39 W38 W37 W36
    SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 20

    vmovdqa         xmm3, xmm8
    SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W43 W42 W41 W40
    SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 24

    vmovdqa         xmm4, xmm8
    SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W47 W46 W45 W44
    SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 28

    vmovdqa         xmm5, xmm8
    SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W51 W50 W49 W48
    SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 32

    vmovdqa         xmm2, xmm8
    SM3MSG          xmm3, xmm4, xmm5, xmm2, xmm8, xmm9, xmm1        ;; xmm8 = W55 W54 W53 W52
    SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 36

    vmovdqa         xmm3, xmm8
    SM3MSG          xmm4, xmm5, xmm2, xmm3, xmm8, xmm9, xmm1        ;; xmm8 = W59 W58 W57 W56
    SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 40

    vmovdqa         xmm4, xmm8
    SM3MSG          xmm5, xmm2, xmm3, xmm4, xmm8, xmm9, xmm1        ;; xmm8 = W63 W62 W61 W60
    SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 44

    vmovdqa         xmm5, xmm8
    SM3MSG          xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm1        ;; xmm8 = W67 W66 W65 W64
    SM3ROUNDS4      xmm6, xmm7, xmm2, xmm3, xmm1, 48

    vmovdqa         xmm2, xmm8
    SM3ROUNDS4      xmm6, xmm7, xmm3, xmm4, xmm1, 52

    SM3ROUNDS4      xmm6, xmm7, xmm4, xmm5, xmm1, 56

    SM3ROUNDS4      xmm6, xmm7, xmm5, xmm2, xmm1, 60

    ;; update the hash value (xmm6, xmm7) and process the next message block
    vpxor           xmm6, xmm6, xmm10
    vpxor           xmm7, xmm7, xmm11
    add             mPtr, MBS_SM3
    sub             mLen, MBS_SM3
    jne      .main_loop

    ;; store the hash value back in memory
    vpslld          xmm2, xmm7, 9
    vpsrld          xmm3, xmm7, 23
    vpxor           xmm1, xmm2, xmm3        ;; xmm1 = xmm2 ^ xmm3 = ROL32(CDGH, 9)
    vpslld          xmm4, xmm7, 19
    vpsrld          xmm5, xmm7, 13
    vpxor           xmm0, xmm4, xmm5        ;; xmm0 = xmm2 ^ xmm3 = ROL32(CDGH, 19)
    vpblendd        xmm7, xmm1, xmm0, 0x3   ;; xmm7 = ROL32(C, 9) ROL32(D, 9) ROL32(G, 19) ROL32(H, 19)
    vpshufd         xmm0, xmm6, 0x1B        ;; xmm0 = F E B A
    vpshufd         xmm1, xmm7, 0x1B        ;; xmm1 = H G D C

    vpunpcklqdq     xmm6, xmm0, xmm1        ;; xmm6 = D C B A
    vpunpckhqdq     xmm7, xmm0, xmm1        ;; xmm7 = H G F E

    vmovdqu         [hPtr], xmm6
    vmovdqu         [hPtr + 16], xmm7

   REST_XMM
   REST_GPR
   ret
ENDFUNC UpdateSM3ni

%endif    ;; _IPP32E >= _IPP32E_L9
%endif    ;; _ENABLE_ALG_SM3_
