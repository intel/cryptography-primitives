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
;               Message block processing and key setup for SM4 algorithm
;               (former SMS4)
;
;     Content:
;        
;

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%if (_IPP32E >= _IPP32E_L9)


segment .data align=IPP_ALIGN_FACTOR

align 16
sms4_fk:
dd 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc

align 16
sms4_ck:
dd 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
dd 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
dd 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
dd 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
dd 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
dd 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
dd 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
dd 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279

in_shufb:
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

out_shufb:
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00

segment .text align=IPP_ALIGN_FACTOR

;*************************************************************************
;* void cpSMS4_SetRoundKeys_ni(Ipp32u* pRoundKey, const Ipp8u* pSecretKey)
;*************************************************************************
align IPP_ALIGN_FACTOR
IPPASM cpSMS4_SetRoundKeys_ni,PUBLIC
    ; "COMP_ABI 2" definitely overwrites rdi, rsi
    USES_GPR rsi,rdi
    USES_XMM_AVX xmm0
    ;; 2 arguments
    COMP_ABI 2

    ;; rdi = pointer to the round key
    ;; rsi = pointer to the secret key
    ;;
    ;; "COMP_ABI >= 2" makes sure these registers are always correct
    %define pRoundKey    rdi
    %define pSecretKey   rsi

    vmovdqu xmm0, [pSecretKey]
    vpshufb xmm0, xmm0, [rel in_shufb]
    vpxor   xmm0, [rel sms4_fk]

    %assign i 0
    %rep 8
        vsm4key4 xmm0, xmm0, [rel sms4_ck + 16*i]
        vmovdqu [pRoundKey + 16*i], xmm0
    %assign i (i + 1)
    %endrep

    REST_XMM_AVX
    REST_GPR
    ret
ENDFUNC cpSMS4_SetRoundKeys_ni

;******************************************************************************
;* void cpSMS4_ECB_ni(Ipp8u* pOut, const Ipp8u* pInp, const Ipp32u* pRoundKey)
;*****************************************************************************
align IPP_ALIGN_FACTOR
IPPASM cpSMS4_ECB_ni,PUBLIC
    ; "COMP_ABI 3" definitely overwrites rdi, rsi, rdx
    USES_GPR rsi,rdi,rdx
    USES_XMM_AVX xmm0
    ;; 3 arguments
    COMP_ABI 3

    ;; rdi = pointer to the output
    ;; rsi = pointer to the secret key
    ;; rdx = pointer to the round key
    ;;
    ;; "COMP_ABI >= 3" makes sure these registers are always correct
    %define pOut        rdi
    %define pInp        rsi
    %define pRoundKey   rdx

    vmovdqu xmm0, [pInp]
    vpshufb xmm0, xmm0, [rel in_shufb]

    %assign i 0
    %rep 8
        vsm4rnds4 xmm0, xmm0, [pRoundKey + 16*i]
    %assign i (i + 1)
    %endrep

    vpshufb xmm0, [rel out_shufb]
    vmovdqu [pOut], xmm0

    REST_XMM_AVX
    REST_GPR
    ret
ENDFUNC cpSMS4_ECB_ni

;*********************************************************************************
;* void cpSMS4_ECB_ni_256(Ipp8u* pOut, const Ipp8u* pInp, const Ipp32u* pRoundKey)
;*********************************************************************************
align IPP_ALIGN_FACTOR
IPPASM cpSMS4_ECB_ni_256,PUBLIC
    ; "COMP_ABI 3" definitely overwrites rdi, rsi, rdx
    USES_GPR rsi,rdi,rdx
    USES_XMM_AVX ymm0, ymm1
    ;; 3 arguments
    COMP_ABI 3

    ;; rdi = pointer to the output
    ;; rsi = pointer to the secret key
    ;; rdx = pointer to the round key
    ;;
    ;; "COMP_ABI >= 3" makes sure these registers are always correct
    %define pOut        rdi
    %define pInp        rsi
    %define pRoundKey   rdx

    vmovdqu ymm0, [pInp]
    vpshufb ymm0, ymm0, [rel in_shufb]

    %assign i 0
    %rep 8
        vbroadcasti128 ymm1, [pRoundKey + 16*i]
        vsm4rnds4 ymm0, ymm0, ymm1
    %assign i (i + 1)
    %endrep

    vpshufb ymm0, [rel out_shufb]
    vmovdqu [pOut], ymm0

    REST_XMM_AVX
    REST_GPR
    ret
ENDFUNC cpSMS4_ECB_ni_256

%endif    ;; _IPP32E >= _IPP32E_L9
