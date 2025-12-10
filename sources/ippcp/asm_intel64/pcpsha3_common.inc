;=========================================================================
; Copyright (C) 2025 Intel Corporation
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
; Utility macros and defines for SHA3 and SHAKE functions
;

%ifndef _CP_SHA3_COMMON_INC_
%define _CP_SHA3_COMMON_INC_
%include "os.inc"

;; Arguments assignment for SHA3 and SHAKE kernels after COMP_ABI macro call
%define arg1  rdi
%define arg2  rsi
%define arg3  rdx
%define arg4  rcx
%define arg5  r8
%define arg5d r8d
%define arg6  r9
%define arg7  [rsp + ARG_7]
%define arg8  [rsp + ARG_8]
%define arg9  [rsp + ARG_9]
%define arg10 [rsp + ARG_10]

;; SHA3 rates
%define SHA3_256_RATE 136
%define SHA3_384_RATE 104
%define SHA3_512_RATE 72
%define SHAKE128_RATE 168
%define SHAKE256_RATE 136

;; SHA3 digest sizes
%define SHA3_256_DIGEST_SZ 32
%define SHA3_384_DIGEST_SZ 48
%define SHA3_512_DIGEST_SZ 64

;; SHA3 multi-rate padding byte (added after the message)
%define SHA3_MRATE_PADDING  0x06
%define SHAKE_MRATE_PADDING 0x1F

%define APPEND(a,b) a %+ b

;; Absorb input bytes into state registers
%macro ABSORB_BYTES 3
%define %%INPUT         %1
%define %%OFFSET        %2
%define %%RATE          %3

        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*0]
        vpxorq  ymm0, ymm0, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*1]
        vpxorq  ymm1, ymm1, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*2]
        vpxorq  ymm2, ymm2, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*3]
        vpxorq  ymm3, ymm3, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*4]
        vpxorq  ymm4, ymm4, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*5]
        vpxorq  ymm5, ymm5, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*6]
        vpxorq  ymm6, ymm6, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*7]
        vpxorq  ymm7, ymm7, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*8]
        vpxorq  ymm8, ymm8, ymm31
        ;; SHA3_512 RATE, 72 bytes

%if %%RATE > SHA3_512_RATE
        ;; SHA3_384 RATE
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*9]
        vpxorq  ymm9, ymm9, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*10]
        vpxorq  ymm10, ymm10, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*11]
        vpxorq  ymm11, ymm11, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*12]
        vpxorq  ymm12, ymm12, ymm31
%endif
%if %%RATE > SHA3_384_RATE
        ;; SHA3_256 and SHAKE256 RATE
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*13]
        vpxorq  ymm13, ymm13, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*14]
        vpxorq  ymm14, ymm14, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*15]
        vpxorq  ymm15, ymm15, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*16]
        vpxorq  ymm16, ymm16, ymm31
%endif
%if %%RATE > SHA3_256_RATE
        ;; SHAKE128 RATE
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*17]
        vpxorq  ymm17, ymm17, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*18]
        vpxorq  ymm18, ymm18, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*19]
        vpxorq  ymm19, ymm19, ymm31
        vmovq   xmm31, [%%INPUT + %%OFFSET + 8*20]
        vpxorq  ymm20, ymm20, ymm31
%endif
%endmacro

;; Store state from SIMD registers to memory
;; State registers are kept in xmm0-xmm24
%macro STATE_EXTRACT 3
%define %%OUTPUT        %1      ; [in] destination pointer
%define %%OFFSET        %2      ; [in] destination offset
%define %%N             %3      ; [in] numerical values, number of 8-byte state registers to save

%assign I 0
%rep %%N
        vmovq   [%%OUTPUT + %%OFFSET + 8*I], APPEND(xmm, I)
%assign I (I + 1)
%endrep
%endmacro

;; Absorb input bytes into x4 state registers
;;   ymm0-ymm24          [in] x4 state registers
;;   ymm30-ymm31  [clobbered] used as a temporary registers
%macro ABSORB_BYTES_x4 6
%define %%INPUT0        %1
%define %%INPUT1        %2
%define %%INPUT2        %3
%define %%INPUT3        %4
%define %%OFFSET        %5
%define %%RATE          %6

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*0]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*0], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*0]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*0], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm0, ymm0, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*1]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*1], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*1]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*1], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm1, ymm1, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*2]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*2], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*2]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*2], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm2, ymm2, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*3]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*3], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*3]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*3], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm3, ymm3, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*4]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*4], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*4]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*4], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm4, ymm4, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*5]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*5], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*5]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*5], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm5, ymm5, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*6]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*6], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*6]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*6], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm6, ymm6, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*7]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*7], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*7]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*7], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm7, ymm7, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*8]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*8], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*8]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*8], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm8, ymm8, ymm31
        ;; SHA3_512 RATE, 72 bytes

%if %%RATE > SHA3_512_RATE
        ;; SHA3_384 RATE
        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*9]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*9], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*9]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*9], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm9, ymm9, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*10]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*10], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*10]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*10], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm10, ymm10, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*11]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*11], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*11]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*11], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm11, ymm11, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*12]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*12], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*12]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*12], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm12, ymm12, ymm31
%endif
%if %%RATE > SHA3_384_RATE
        ;; SHA3_256 and SHAKE256 RATE
        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*13]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*13], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*13]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*13], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm13, ymm13, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*14]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*14], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*14]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*14], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm14, ymm14, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*15]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*15], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*15]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*15], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm15, ymm15, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*16]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*16], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*16]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*16], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm16, ymm16, ymm31
%endif
%if %%RATE > SHA3_256_RATE
        ;; SHAKE128 RATE
        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*17]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*17], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*17]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*17], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm17, ymm17, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*18]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*18], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*18]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*18], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm18, ymm18, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*19]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*19], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*19]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*19], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm19, ymm19, ymm31

        vmovq   xmm31, [%%INPUT0 + %%OFFSET + 8*20]
        vpinsrq xmm31, [%%INPUT1 + %%OFFSET + 8*20], 1
        vmovq   xmm30, [%%INPUT2 + %%OFFSET + 8*20]
        vpinsrq xmm30, [%%INPUT3 + %%OFFSET + 8*20], 1
        vinserti32x4 ymm31, xmm30, 1
        vpxorq  ymm20, ymm20, ymm31
%endif
%endmacro

;; Store x4 state from SIMD registers to memory
;;   ymm0-ymm24        [in] x4 state registers
;;   ymm31      [clobbered] used as a temporary register
%macro STATE_EXTRACT_x4 6
%define %%OUTPUT0       %1      ; [in] destination pointer lane 0
%define %%OUTPUT1       %2      ; [in] destination pointer lane 1
%define %%OUTPUT2       %3      ; [in] destination pointer lane 2
%define %%OUTPUT3       %4      ; [in] destination pointer lane 3
%define %%OFFSET        %5      ; [in] destination offset
%define %%N             %6      ; [in] numerical values, number of 8-byte state registers to save

%assign I 0
%rep %%N
        vextracti64x2   xmm31, APPEND(ymm, I), 1
        vmovq   [%%OUTPUT0 + %%OFFSET + 8*I], APPEND(xmm, I)
        vpextrq [%%OUTPUT1 + %%OFFSET + 8*I], APPEND(xmm, I), 1
        vmovq   [%%OUTPUT2 + %%OFFSET + 8*I], xmm31
        vpextrq [%%OUTPUT3 + %%OFFSET + 8*I], xmm31, 1
%assign I (I + 1)
%endrep
%endmacro

%endif ; _CP_SHA3_COMMON_INC_
