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
; Keccak kernels
;

%ifndef _CP_SHA3_UTILS_INC_
%define _CP_SHA3_UTILS_INC_

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%include "pcpsha3_common.inc"

default rel
%use smartalign

section .text align=IPP_ALIGN_FACTOR

;; Initialized keccak state in registers
;;
;; input:
;; output: xmm0-xmm24
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_init_state, PRIVATE
        vpxorq          xmm0,  xmm0, xmm0
        vpxorq          xmm1,  xmm1, xmm1
        vpxorq          xmm2,  xmm2, xmm2
        vmovdqa64       ymm3,  ymm0
        vmovdqa64       ymm4,  ymm0
        vmovdqa64 	ymm5,  ymm0
        vmovdqa64 	ymm6,  ymm0
        vmovdqa64 	ymm7,  ymm0
        vmovdqa64 	ymm8,  ymm0
        vmovdqa64 	ymm9,  ymm0
        vmovdqa64 	ymm10, ymm0
        vmovdqa64 	ymm11, ymm0
        vmovdqa64 	ymm12, ymm0
        vmovdqa64 	ymm13, ymm0
        vmovdqa64 	ymm14, ymm0
        vmovdqa64 	ymm15, ymm0
        vmovdqa64 	ymm16, ymm0
        vmovdqa64 	ymm17, ymm0
        vmovdqa64 	ymm18, ymm0
        vmovdqa64 	ymm19, ymm0
        vmovdqa64 	ymm20, ymm0
        vmovdqa64 	ymm21, ymm0
        vmovdqa64 	ymm22, ymm0
        vmovdqa64 	ymm23, ymm0
        vmovdqa64 	ymm24, ymm0
        ret
ENDFUNC keccak_1600_init_state

;; Loads keccak state from memory
;;
;; input:  arg1 - state pointer
;; output: xmm0-xmm24
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_load_state, PRIVATE
        vmovq   xmm0, [arg1 + 8*0]
        vmovq   xmm1, [arg1 + 8*1]
        vmovq   xmm2, [arg1 + 8*2]
        vmovq   xmm3, [arg1 + 8*3]
        vmovq   xmm4, [arg1 + 8*4]
        vmovq   xmm5, [arg1 + 8*5]
        vmovq   xmm6, [arg1 + 8*6]
        vmovq   xmm7, [arg1 + 8*7]
        vmovq   xmm8, [arg1 + 8*8]
        vmovq   xmm9, [arg1 + 8*9]
        vmovq   xmm10, [arg1 + 8*10]
        vmovq   xmm11, [arg1 + 8*11]
        vmovq   xmm12, [arg1 + 8*12]
        vmovq   xmm13, [arg1 + 8*13]
        vmovq   xmm14, [arg1 + 8*14]
        vmovq   xmm15, [arg1 + 8*15]
        vmovq   xmm16, [arg1 + 8*16]
        vmovq   xmm17, [arg1 + 8*17]
        vmovq   xmm18, [arg1 + 8*18]
        vmovq   xmm19, [arg1 + 8*19]
        vmovq   xmm20, [arg1 + 8*20]
        vmovq   xmm21, [arg1 + 8*21]
        vmovq   xmm22, [arg1 + 8*22]
        vmovq   xmm23, [arg1 + 8*23]
        vmovq   xmm24, [arg1 + 8*24]
        ret
ENDFUNC keccak_1600_load_state

;; Saves keccak state to memory memory
;;
;; input:  arg1 - state pointer
;;         xmm0-xmm24 - keccak state registers
;; output: memory from [arg1] to [arg1 + 25*8]
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_save_state, PRIVATE
        vmovq   [arg1 + 8*0], xmm0
        vmovq   [arg1 + 8*1], xmm1
        vmovq   [arg1 + 8*2], xmm2
        vmovq   [arg1 + 8*3], xmm3
        vmovq   [arg1 + 8*4], xmm4
        vmovq   [arg1 + 8*5], xmm5
        vmovq   [arg1 + 8*6], xmm6
        vmovq   [arg1 + 8*7], xmm7
        vmovq   [arg1 + 8*8], xmm8
        vmovq   [arg1 + 8*9], xmm9
        vmovq   [arg1 + 8*10], xmm10
        vmovq   [arg1 + 8*11], xmm11
        vmovq   [arg1 + 8*12], xmm12
        vmovq   [arg1 + 8*13], xmm13
        vmovq   [arg1 + 8*14], xmm14
        vmovq   [arg1 + 8*15], xmm15
        vmovq   [arg1 + 8*16], xmm16
        vmovq   [arg1 + 8*17], xmm17
        vmovq   [arg1 + 8*18], xmm18
        vmovq   [arg1 + 8*19], xmm19
        vmovq   [arg1 + 8*20], xmm20
        vmovq   [arg1 + 8*21], xmm21
        vmovq   [arg1 + 8*22], xmm22
        vmovq   [arg1 + 8*23], xmm23
        vmovq   [arg1 + 8*24], xmm24
        ret
ENDFUNC keccak_1600_save_state

;; Add input data to state when message length is less than rate
;;
;; input:
;;    r13  - state
;;    arg2 - message pointer (updated on output)
;;    r12  - length (clobbered on output)
;; output:
;;    memory - state from [r13] to [r13 + r12 - 1]
;; clobbered:
;;    rax, k1, ymm31
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_partial_add, PRIVATE
.ymm_loop:
        cmp             r12, 32
        jb              .lt_32_bytes
        vmovdqu64       ymm31, [arg2]
        vpxorq          ymm31, ymm31, [r13]
        vmovdqu64       [r13], ymm31
        add             arg2, 32
        add             r13, 32
        sub             r12, 32
        jz              .zero_bytes
        jmp             .ymm_loop

.lt_32_bytes:
        xor             rax, rax
        bts             rax, r12
        dec             rax
        kmovq           k1, rax                 ; k1 is the mask of message bytes to read
        vmovdqu8        ymm31{k1}{z}, [arg2]    ; Read 0 to 31 bytes
        vpxorq          ymm31, ymm31, [r13]
        vmovdqu8        [r13]{k1}, ymm31
        add             arg2, r12               ; increment message pointer

.zero_bytes:
        ret
ENDFUNC keccak_1600_partial_add

;; Extract bytes from state and write to output
;;
;; input:
;;    r13  - state
;;    r10  - output pointer (updated on output)
;;    r12  - length (clobbered on output)
;; output:
;;    memory - output from [r10] to [r10 + r12 - 1]
;; clobbered:
;;    rax, k1, ymm31
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_extract_bytes, PRIVATE

.extract_32_byte_loop:
        cmp             r12, 32
        jb              .extract_lt_32_bytes
        vmovdqu64       ymm31, [r13]
        vmovdqu64       [r10], ymm31
        add             r13, 32
        add             r10, 32
        sub             r12, 32
        jz              .zero_bytes
        jmp             .extract_32_byte_loop

.extract_lt_32_bytes:
        xor             rax, rax
        bts             rax, r12
        dec             rax
        kmovq           k1, rax                 ; k1 is the mask of the last message bytes
        vmovdqu8        ymm31{k1}{z}, [r13]     ; Read 0 to 31 bytes
        vmovdqu8        [r10]{k1}, ymm31
        add             r10, r12           ; increment output pointer
.zero_bytes:
        ret
ENDFUNC keccak_1600_extract_bytes

;; Copy partial block message into temporary buffer,
;; add padding byte and EOM bit
;;
;;    r13  [in/out] destination pointer
;;    r12  [in/out] source pointer
;;    r11  [in/out] length in bytes
;;    r9   [in] rate
;;    r8   [in] pointer to the padding byte
;; output:
;;    memory - output from [r13] to [r13 + r11 - 1], [r13 + r11] padding, [r13 + r9 - 1] EOM
;; clobbered:
;;    rax, r15, k1, k2, ymm31
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_copy_with_padding, PRIVATE
        ; Clear the temporary buffer
        vpxorq          ymm31, ymm31, ymm31
        vmovdqu64       [r13 + 32*0], ymm31
        vmovdqu64       [r13 + 32*1], ymm31
        vmovdqu64       [r13 + 32*2], ymm31
        vmovdqu64       [r13 + 32*3], ymm31
        vmovdqu64       [r13 + 32*4], ymm31
        vmovdqu64       [r13 + 32*5], ymm31
        vmovdqu64       [r13 + 32*6], ymm31
        vmovdqu64       [r13 + 32*7], ymm31

        xor             r15, r15
align IPP_ALIGN_FACTOR
.copy32_loop:
        cmp             r11, 32                 ; At least 32 remaining?
        jb              .partial32_with_padding ; If no remaining bytes, jump to the done label
        vmovdqu64       ymm31, [r12 + r15]
        vmovdqu64       [r13 + r15], ymm31
        sub             r11, 32                 ; Decrement the remaining length
        add             r15, 32                 ; Increment offset
        jmp             .copy32_loop

.partial32_with_padding:
        xor             rax, rax
        bts             rax, r11
        kmovq           k2, rax                 ; k2 is mask of the 1st byte after the message
        dec             rax
        kmovq           k1, rax                 ; k1 is the mask of the last message bytes
        vmovdqu8        ymm31{k1}{z}, [r12 + r15]       ; Read 0 to 31 bytes
        vpbroadcastb    ymm31{k2}, [r8]                 ; Add padding byte
        vmovdqu64       [r13 + r15], ymm31              ; Store whole 32 bytes
        ; EOM bit - XOR the last byte of the block
        xor             byte [r13 + r9 - 1], 0x80
        ret
ENDFUNC keccak_1600_copy_with_padding

;; Copy partial digest (not equal to rate value)
;;
;;    r13  [in/out] destination pointer
;;    r12  [in/out] source pointer
;;    arg2 [in/out] length in bytes
;; output:
;;    memory - output from [r13] to [r13 + arg2 - 1]
;; clobbered:
;;    rax, k1, ymm31
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_copy_digest, PRIVATE
.copy32_loop:
        cmp             arg2, 32                ; At least 32 remaining?
        jb              .partial32              ; If no remaining bytes, jump to the done label
        vmovdqu64       ymm31, [r12]
        vmovdqu64       [r13], ymm31
        add             r13, 32                 ; Increment destination pointer
        add             r12, 32                 ; Increment source pointer
        sub             arg2, 32                ; Decrement the remaining length
        jz              .done
        jmp             .copy32_loop

.partial32:
        xor             rax, rax
        bts             rax, arg2
        dec             rax
        kmovq           k1, rax                 ; k1 is the mask of the last message bytes
        vmovdqu8        ymm31{k1}{z}, [r12]     ; Read 0 to 31 bytes
        vmovdqu8        [r13]{k1}, ymm31        ; Store 0 to 31 bytes
.done:
        ret
ENDFUNC keccak_1600_copy_digest

;; YMM0-YMM24    [in/out]    keccak state registers (one SIMD per one state register)
;; YMM25-YMM31   [clobbered] temporary SIMD registers
;; R13           [clobbered] used for round tracking
;; R14           [clobbered] used for access to SHA3 constant table

align IPP_ALIGN_FACTOR
IPPASM keccak1600_block_64bit, PRIVATE
        mov             r13d, 24                ; 24 rounds
        lea             r14, [rel SHA3RC]       ; Load the address of the SHA3 round constants

align IPP_ALIGN_FACTOR
keccak_rnd_loop:
        ; Theta step
        vmovdqa64       ymm25, ymm0
        vpternlogq      ymm25, ymm5, ymm10, 0x96
        vmovdqa64       ymm26, ymm1
        vpternlogq      ymm26, ymm6, ymm11, 0x96
        vmovdqa64       ymm27, ymm2
        vpternlogq      ymm27, ymm7, ymm12, 0x96

        vmovdqa64       ymm28, ymm3
        vpternlogq      ymm28, ymm8, ymm13, 0x96
        vmovdqa64       ymm29, ymm4
        vpternlogq      ymm29, ymm9, ymm14, 0x96
        vpternlogq      ymm25, ymm15, ymm20, 0x96

        vpternlogq      ymm26, ymm16, ymm21, 0x96
        vpternlogq      ymm27, ymm17, ymm22, 0x96
        vpternlogq      ymm28, ymm18, ymm23, 0x96

        ; Rho and Pi steps
        vprolq          ymm30, ymm26, 1
        vprolq          ymm31, ymm27, 1
        vpternlogq      ymm29, ymm19, ymm24, 0x96

        ; Chi step
        vpternlogq      ymm0,  ymm29, ymm30, 0x96
        vpternlogq      ymm10, ymm29, ymm30, 0x96
        vpternlogq      ymm20, ymm29, ymm30, 0x96

        vpternlogq      ymm5,  ymm29, ymm30, 0x96
        vpternlogq      ymm15, ymm29, ymm30, 0x96
        vprolq          ymm30, ymm28, 1

        vpternlogq      ymm6, ymm25, ymm31, 0x96
        vpternlogq      ymm16, ymm25, ymm31, 0x96
        vpternlogq      ymm1, ymm25, ymm31, 0x96

        vpternlogq      ymm11, ymm25, ymm31, 0x96
        vpternlogq      ymm21, ymm25, ymm31, 0x96
        vprolq          ymm31, ymm29, 1

        vpbroadcastq    ymm29, [r14]    ; Load the round constant into ymm29
        add             r14, 8          ; Increment the pointer to the next round constant

        vpternlogq      ymm12, ymm26, ymm30, 0x96
        vpternlogq      ymm7, ymm26, ymm30, 0x96
        vpternlogq      ymm22, ymm26, ymm30, 0x96

        vpternlogq      ymm17, ymm26, ymm30, 0x96
        vpternlogq      ymm2, ymm26, ymm30, 0x96
        vprolq          ymm30, ymm25, 1

        vpternlogq      ymm3, ymm27, ymm31, 0x96
        vpternlogq      ymm13, ymm27, ymm31, 0x96
        vpternlogq      ymm23, ymm27, ymm31, 0x96

        vprolq          ymm6, ymm6, 44
        vpternlogq      ymm18, ymm27, ymm31, 0x96
        vpternlogq      ymm8, ymm27, ymm31, 0x96

        vprolq          ymm12, ymm12, 43
        vprolq          ymm18, ymm18, 21
        vpternlogq      ymm24, ymm28, ymm30, 0x96

        vprolq          ymm24, ymm24, 14
        vprolq          ymm3, ymm3, 28
        vpternlogq      ymm9, ymm28, ymm30, 0x96

        vprolq          ymm9, ymm9, 20
        vprolq          ymm10, ymm10, 3
        vpternlogq      ymm19, ymm28, ymm30, 0x96

        vprolq          ymm16, ymm16, 45
        vprolq          ymm22, ymm22, 61
        vpternlogq      ymm4, ymm28, ymm30, 0x96

        vprolq          ymm1, ymm1, 1
        vprolq          ymm7, ymm7, 6
        vpternlogq      ymm14, ymm28, ymm30, 0x96

        vprolq          ymm13, ymm13, 25
        vprolq          ymm19, ymm19, 8
        vmovdqa64       ymm30, ymm0
        vpternlogq      ymm30, ymm6, ymm12, 0xD2

        vprolq          ymm20, ymm20, 18
        vprolq          ymm4,  ymm4,  27
        vpxorq ymm30, ymm30, ymm29
        
        vprolq          ymm5,  ymm5,  36
        vprolq          ymm11, ymm11, 10
        vmovdqa64       ymm31, ymm6
        vpternlogq      ymm31, ymm12, ymm18, 0xD2

        vprolq          ymm17, ymm17, 15
        vprolq          ymm23, ymm23, 56
        vpternlogq      ymm12, ymm18, ymm24, 0xD2

        vprolq          ymm2, ymm2, 62
        vprolq          ymm8, ymm8, 55
        vpternlogq      ymm18, ymm24, ymm0, 0xD2

        vprolq          ymm14, ymm14, 39
        vprolq          ymm15, ymm15, 41
        vpternlogq      ymm24, ymm0, ymm6, 0xD2
        vmovdqa64       ymm0, ymm30
        vmovdqa64       ymm6, ymm31

        vprolq          ymm21, ymm21, 2
        vmovdqa64       ymm30, ymm3
        vpternlogq      ymm30, ymm9, ymm10, 0xD2
        vmovdqa64       ymm31, ymm9
        vpternlogq      ymm31, ymm10, ymm16, 0xD2
        
        vpternlogq      ymm10, ymm16, ymm22, 0xD2
        vpternlogq      ymm16, ymm22, ymm3, 0xD2
        vpternlogq      ymm22, ymm3, ymm9, 0xD2
        vmovdqa64       ymm3, ymm30
        vmovdqa64       ymm9, ymm31

        vmovdqa64       ymm30, ymm1
        vpternlogq      ymm30, ymm7, ymm13, 0xD2
        vmovdqa64       ymm31, ymm7
        vpternlogq      ymm31, ymm13, ymm19, 0xD2
        vpternlogq      ymm13, ymm19, ymm20, 0xD2

        vpternlogq      ymm19, ymm20, ymm1, 0xD2
        vpternlogq      ymm20, ymm1, ymm7, 0xD2
        vmovdqa64       ymm1, ymm30
        vmovdqa64       ymm7, ymm31   
        vmovdqa64       ymm30, ymm4
        vpternlogq      ymm30, ymm5, ymm11, 0xD2

        vmovdqa64       ymm31, ymm5
        vpternlogq      ymm31, ymm11, ymm17, 0xD2
        vpternlogq      ymm11, ymm17, ymm23, 0xD2
        vpternlogq      ymm17, ymm23, ymm4, 0xD2

        vpternlogq      ymm23, ymm4, ymm5, 0xD2
        vmovdqa64       ymm4, ymm30
        vmovdqa64       ymm5, ymm31
        vmovdqa64       ymm30, ymm2
        vpternlogq      ymm30, ymm8, ymm14, 0xD2
        vmovdqa64       ymm31, ymm8
        vpternlogq      ymm31, ymm14, ymm15, 0xD2

        vpternlogq      ymm14, ymm15, ymm21, 0xD2
        vpternlogq      ymm15, ymm21, ymm2, 0xD2
        vpternlogq      ymm21, ymm2, ymm8, 0xD2
        vmovdqa64       ymm2, ymm30
        vmovdqa64       ymm8, ymm31

        ;; π(ρ(θ(A)))
        vmovdqa64       ymm30, ymm3        ;; store ymm3 temporarily in ymm30
        vmovdqa64       ymm3,  ymm18
        vmovdqa64       ymm18, ymm17
        vmovdqa64       ymm17, ymm11
        vmovdqa64       ymm11, ymm7
        vmovdqa64       ymm7,  ymm10
        vmovdqa64       ymm10, ymm1
        vmovdqa64       ymm1,  ymm6
        vmovdqa64       ymm6,  ymm9
        vmovdqa64       ymm9,  ymm22
        vmovdqa64       ymm22, ymm14
        vmovdqa64       ymm14, ymm20
        vmovdqa64       ymm20, ymm2
        vmovdqa64       ymm2,  ymm12
        vmovdqa64       ymm12, ymm13
        vmovdqa64       ymm13, ymm19
        vmovdqa64       ymm19, ymm23
        vmovdqa64       ymm23, ymm15
        vmovdqa64       ymm15, ymm4
        vmovdqa64       ymm4,  ymm24
        vmovdqa64       ymm24, ymm21
        vmovdqa64       ymm21, ymm8
        vmovdqa64       ymm8,  ymm16
        vmovdqa64       ymm16, ymm5
        vmovdqa64       ymm5,  ymm30

        dec r13d                ; Decrement the round counter
        jnz keccak_rnd_loop     ; Jump to the start of the loop if r13d is not zero
        ret
ENDFUNC keccak1600_block_64bit

section .rodata

align 64
SHA3RC:
;; SHA3 round constants
;; These constants are used in each round of the Keccak permutation.
        DQ 0x0000000000000001, 0x0000000000008082 
        DQ 0x800000000000808a, 0x8000000080008000
        DQ 0x000000000000808b, 0x0000000080000001 
        DQ 0x8000000080008081, 0x8000000000008009
        DQ 0x000000000000008a, 0x0000000000000088 
        DQ 0x0000000080008009, 0x000000008000000a
        DQ 0x000000008000808b, 0x800000000000008b 
        DQ 0x8000000000008089, 0x8000000000008003
        DQ 0x8000000000008002, 0x8000000000000080 
        DQ 0x000000000000800a, 0x800000008000000a
        DQ 0x8000000080008081, 0x8000000000008080 
        DQ 0x0000000080000001, 0x8000000080008008

%endif ; _CP_SHA3_UTILS_INC_
