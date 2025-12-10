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
; Multi-buffer keccak kernels
;

%ifndef _CP_SHA3_UTILS_MB4_INC_
%define _CP_SHA3_UTILS_MB4_INC_

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%include "pcpsha3_common.inc"

default rel
%use smartalign

section .text align=IPP_ALIGN_FACTOR

;; Loads keccak state from memory
;;
;; input:  arg1 - state pointer
;; output: ymm0-ymm24
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_load_state_x4, PRIVATE
        vmovdqu64       ymm0,  [arg1 + 32*0]
        vmovdqu64       ymm1,  [arg1 + 32*1]
        vmovdqu64       ymm2,  [arg1 + 32*2]
        vmovdqu64       ymm3,  [arg1 + 32*3]
        vmovdqu64       ymm4,  [arg1 + 32*4]
        vmovdqu64       ymm5,  [arg1 + 32*5]
        vmovdqu64       ymm6,  [arg1 + 32*6]
        vmovdqu64       ymm7,  [arg1 + 32*7]
        vmovdqu64       ymm8,  [arg1 + 32*8]
        vmovdqu64       ymm9,  [arg1 + 32*9]
        vmovdqu64       ymm10, [arg1 + 32*10]
        vmovdqu64       ymm11, [arg1 + 32*11]
        vmovdqu64       ymm12, [arg1 + 32*12]
        vmovdqu64       ymm13, [arg1 + 32*13]
        vmovdqu64       ymm14, [arg1 + 32*14]
        vmovdqu64       ymm15, [arg1 + 32*15]
        vmovdqu64       ymm16, [arg1 + 32*16]
        vmovdqu64       ymm17, [arg1 + 32*17]
        vmovdqu64       ymm18, [arg1 + 32*18]
        vmovdqu64       ymm19, [arg1 + 32*19]
        vmovdqu64       ymm20, [arg1 + 32*20]
        vmovdqu64       ymm21, [arg1 + 32*21]
        vmovdqu64       ymm22, [arg1 + 32*22]
        vmovdqu64       ymm23, [arg1 + 32*23]
        vmovdqu64       ymm24, [arg1 + 32*24]
        ret
ENDFUNC keccak_1600_load_state_x4

;; Saves keccak state to memory memory
;;
;; input:  arg1 - state pointer
;;         ymm0-ymm24 - keccak state registers
;; output: memory from [arg1] to [arg1 + 100*8]
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_save_state_x4, PRIVATE
        vmovdqu64       [arg1 + 32*0],  ymm0
        vmovdqu64       [arg1 + 32*1],  ymm1
        vmovdqu64       [arg1 + 32*2],  ymm2
        vmovdqu64       [arg1 + 32*3],  ymm3
        vmovdqu64       [arg1 + 32*4],  ymm4
        vmovdqu64       [arg1 + 32*5],  ymm5
        vmovdqu64       [arg1 + 32*6],  ymm6
        vmovdqu64       [arg1 + 32*7],  ymm7
        vmovdqu64       [arg1 + 32*8],  ymm8
        vmovdqu64       [arg1 + 32*9],  ymm9
        vmovdqu64       [arg1 + 32*10], ymm10
        vmovdqu64       [arg1 + 32*11], ymm11
        vmovdqu64       [arg1 + 32*12], ymm12
        vmovdqu64       [arg1 + 32*13], ymm13
        vmovdqu64       [arg1 + 32*14], ymm14
        vmovdqu64       [arg1 + 32*15], ymm15
        vmovdqu64       [arg1 + 32*16], ymm16
        vmovdqu64       [arg1 + 32*17], ymm17
        vmovdqu64       [arg1 + 32*18], ymm18
        vmovdqu64       [arg1 + 32*19], ymm19
        vmovdqu64       [arg1 + 32*20], ymm20
        vmovdqu64       [arg1 + 32*21], ymm21
        vmovdqu64       [arg1 + 32*22], ymm22
        vmovdqu64       [arg1 + 32*23], ymm23
        vmovdqu64       [arg1 + 32*24], ymm24
        ret
ENDFUNC keccak_1600_save_state_x4

;; Add input data to state when message length is less than rate
;;
;; input:
;;    r10  - state pointer to absorb into (clobbered)
;;    arg2 - message pointer lane 0 (updated on output)
;;    arg3 - message pointer lane 1 (updated on output)
;;    arg4 - message pointer lane 2 (updated on output)
;;    arg5 - message pointer lane 3 (updated on output)
;;    r12  - length in bytes (clobbered on output)
;; output:
;;    memory - state from [r10] to [r10 + 4*r12 - 1]
;; clobbered:
;;    rax, rbx, r15, k1, ymm31-ymm29
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_partial_add_x4, PRIVATE
        mov             rax, [r10 + 8*100]
        test            eax, 7
        jz              .start_aligned_to_4x8

        ;; start offset is not aligned to register size
        ;; - calculate remaining capacity of the register
        ;; - get the min between length and the capacity of the register
        ;; - perform partial add on the register
        ;; - once aligned to the register

        mov             r15, rax        ; r15 = s[100]

        and             eax, 7
        neg             eax
        add             eax, 8          ; register capacity = 8 - (offset % 8)
        cmp             r12d, eax
        cmovb           eax, r12d       ; eax = min(register capacity, length)

        lea             rbx, [rel byte_kmask_0_to_7]
        kmovb           k1, [rbx + rax] ; message load mask

        mov             rbx, r15
        and             ebx, ~7
        lea             r10, [r10 + rbx*4]      ; get to state starting register

        mov             rbx, r15
        and             ebx, 7

        vmovdqu8        ymm31, [r10]            ; load & store // allocate SB for the register
        vmovdqu8        [r10], ymm31

        vmovdqu8        xmm31{k1}{z}, [arg2]            ; Read 1 to 7 bytes from lane 0
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 8*0] ; Read 1 to 7 bytes from state reg lane 0
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 8*0]{k1}, xmm31    ; Write 1 to 7 bytes to state reg lane 0

        vmovdqu8        xmm31{k1}{z}, [arg3]            ; Read 1 to 7 bytes from lane 1
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 8*1] ; Read 1 to 7 bytes from state reg lane 1
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 8*1]{k1}, xmm31    ; Write 1 to 7 bytes to state reg lane 1

        vmovdqu8        xmm31{k1}{z}, [arg4]            ; Read 1 to 7 bytes from lane 2
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 8*2] ; Read 1 to 7 bytes from state reg lane 2
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 8*2]{k1}, xmm31    ; Write 1 to 7 bytes to state reg lane 2

        vmovdqu8        xmm31{k1}{z}, [arg5]            ; Read 1 to 7 bytes from lane 3
        vmovdqu8        xmm30{k1}{z}, [r10 + rbx + 8*3] ; Read 1 to 7 bytes from state reg lane 3
        vpxorq          xmm31, xmm31, xmm30
        vmovdqu8        [r10 + rbx + 8*3]{k1}, xmm31    ; Write 1 to 7 bytes to state reg lane 3

        sub             r12, rax
        jz              .zero_bytes

        add             arg2, rax
        add             arg3, rax
        add             arg4, rax
        add             arg5, rax
        add             r10, 32
        xor             rax, rax
        jmp             .ymm_loop

.start_aligned_to_4x8:
        lea             r10, [r10 + rax*4]
        xor             rax, rax

align IPP_ALIGN_FACTOR
.ymm_loop:
        cmp             r12d, 8
        jb              .lt_8_bytes

        vmovq           xmm31, [arg2 + rax]             ; Read 8 bytes from lane 0
        vpinsrq         xmm31, [arg3 + rax], 1          ; Read 8 bytes from lane 1
        vmovq           xmm30, [arg4 + rax]             ; Read 8 bytes from lane 2
        vpinsrq         xmm30, [arg5 + rax], 1          ; Read 8 bytes from lane 3
        vinserti32x4    ymm31, ymm31, xmm30, 1
        vpxorq          ymm31, ymm31, [r10 + rax*4]     ; Add data with the state
        vmovdqu64       [r10 + rax*4], ymm31
        add             rax, 8
        sub             r12, 8
        jz              .zero_bytes
        jmp             .ymm_loop

align IPP_ALIGN_FACTOR
.zero_bytes:
        add             arg2, rax
        add             arg3, rax
        add             arg4, rax
        add             arg5, rax
        ret

align IPP_ALIGN_FACTOR
.lt_8_bytes:
        add             arg2, rax
        add             arg3, rax
        add             arg4, rax
        add             arg5, rax
        lea             r10,  [r10 + rax*4]

        lea             rbx, [rel byte_kmask_0_to_7]
        kmovb           k1, [rbx + r12]         ; message load mask

        vmovdqu8        xmm31{k1}{z}, [arg2]    ; Read 1 to 7 bytes from lane 0
        vmovdqu8        xmm30{k1}{z}, [arg3]    ; Read 1 to 7 bytes from lane 1
        vpunpcklqdq     xmm31, xmm31, xmm30     ; Interleave data from lane 0 and lane 1
        vmovdqu8        xmm30{k1}{z}, [arg4]    ; Read 1 to 7 bytes from lane 2
        vmovdqu8        xmm29{k1}{z}, [arg5]    ; Read 1 to 7 bytes from lane 3
        vpunpcklqdq     xmm30, xmm30, xmm29     ; Interleave data from lane 2 and lane 3
        vinserti32x4    ymm31, ymm31, xmm30, 1

        vpxorq          ymm31, ymm31, [r10]     ; Add data to the state
        vmovdqu64       [r10], ymm31            ; Update state in memory

        add             arg2, r12               ; increment message pointer lane 0
        add             arg3, r12               ; increment message pointer lane 1
        add             arg4, r12               ; increment message pointer lane 2
        add             arg5, r12               ; increment message pointer lane 3
        ret
ENDFUNC keccak_1600_partial_add_x4

;; Extract bytes from state and write to outputs
;;
;; input:
;;    r10  - state pointer to start extracting from (clobbered)
;;    arg1 - output pointer lane 0 (updated on output)
;;    arg2 - output pointer lane 1 (updated on output)
;;    arg3 - output pointer lane 2 (updated on output)
;;    arg4 - output pointer lane 3 (updated on output)
;;    r12  - length in bytes (clobbered on output)
;;    r11  - state offset to start extract from
;; output:
;;    memory - output lane 0 from [arg1] to [arg1 + r12 - 1]
;;    memory - output lane 1 from [arg2] to [arg2 + r12 - 1]
;;    memory - output lane 2 from [arg3] to [arg3 + r12 - 1]
;;    memory - output lane 3 from [arg4] to [arg4 + r12 - 1]
;; clobbered:
;;    rax, rbx, k1, ymm31-ymm30
align IPP_ALIGN_FACTOR
IPPASM keccak_1600_extract_bytes_x4, PRIVATE
        or              r12, r12
        jz              .zero_bytes

        test            r11d, 7
        jz              .start_aligned_to_4x8

        ;; extract offset is not aligned to the register size (8 bytes)
        ;; - calculate remaining capacity of the register
        ;; - get the min between length to extract and register capacity
        ;; - perform partial add on the register

        mov             rax, r11        ; rax = r11 = offset in the state

        and             eax, 7
        neg             eax
        add             eax, 8          ; register capacity = 8 - (offset % 8)
        cmp             r12d, eax
        cmovb           eax, r12d       ; eax = min(register capacity, length)

        lea             rbx, [rel byte_kmask_0_to_7]
        kmovb           k1, [rbx + rax] ; message store mask

        mov             rbx, r11
        and             ebx, ~7
        lea             r10, [r10 + rbx*4]      ; get to state starting register

        mov             rbx, r11
        and             ebx, 7

        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 8*0] ; Read 1 to 7 bytes from state reg lane 0
        vmovdqu8        [arg1]{k1}, xmm31               ; Write 1 to 7 bytes to lane 0 output

        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 8*1] ; Read 1 to 7 bytes from state reg lane 1
        vmovdqu8        [arg2]{k1}, xmm31               ; Write 1 to 7 bytes to lane 1 output

        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 8*2] ; Read 1 to 7 bytes from state reg lane 2
        vmovdqu8        [arg3]{k1}, xmm31               ; Write 1 to 7 bytes to lane 2 output

        vmovdqu8        xmm31{k1}{z}, [r10 + rbx + 8*3] ; Read 1 to 7 bytes from state reg lane 3
        vmovdqu8        [arg4]{k1}, xmm31               ; Write 1 to 7 bytes to lane 3 output

        ;; increment output registers
        add             arg1, rax
        add             arg2, rax
        add             arg3, rax
        add             arg4, rax

        ;; decrement length to extract
        sub             r12, rax
        jz              .zero_bytes

        ;; there is more data to extract, update state register pointer and go to the main loop
        add             r10, 32
        xor             rax, rax
        jmp             .ymm_loop

.start_aligned_to_4x8:
        lea             r10, [r10 + r11*4]
        xor             rax, rax

align IPP_ALIGN_FACTOR
.ymm_loop:
        cmp             r12, 8
        jb              .lt_8_bytes
        vmovdqu64       xmm31, [r10]
        vmovdqu64       xmm30, [r10 + 16]
        vmovq           [arg1 + rax], xmm31
        vpextrq         [arg2 + rax], xmm31, 1
        vmovq           [arg3 + rax], xmm30
        vpextrq         [arg4 + rax], xmm30, 1
        add             rax, 8
        sub             r12, 8
        jz              .zero_bytes_left
        add             r10, 4*8
        jmp             .ymm_loop

align IPP_ALIGN_FACTOR
.zero_bytes_left:
        ;; increment output pointers
        add             arg1, rax
        add             arg2, rax
        add             arg3, rax
        add             arg4, rax
.zero_bytes:
        ret

align IPP_ALIGN_FACTOR
.lt_8_bytes:
        add             arg1, rax
        add             arg2, rax
        add             arg3, rax
        add             arg4, rax

        lea             rax, [rel byte_kmask_0_to_7]
        kmovb           k1, [rax + r12]         ; k1 is the mask of message bytes to read

        vmovq           xmm31, [r10 + 0*8]      ; Read 8 bytes from state lane 0
        vmovdqu8        [arg1]{k1}, xmm31       ; Extract 1 to 7 bytes of state into output 0
        vmovq           xmm31, [r10 + 1*8]      ; Read 8 bytes from state lane 1
        vmovdqu8        [arg2]{k1}, xmm31       ; Extract 1 to 7 bytes of state into output 1
        vmovq           xmm31, [r10 + 2*8]      ; Read 8 bytes from state lane 2
        vmovdqu8        [arg3]{k1}, xmm31       ; Extract 1 to 7 bytes of state into output 2
        vmovq           xmm31, [r10 + 3*8]      ; Read 8 bytes from state lane 3
        vmovdqu8        [arg4]{k1}, xmm31       ; Extract 1 to 7 bytes of state into output 3

        ;; increment output pointers
        add             arg1, r12
        add             arg2, r12
        add             arg3, r12
        add             arg4, r12
        ret
ENDFUNC keccak_1600_extract_bytes_x4

section .rodata

align 8
byte_kmask_0_to_7:
        db      0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f  ; 0xff should never happen

%endif ; _CP_SHA3_UTILS_MB4_INC_
