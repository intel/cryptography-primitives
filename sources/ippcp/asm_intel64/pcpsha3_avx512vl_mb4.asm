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
; Authors:
;       Erdinc Ozturk
;       Tomasz Kantecki
;       Marcel Cornu

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%if (_IPP32E >= _IPP32E_K0)

default rel
%use smartalign

%include "pcpsha3_common.inc"
%include "pcpsha3_utils.inc"
%include "pcpsha3_utils_mb4.inc"

%define STATE_SIZE  ((25 * 8 * 4) + 8)

section .text align=IPP_ALIGN_FACTOR

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;        SHAKE128 init->absorb->finalize->squeeze
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; void
;; cp_SHA3_SHAKE128_InitMB4(cpSHA3_SHAKE128Ctx_mb4* state)
;;      arg1 - state, x4 keccak1600 state
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE128_InitMB4, PUBLIC
        USES_GPR rdi
        COMP_ABI 1

        mov     arg1, [arg1]            ; state.ctx into arg1
        vpxorq  xmm0, xmm0, xmm0

        ;; clear 4 x 200 B of state + 8 bytes
        vmovdqu64 [arg1 + 0*32], ymm0
        vmovdqu64 [arg1 + 1*32], ymm0
        vmovdqu64 [arg1 + 2*32], ymm0
        vmovdqu64 [arg1 + 3*32], ymm0
        vmovdqu64 [arg1 + 4*32], ymm0
        vmovdqu64 [arg1 + 5*32], ymm0
        vmovdqu64 [arg1 + 6*32], ymm0
        vmovdqu64 [arg1 + 7*32], ymm0
        vmovdqu64 [arg1 + 8*32], ymm0
        vmovdqu64 [arg1 + 9*32], ymm0
        vmovdqu64 [arg1 + 10*32], ymm0
        vmovdqu64 [arg1 + 11*32], ymm0
        vmovdqu64 [arg1 + 12*32], ymm0
        vmovdqu64 [arg1 + 13*32], ymm0
        vmovdqu64 [arg1 + 14*32], ymm0
        vmovdqu64 [arg1 + 15*32], ymm0
        vmovdqu64 [arg1 + 16*32], ymm0
        vmovdqu64 [arg1 + 17*32], ymm0
        vmovdqu64 [arg1 + 18*32], ymm0
        vmovdqu64 [arg1 + 19*32], ymm0
        vmovdqu64 [arg1 + 20*32], ymm0
        vmovdqu64 [arg1 + 21*32], ymm0
        vmovdqu64 [arg1 + 22*32], ymm0
        vmovdqu64 [arg1 + 23*32], ymm0
        vmovdqu64 [arg1 + 24*32], ymm0
        vmovq     [arg1 + 25*32], xmm0
        
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE128_InitMB4

;;
;; void
;; cp_SHA3_SHAKE128_AbsorbMB4(cpSHA3_SHAKE128Ctx_mb4 * state,
;;                                      const Ipp8u* in0, const Ipp8u* in1,
;;                                      const Ipp8u* in2, const Ipp8u* in3,
;;                                      Ipp64u inlen)
;;      arg1 - state, x4 keccak1600 state
;;      arg2 - msg0, pointer to message lane 0 to be absorbed
;;      arg3 - msg1, pointer to message lane 1 to be absorbed
;;      arg4 - msg2, pointer to message lane 2 to be absorbed
;;      arg5 - msg3, pointer to message lane 3 to be absorbed
;;      arg6 - length, number of bytes to be absorbed from each lane
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE128_AbsorbMB4, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 6

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*100]
        or      r14, r14                ; s[100] == 0?
        je      .absorb_main_loop_start
        
        ; process remaining bytes if message long enough
        mov     r12, SHAKE128_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg6, r12               ; if mlen <= capacity then no permute
        jbe     .absorb_skip_permute

        sub     arg6, r12

        ; r10/state, arg2-arg5/inputs, r12/length
        mov     r10, arg1                       ; r10 = state
        CALL_IPPASM    keccak_1600_partial_add_x4      ; arg2-arg5 are updated

        CALL_IPPASM    keccak_1600_load_state_x4
        CALL_IPPASM    keccak1600_block_64bit
        mov     qword [arg1 + 8*100], 0         ; clear s[100]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        ; r10/state, arg2-arg5/inputs, r12/length
        mov     r10, arg1
        mov     r12, arg6
        CALL_IPPASM    keccak_1600_partial_add_x4
        lea     r15, [arg6 + r14]
        mov     [arg1 + 8*100], r15     ; s[100] += inlen

        cmp     r15, SHAKE128_RATE      ; s[100] >= rate ?
        jb      .absorb_exit

        CALL_IPPASM    keccak_1600_load_state_x4
        CALL_IPPASM    keccak1600_block_64bit
        CALL_IPPASM    keccak_1600_save_state_x4
        mov     qword [arg1 + 8*100], 0 ; clear s[100]
        jmp     .absorb_exit

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state_x4

.absorb_partial_block_done:
        mov     r11, arg6               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHAKE128_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES_x4 arg2, arg3, arg4, arg5, r12, SHAKE128_RATE   ; 4 x input, offset, rate

        sub     r11, SHAKE128_RATE              ; Subtract the rate from the remaining length
        add     r12, SHAKE128_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:
        CALL_IPPASM    keccak_1600_save_state_x4

        mov     [arg1 + 8*100], r11    ; update s[100]
        or      r11, r11
        jz      .absorb_exit

        mov     qword [arg1 + 8*100], 0 ; clear s[100]

        ; r10/state, arg2-arg5/input, r12/length
        mov     r10, arg1
        add     arg2, r12
        add     arg3, r12
        add     arg4, r12
        add     arg5, r12
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add_x4

        mov     [arg1 + 8*100], r11    ; update s[100]

.absorb_exit:
        REST_XMM_AVX
        REST_GPR

        ret
ENDFUNC cp_SHA3_SHAKE128_AbsorbMB4

;;
;; void
;; cp_SHA3_SHAKE128_FinalizeMB4(cpSHA3_SHAKE128Ctx_mb4* state)
;;      arg1 - state, x4 keccak1600 state
;; Clobbers:
;;      rax, r10-r11, ymm30-ymm31, arg1
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE128_FinalizeMB4, PUBLIC
        USES_GPR rdi
        COMP_ABI 1

        mov             arg1, [arg1]                            ; state.ctx into arg1
        mov             r11, [arg1 + 8*100]                     ; load state offset from s[100]
        mov             r10, r11
        and             r10d, ~7                                ; offset to the state register
        and             r11d, 7                                 ; offset within the register

        ;; add padding byte right after the message
        vmovdqu32       ymm31, [arg1 + r10*4]
        lea             rax, [rel SHAKE_MSG_PAD_x4]
        sub             rax, r11
        vmovdqu32       ymm30, [rax]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [arg1 + r10*4], ymm31

        ;; add EOM byte at offset equal to rate - 1
        vmovdqu32       ymm31, [arg1 + SHAKE128_RATE*4 - 4*8]
        vmovdqa32       ymm30, [rel SHAKE_TERMINATOR_BYTE_x4]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [arg1 + SHAKE128_RATE*4 - 4*8], ymm31

        mov             qword [arg1 + 8*100], 0                 ; clear s[100]

        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE128_FinalizeMB4

;;
;; void
;; cp_SHA3_SHAKE128_SqueezeMB4(Ipp8u* out0, Ipp8u* out1,
;;                                       Ipp8u* out2, Ipp8u* out3,
;;                                       Ipp64u outlen,
;;                                       cpSHA3_SHAKE128Ctx_mb4* state)
;;      arg1 - out0, pointer to output buffer lane 0 to extract into
;;      arg2 - out1, pointer to output buffer lane 1 to extract into
;;      arg3 - out2, pointer to output buffer lane 2 to extract into
;;      arg4 - out3, pointer to output buffer lane 3 to extract into
;;      arg5 - length, number of bytes to extract into each output buffer
;;      arg6 - state, x4 keccak1600 state
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE128_SqueezeMB4, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 6

        or      arg5, arg5
        jz      .squeeze_done

        mov     arg6, [arg6]            ; arg6 - state.ctx

        ; check for partially processed block
        mov     r15, [arg6 + 8*100]     ; s[100] - capacity
        or      r15, r15
        jnz     .squeeze_no_init_permute

        mov     r14, arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_load_state_x4
        mov     arg1, r14

        xor     rax, rax
        jmp     .squeeze_loop

align IPP_ALIGN_FACTOR
.squeeze_no_init_permute:
        ; extract bytes: r10 - state/src, arg1-arg4 - output/dst, r12 - length = min(capacity, outlen), r11 - offset
        mov     r10, arg6

        mov     r12, r15
        cmp     arg5, r15
        cmovb   r12, arg5               ; r12 = min(capacity, outlen)

        sub     arg5, r12               ; outlen -= length

        mov     r11d, SHAKE128_RATE
        sub     r11, r15                ; state offset

        sub     r15, r12                ; capacity -= length
        mov     [arg6 + 8*100], r15     ; update s[100]

        CALL_IPPASM    keccak_1600_extract_bytes_x4

        or      r15, r15
        jnz     .squeeze_done           ; s[100] != 0 ?

        mov     r14, arg1               ; preserve arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_load_state_x4
        mov     arg1, r14

        xor     rax, rax

align IPP_ALIGN_FACTOR
.squeeze_loop:
        cmp     arg5, SHAKE128_RATE     ; outlen > r
        jb      .squeeze_final_extract

        CALL_IPPASM    keccak1600_block_64bit

        ; Extract SHAKE128 rate bytes into the destination buffer
        STATE_EXTRACT_x4 arg1, arg2, arg3, arg4, rax, (SHAKE128_RATE / 8)

        add     rax, SHAKE128_RATE      ; dst offset += r
        sub     arg5, SHAKE128_RATE     ; outlen -= r
        jmp     .squeeze_loop

align IPP_ALIGN_FACTOR
.squeeze_final_extract:
        
        or      arg5, arg5
        jz      .squeeze_no_end_permute

        ;; update output pointers
        add     arg1, rax
        add     arg2, rax
        add     arg3, rax
        add     arg4, rax

        mov     r15d, SHAKE128_RATE
        sub     r15, arg5
        mov     [arg6 + 8*100], r15     ; s[100] = c

        CALL_IPPASM    keccak1600_block_64bit

        mov     r14, arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_save_state_x4
        mov     arg1, r14

        ; extract bytes: r10 - state/src, arg1-arg4 - output/dst, r12 - length, r11 - offset = 0
        mov     r10, arg6
        mov     r12, arg5
        xor     r11, r11
        CALL_IPPASM    keccak_1600_extract_bytes_x4
        jmp     .squeeze_done

.squeeze_no_end_permute:
        mov     qword [arg6 + 8*100], 0 ; s[100] = 0
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_save_state_x4

.squeeze_done:
        REST_XMM_AVX
        REST_GPR

        ret
ENDFUNC cp_SHA3_SHAKE128_SqueezeMB4

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;        SHAKE256 init->absorb->finalize->squeeze
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; void
;; cp_SHA3_SHAKE256_InitMB4(cpSHA3_SHAKE128Ctx_mb4* state)
;;      arg1 - state, x4 keccak1600 state
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_InitMB4, PUBLIC
        USES_GPR rdi
        COMP_ABI 1

        mov     arg1, [arg1]            ; state.ctx into arg1
        vpxorq  xmm0, xmm0, xmm0

        ;; clear 4 x 200 B of state + 8 bytes
        vmovdqu64 [arg1 + 0*32], ymm0
        vmovdqu64 [arg1 + 1*32], ymm0
        vmovdqu64 [arg1 + 2*32], ymm0
        vmovdqu64 [arg1 + 3*32], ymm0
        vmovdqu64 [arg1 + 4*32], ymm0
        vmovdqu64 [arg1 + 5*32], ymm0
        vmovdqu64 [arg1 + 6*32], ymm0
        vmovdqu64 [arg1 + 7*32], ymm0
        vmovdqu64 [arg1 + 8*32], ymm0
        vmovdqu64 [arg1 + 9*32], ymm0
        vmovdqu64 [arg1 + 10*32], ymm0
        vmovdqu64 [arg1 + 11*32], ymm0
        vmovdqu64 [arg1 + 12*32], ymm0
        vmovdqu64 [arg1 + 13*32], ymm0
        vmovdqu64 [arg1 + 14*32], ymm0
        vmovdqu64 [arg1 + 15*32], ymm0
        vmovdqu64 [arg1 + 16*32], ymm0
        vmovdqu64 [arg1 + 17*32], ymm0
        vmovdqu64 [arg1 + 18*32], ymm0
        vmovdqu64 [arg1 + 19*32], ymm0
        vmovdqu64 [arg1 + 20*32], ymm0
        vmovdqu64 [arg1 + 21*32], ymm0
        vmovdqu64 [arg1 + 22*32], ymm0
        vmovdqu64 [arg1 + 23*32], ymm0
        vmovdqu64 [arg1 + 24*32], ymm0
        vmovq     [arg1 + 25*32], xmm0

        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_InitMB4

;;
;; void
;; cp_SHA3_SHAKE256_FinalizeMB4(cpSHA3_SHAKE256Ctx_mb4* state)
;;      arg1 - state, x4 keccak1600 state
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_FinalizeMB4, PUBLIC
        USES_GPR rdi
        COMP_ABI 1

        mov             arg1, [arg1]                            ; state.ctx into arg1
        mov             r11, [arg1 + 8*100]                     ; load state offset from s[100]
        mov             r10, r11
        and             r10d, ~7                                ; offset to the state register
        and             r11d, 7                                 ; offset within the register

        ;; add padding byte right after the message
        vmovdqu32       ymm31, [arg1 + r10*4]
        lea             rax, [rel SHAKE_MSG_PAD_x4]
        sub             rax, r11
        vmovdqu32       ymm30, [rax]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [arg1 + r10*4], ymm31

        ;; add EOM byte at offset equal to rate - 1
        vmovdqu32       ymm31, [arg1 + SHAKE256_RATE*4 - 4*8]
        vmovdqa32       ymm30, [rel SHAKE_TERMINATOR_BYTE_x4]
        vpxorq          ymm31, ymm31, ymm30
        vmovdqu32       [arg1 + SHAKE256_RATE*4 - 4*8], ymm31

        mov             qword [arg1 + 8*100], 0                 ; clear s[100]

        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_FinalizeMB4

;;
;; void
;; cp_SHA3_SHAKE256_AbsorbMB4(cpSHA3_SHAKE256Ctx_mb4 * state,
;;                                      const Ipp8u* in0, const Ipp8u* in1,
;;                                      const Ipp8u* in2, const Ipp8u* in3,
;;                                      Ipp64u inlen)
;;      arg1 - state, x4 keccak1600 state
;;      arg2 - msg0, pointer to message lane 0 to be absorbed
;;      arg3 - msg1, pointer to message lane 1 to be absorbed
;;      arg4 - msg2, pointer to message lane 2 to be absorbed
;;      arg5 - msg3, pointer to message lane 3 to be absorbed
;;      arg6 - length, number of bytes to be absorbed from each lane
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_AbsorbMB4, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 6

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*100]
        or      r14, r14                ; s[100] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHAKE256_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg6, r12               ; if mlen <= capacity then no permute
        jbe     .absorb_skip_permute

        sub     arg6, r12

        ; r10/state, arg2-arg5/inputs, r12/length
        mov     r10, arg1                       ; r10 = state
        CALL_IPPASM    keccak_1600_partial_add_x4      ; arg2-arg5 are updated

        CALL_IPPASM    keccak_1600_load_state_x4
        CALL_IPPASM    keccak1600_block_64bit
        mov     qword [arg1 + 8*100], 0         ; clear s[100]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        ; r10/state, arg2-arg5/inputs, r12/length
        mov     r10, arg1
        mov     r12, arg6
        CALL_IPPASM    keccak_1600_partial_add_x4
        lea     r15, [arg6 + r14]
        mov     [arg1 + 8*100], r15     ; s[100] += inlen

        cmp     r15, SHAKE256_RATE      ; s[100] >= rate ?
        jb      .absorb_exit

        CALL_IPPASM    keccak_1600_load_state_x4
        CALL_IPPASM    keccak1600_block_64bit
        CALL_IPPASM    keccak_1600_save_state_x4
        mov     qword [arg1 + 8*100], 0 ; clear s[100]
        jmp     .absorb_exit

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state_x4

.absorb_partial_block_done:
        mov     r11, arg6               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHAKE256_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES_x4 arg2, arg3, arg4, arg5, r12, SHAKE256_RATE   ; 4 x input, offset, rate

        sub     r11, SHAKE256_RATE              ; Subtract the rate from the remaining length
        add     r12, SHAKE256_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:
        CALL_IPPASM    keccak_1600_save_state_x4

        mov     [arg1 + 8*100], r11    ; update s[100]
        or      r11, r11
        jz      .absorb_exit

        mov     qword [arg1 + 8*100], 0 ; clear s[100]

        ; r10/state, arg2-arg5/input, r12/length
        mov     r10, arg1
        add     arg2, r12
        add     arg3, r12
        add     arg4, r12
        add     arg5, r12
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add_x4

        mov     [arg1 + 8*100], r11    ; update s[100]

.absorb_exit:

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_AbsorbMB4

;;
;; void
;; cp_SHA3_SHAKE256_SqueezeMB4(Ipp8u* out0,
;;                                       Ipp8u* out1, Ipp8u* out2,
;;                                       Ipp8u* out3, Ipp64u outlen,
;;                                       cpSHA3_SHAKE256Ctx_mb4* state)
;;      arg1 - out0, pointer to output buffer lane 0 to extract into
;;      arg2 - out1, pointer to output buffer lane 1 to extract into
;;      arg3 - out2, pointer to output buffer lane 2 to extract into
;;      arg4 - out3, pointer to output buffer lane 3 to extract into
;;      arg5 - length, number of bytes to extract into each output buffer
;;      arg6 - state, x4 keccak1600 state
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_SqueezeMB4, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 6

        or      arg5, arg5
        jz      .squeeze_done

        mov     arg6, [arg6]            ; arg6 - state.ctx

        ; check for partially processed block
        mov     r15, [arg6 + 8*100]     ; s[100] - capacity
        or      r15, r15
        jnz     .squeeze_no_init_permute

        mov     r14, arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_load_state_x4
        mov     arg1, r14

        xor     rax, rax
        jmp     .squeeze_loop

align IPP_ALIGN_FACTOR
.squeeze_no_init_permute:
        ; extract bytes: r10 - state/src, arg1-arg4 - output/dst, r12 - length = min(capacity, outlen), r11 - offset
        mov     r10, arg6

        mov     r12, r15
        cmp     arg5, r15
        cmovb   r12, arg5               ; r12 = min(capacity, outlen)

        sub     arg5, r12               ; outlen -= length

        mov     r11d, SHAKE256_RATE
        sub     r11, r15                ; state offset

        sub     r15, r12                ; capacity -= length
        mov     [arg6 + 8*100], r15     ; update s[100]

        CALL_IPPASM    keccak_1600_extract_bytes_x4

        or      r15, r15
        jnz     .squeeze_done           ; s[100] != 0 ?

        mov     r14, arg1               ; preserve arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_load_state_x4
        mov     arg1, r14

        xor     rax, rax

align IPP_ALIGN_FACTOR
.squeeze_loop:
        cmp     arg5, SHAKE256_RATE     ; outlen > r
        jb      .squeeze_final_extract

        CALL_IPPASM    keccak1600_block_64bit

        ; Extract SHAKE256 rate bytes into the destination buffer
        STATE_EXTRACT_x4 arg1, arg2, arg3, arg4, rax, (SHAKE256_RATE / 8)

        add     rax, SHAKE256_RATE      ; dst offset += r
        sub     arg5, SHAKE256_RATE     ; outlen -= r
        jmp     .squeeze_loop

align IPP_ALIGN_FACTOR
.squeeze_final_extract:
        
        or      arg5, arg5
        jz      .squeeze_no_end_permute

        ;; update output pointers
        add     arg1, rax
        add     arg2, rax
        add     arg3, rax
        add     arg4, rax

        mov     r15d, SHAKE256_RATE
        sub     r15, arg5
        mov     [arg6 + 8*100], r15     ; s[100] = c

        CALL_IPPASM    keccak1600_block_64bit

        mov     r14, arg1
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_save_state_x4
        mov     arg1, r14

        ; extract bytes: r10 - state/src, arg1-arg4 - output/dst, r12 - length, r11 - offset = 0
        mov     r10, arg6
        mov     r12, arg5
        xor     r11, r11
        CALL_IPPASM    keccak_1600_extract_bytes_x4
        jmp     .squeeze_done

.squeeze_no_end_permute:
        mov     qword [arg6 + 8*100], 0 ; s[100] = 0
        mov     arg1, arg6
        CALL_IPPASM    keccak_1600_save_state_x4

.squeeze_done:

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_SqueezeMB4

section .rodata

;; SHAKE128 and SHAKE256 use the same terminator byte
align IPP_ALIGN_FACTOR
SHAKE_TERMINATOR_BYTE_x4:
        db 0, 0, 0, 0, 0, 0, 0, 0x80
        db 0, 0, 0, 0, 0, 0, 0, 0x80
        db 0, 0, 0, 0, 0, 0, 0, 0x80
        db 0, 0, 0, 0, 0, 0, 0, 0x80

;; SHAKE128 and SHAKE256 use the same multi-rate padding byte
align 8
        ;; This is not a mistake and these 8 zero bytes are required here.
        ;; Address is decremented depending on the offset within the state register.
        db 0, 0, 0, 0, 0, 0, 0, 0
SHAKE_MSG_PAD_x4:
        db SHAKE_MRATE_PADDING, 0, 0, 0, 0, 0, 0, 0
        db SHAKE_MRATE_PADDING, 0, 0, 0, 0, 0, 0, 0
        db SHAKE_MRATE_PADDING, 0, 0, 0, 0, 0, 0, 0
        db SHAKE_MRATE_PADDING, 0, 0, 0, 0, 0, 0, 0

%endif ; %if (_IPP32E >= _IPP32E_K0)
