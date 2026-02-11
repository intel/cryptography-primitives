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

section .text align=IPP_ALIGN_FACTOR

;;
;; void
;; cp_SHA3_224_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_224_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHA3_224_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg3, r12               ; if mlen < capacity then cannot permute yet
        jb      .absorb_skip_permute

        mov     r10, arg3
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        mov     arg3, arg2
        CALL_IPPASM    keccak_1600_partial_add
        mov     arg3, r10

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit

        mov     qword [arg1 + 8*25], 0  ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]
        add     arg1, r14               ; state += s[25]
        jmp     .absorb_final_partial_add

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHA3_224_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHA3_224_RATE   ; input, offset, rate

        sub     r11, SHA3_224_RATE              ; Subtract the rate from the remaining length
        add     r12, SHA3_224_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit   ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:

        CALL_IPPASM    keccak_1600_save_state
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]

.absorb_final_partial_add:
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_224_Absorb

;;
;; void
;; cp_SHA3_256_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_256_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHA3_256_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg3, r12               ; if mlen < capacity then cannot permute yet
        jb      .absorb_skip_permute

        mov     r10, arg3
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        mov     arg3, arg2
        CALL_IPPASM    keccak_1600_partial_add
        mov     arg3, r10

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit

        mov     qword [arg1 + 8*25], 0  ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]
        add     arg1, r14               ; state += s[25]
        jmp     .absorb_final_partial_add

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHA3_256_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHA3_256_RATE   ; input, offset, rate

        sub     r11, SHA3_256_RATE              ; Subtract the rate from the remaining length
        add     r12, SHA3_256_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:

        CALL_IPPASM    keccak_1600_save_state
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]

.absorb_final_partial_add:
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_256_Absorb

;;
;; void
;; cp_SHA3_384_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_384_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHA3_384_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg3, r12               ; if mlen < capacity then cannot permute yet
        jb      .absorb_skip_permute

        mov     r10, arg3
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        mov     arg3, arg2
        CALL_IPPASM    keccak_1600_partial_add
        mov     arg3, r10

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit

        mov     qword [arg1 + 8*25], 0  ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]
        add     arg1, r14               ; state += s[25]
        jmp     .absorb_final_partial_add

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHA3_384_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHA3_384_RATE   ; input, offset, rate

        sub     r11, SHA3_384_RATE              ; Subtract the rate from the remaining length
        add     r12, SHA3_384_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:

        CALL_IPPASM    keccak_1600_save_state
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]

.absorb_final_partial_add:
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_384_Absorb

;;
;; void
;; cp_SHA3_512_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_512_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHA3_512_RATE      ; c = rate - s[25]
        sub     r12, r14                ; r12 = capacity

        cmp     arg3, r12               ; if mlen < capacity then cannot permute yet
        jb      .absorb_skip_permute

        mov     r10, arg3
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        mov     arg3, arg2
        CALL_IPPASM    keccak_1600_partial_add
        mov     arg3, r10

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit

        mov     qword [arg1 + 8*25], 0         ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]
        add     arg1, r14               ; state += s[25]
        jmp     .absorb_final_partial_add

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHA3_512_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHA3_512_RATE   ; input, offset, rate

        sub     r11, SHA3_512_RATE              ; Subtract the rate from the remaining length
        add     r12, SHA3_512_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:

        CALL_IPPASM    keccak_1600_save_state
        add     [arg1 + 8*25], r11      ; store partially processed length in s[25]

.absorb_final_partial_add:
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_512_Absorb

;;
;; void
;; cp_SHA3_SHAKE128_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE128_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHAKE128_RATE
        sub     r12, r14                ; r12 = capacity = rate - s[25]

        cmp     arg3, r12               ; if mlen <= capacity then no permute
        jbe     .absorb_skip_permute

        sub     arg3, r12

        ; r13/state, arg2/input, r12/length
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        CALL_IPPASM    keccak_1600_partial_add ; arg2 is updated

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit
        mov     qword [arg1 + 8*25], 0         ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        lea     r10, [arg3 + r14]
        mov     [arg1 + 8*25], r10      ; s[25] += inlen
        ; r13/state, arg2/input, r12/length
        lea     r13, [arg1 + r14]       ; state + s[25]
        mov     r12, arg3
        CALL_IPPASM    keccak_1600_partial_add

        cmp     r10, SHAKE128_RATE      ; s[25] >= rate ?
        jb      .absorb_exit

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit
        CALL_IPPASM    keccak_1600_save_state
        mov     qword [arg1 + 8*25], 0         ; clear s[25]
        jmp     .absorb_exit

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHAKE128_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHAKE128_RATE   ; input, offset, rate

        sub     r11, SHAKE128_RATE              ; Subtract the rate from the remaining length
        add     r12, SHAKE128_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:
        CALL_IPPASM    keccak_1600_save_state

        mov     [arg1 + 8*25], r11      ; update s[25]
        or      r11, r11
        jz      .absorb_exit

        ; r13/state, arg2/input, r12/length
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

.absorb_exit:
        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE128_Absorb

;;
;; void
;; cp_SHA3_SHAKE256_Absorb(void *state, const Ipp8u *input, Ipp64u inlen);
;; Input:
;;   - state/arg1: pointer to the state
;;   - input/arg2: pointer to the input message
;;   - inlen/arg3: length of the input message in bytes
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_Absorb, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 3

        mov     arg1, [arg1]            ; state.ctx into arg1

        ; check for partially processed block
        mov     r14, [arg1 + 8*25]
        or      r14, r14                ; s[25] == 0?
        je      .absorb_main_loop_start

        ; process remaining bytes if message long enough
        mov     r12, SHAKE256_RATE
        sub     r12, r14                ; r12 = capacity = rate - s[25]

        cmp     arg3, r12               ; if mlen <= capacity then no permute
        jbe     .absorb_skip_permute

        sub     arg3, r12

        ; r13/state, arg2/input, r12/length
        lea     r13, [arg1 + r14]       ; r13 = state + s[25]
        CALL_IPPASM    keccak_1600_partial_add ; arg2 is updated

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit
        mov     qword [arg1 + 8*25], 0         ; clear s[25]
        jmp     .absorb_partial_block_done

.absorb_skip_permute:
        lea     r10, [arg3 + r14]
        mov     [arg1 + 8*25], r10      ; s[25] += inlen
        ; r13/state, arg2/input, r12/length
        lea     r13, [arg1 + r14]       ; state + s[25]
        mov     r12, arg3
        CALL_IPPASM    keccak_1600_partial_add

        cmp     r10, SHAKE256_RATE      ; s[25] >= rate ?
        jb      .absorb_exit

        CALL_IPPASM    keccak_1600_load_state
        CALL_IPPASM    keccak1600_block_64bit
        CALL_IPPASM    keccak_1600_save_state
        mov     qword [arg1 + 8*25], 0         ; clear s[25]
        jmp     .absorb_exit

.absorb_main_loop_start:
        CALL_IPPASM    keccak_1600_load_state

.absorb_partial_block_done:
        mov     r11, arg3               ; copy message length to r11
        xor     r12, r12                ; zero message offset

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.absorb_while_loop:
        cmp     r11, SHAKE256_RATE      ; compare mlen to rate
        jb      .absorb_while_loop_done

        ABSORB_BYTES arg2, r12, SHAKE256_RATE   ; input, offset, rate

        sub     r11, SHAKE256_RATE              ; Subtract the rate from the remaining length
        add     r12, SHAKE256_RATE              ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit          ; Perform the Keccak permutation
        jmp     .absorb_while_loop

align IPP_ALIGN_FACTOR
.absorb_while_loop_done:
        CALL_IPPASM    keccak_1600_save_state

        mov     [arg1 + 8*25], r11      ; update s[25]
        or      r11, r11
        jz      .absorb_exit

        ; r13/state, arg2/input, r12/length
        add     arg2, r12
        mov     r13, arg1
        mov     r12, r11
        CALL_IPPASM    keccak_1600_partial_add

.absorb_exit:
        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_Absorb

;;
;; void
;; cp_SHA3_SHAKE256_HashMessage(Ipp8u *output,
;;                           Ipp64u outlen,
;;                           const Ipp8u *input,
;;                           Ipp64u inplen);
;; Input:
;;   - output/arg1: pointer to the output buffer for the message digest
;;   - outlen/arg2: length of the output buffer in bytes
;;   - input/arg3: pointer to the input message
;;   - inplen/arg4: length of the input message in bytes
;;
;; Output:
;;   - The function computes the SHAKE256 message digest of the input message and stores it in the output buffer.
align IPP_ALIGN_FACTOR
IPPASM cp_SHA3_SHAKE256_HashMessage, PUBLIC
        USES_GPR NONVOLATILE_REGS_LIN64_GPR NONVOLATILE_REGS_WIN64_GPR
        USES_XMM_AVX NONVOLATILE_REGS_WIN64_YMM
        COMP_ABI 4      

        sub     rsp, 32 * 8

        mov     r9d, SHAKE256_RATE      ; Initialize the rate for SHAKE256
        mov     r11, arg4               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        xor     r10, r10

        ; Initialize the state array to zero
        CALL_IPPASM    keccak_1600_init_state

        ; Process the input message in blocks
align IPP_ALIGN_FACTOR
.loop:
        cmp     r11, r9
        jb      .loop_done

        ABSORB_BYTES arg3, r12, SHAKE256_RATE

        sub     r11, r9                 ; Subtract the rate from the remaining length
        add     r12, r9                 ; Adjust the pointer to the next block of the input message
        CALL_IPPASM    keccak1600_block_64bit  ; Perform the Keccak permutation
        jmp     .loop

align IPP_ALIGN_FACTOR
.loop_done:
        mov             r13, rsp        ; dst pointer
        add             r12, arg3       ; src pointer
        ;; r11 is length in bytes already
        ;; r9 is rate in bytes already
        lea             r8, [rel SHAKE_MULTI_RATE_PADDING]
        CALL_IPPASM            keccak_1600_copy_with_padding

        ;; Add padded block to the state
        ABSORB_BYTES    rsp, 0, SHAKE256_RATE
        CALL_IPPASM    keccak1600_block_64bit

align IPP_ALIGN_FACTOR
.continuexof:
        cmp     arg2, r9
        jb      .store_last_block

        ; Store the state into the digest buffer
        STATE_EXTRACT arg1, r10, (SHAKE256_RATE / 8)
        CALL_IPPASM    keccak1600_block_64bit  ; Perform the Keccak permutation

        sub     arg2, r9                ; Subtract the rate from the remaining length
        jz      .done                   ; If equal, jump to the done label
        add     r10, SHAKE256_RATE      ; Adjust the output digest pointer for the next block

        jmp     .continuexof

align IPP_ALIGN_FACTOR
.store_last_block:
        ; Store the state for the last block of SHAKE256 in the temporary buffer
        STATE_EXTRACT rsp, 0, (SHAKE256_RATE / 8)

        ; Copy digest from the buffer to the output buffer byte by byte
        lea     r13, [arg1 + r10]
        mov     r12, rsp
        ;; arg2 is length in bytes
        CALL_IPPASM    keccak_1600_copy_digest

.done:
        add     rsp, 32 * 8
        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC cp_SHA3_SHAKE256_HashMessage

section .rodata

SHA3_MULTI_RATE_PADDING:
;; Multi-rate padding byte (added right after the message)
;; 0x06 for SHA3-224, SHA3-256, SHA3-384 and SHA3-512
        DB 0x06

SHAKE_MULTI_RATE_PADDING:
;; Multi-rate padding byte (added right after the message)
;; 0x1F for SHAKE128 and SHAKE256
        DB 0x1F

%endif ; %if (_IPP32E >= _IPP32E_K0)
