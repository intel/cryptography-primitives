;*************************************************************************
; Copyright (C) 2026 Intel Corporation
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
;************************************************************************/

;
;     Purpose:  Cryptography Primitive.
;               P-256 IFMA dual Montgomery multiplication (AVX-512 IFMA)
;
;     This file implements dual Montgomery multiplication for P-256
;     using AVX-512 IFMA instructions.
;     The implementation keeps all operands in ZMM registers to avoid
;     stack memory usage for security-critical operations.
;

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "reg_sizes.inc"

; Only compile for K1 (Icelake) and later which have AVX-512 IFMA
%if (_IPP32E >= _IPP32E_K1)

;; ============================================================================
;; K mask register allocation
;; ============================================================================
%define K_EL0_MASK      k1      ; 0x01 - element 0 only for MUL_RED_ROUND
%define K_SHIFT_MASK    k2      ; 0x00ffffffffffffff - shift mask for MUL_RED_ROUND
%define K_CARRY_MASK    k3      ; 0xffffffffffffff00 - carry shift mask for LNORM/NORM

;; ============================================================================
;; Read-only data section for constants
;; ============================================================================
section .rodata align=64

align 64
one: dq 1, 0, 0, 0, 0, 0, 0, 0

; P-256 modulus in radix 2^52 representation (must match p256_x1 in C code)
align 64
p256_modulus:
    dq 0x000fffffffffffff   ; limb 0
    dq 0x00000fffffffffff   ; limb 1 (44 ones)
    dq 0x0000000000000000   ; limb 2
    dq 0x0000001000000000   ; limb 3 (bit 36 set)
    dq 0x0000ffffffff0000   ; limb 4
    dq 0x0                  ; limb 5
    dq 0x0                  ; limb 6
    dq 0x0                  ; limb 7

; Index patterns for vpermb (broadcast Bi)
align 64
idx_b0: dq 0x0706050403020100    ; broadcast B[0]
idx_b1: dq 0x0f0e0d0c0b0a0908    ; broadcast B[1]
idx_b2: dq 0x1716151413121110    ; broadcast B[2]
idx_b3: dq 0x1f1e1d1c1b1a1918    ; broadcast B[3]
idx_b4: dq 0x2726252423222120    ; broadcast B[4]
idx_b5: dq 0x2f2e2d2c2b2a2928    ; broadcast B[5]

; Index pattern for right shift by 64 bits (shift one limb)
align 64
idx_sr64:
    dq 0x0f0e0d0c0b0a0908   ; move qword 1 to qword 0
    dq 0x1716151413121110   ; move qword 2 to qword 1
    dq 0x1f1e1d1c1b1a1918   ; move qword 3 to qword 2
    dq 0x2726252423222120   ; move qword 4 to qword 3
    dq 0x2f2e2d2c2b2a2928   ; move qword 5 to qword 4
    dq 0x3736353433323130   ; move qword 6 to qword 5
    dq 0x3f3e3d3c3b3a3938   ; move qword 7 to qword 6
    dq 0x0                  ; qword 7 becomes 0

; Index pattern for carry shift (shift left by 8 bytes)
align 64
idx_carry_shift:
    dq 0x0                  ; qword 0 becomes 0
    dq 0x0706050403020100   ; move qword 0 to qword 1
    dq 0x0f0e0d0c0b0a0908   ; move qword 1 to qword 2
    dq 0x1716151413121110   ; move qword 2 to qword 3
    dq 0x1f1e1d1c1b1a1918   ; move qword 3 to qword 4
    dq 0x2726252423222120   ; move qword 4 to qword 5
    dq 0x2f2e2d2c2b2a2928   ; move qword 5 to qword 6
    dq 0x3736353433323130   ; move qword 6 to qword 7

; Constants for normalization
align 64
digit_mask_x8:
    times 8 dq 0x000fffffffffffff   ; DIGIT_MASK = 2^52 - 1
one_x8:
    times 8 dq 1
mone_x8:
    times 8 dq 0xffffffffffffffff   ; -1 (all ones)

; Scaled modulus constants for point operations
align 64
p256_x2:    ; 2*p256
    dq 0x000ffffffffffffe
    dq 0x00001fffffffffff
    dq 0x0000000000000000
    dq 0x0000002000000000
    dq 0x0001fffffffe0000
    dq 0x0
    dq 0x0
    dq 0x0

align 64
p256_x4:    ; 4*p256
    dq 0x000ffffffffffffc
    dq 0x00003fffffffffff
    dq 0x0000000000000000
    dq 0x0000004000000000
    dq 0x0003fffffffc0000
    dq 0x0
    dq 0x0
    dq 0x0

align 64
p256_x8:    ; 8*p256
    dq 0x000ffffffffffff8
    dq 0x00007fffffffffff
    dq 0x0000000000000000
    dq 0x0000008000000000
    dq 0x0007fffffff80000
    dq 0x0
    dq 0x0
    dq 0x0

;; ============================================================================
;; Code section
;; ============================================================================
section .text align=IPP_ALIGN_FACTOR

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; MUL_RED_ROUND macro - One round of Montgomery multiplication reduction
;   1. Bi = broadcast(B[IDX])
;   2. temp2 = broadcast(B[i])
;   3. R += A * temp2 (low 52 bits)
;   4. temp1 = A * temp2 (high 52 bits)
;   5. temp2 = broadcast(R[0])
;   6. R += M * temp2 (low 52 bits)
;   7. temp1 += M * temp2 (high 52 bits)
;   8. temp2 = R[0] >> 52 (carry)
;   9. temp1 += temp2
;  10. R = R >> 64 (shift right by one limb)
;  11. R += temp1
;
; Prerequisites:
;   - k1 mask register must be set to 0x01 (element 0 only)
;   - k2 mask register must be set to 0x00ffffffffffffff (shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro MUL_RED_ROUND 8
%define %%R         %1   ;; [in/out] ZMM register with accumulator
%define %%A         %2   ;; [in] ZMM register with first operand
%define %%B         %3   ;; [in] ZMM register with second operand
%define %%idx_b     %4   ;; [in] ZMM register with broadcast index for round i
%define %%idx_b0    %5   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64  %6   ;; [in] ZMM register with shift index
%define %%temp1     %7   ;; [temp] ZMM register for high product
%define %%temp2     %8   ;; [temp] ZMM register for temporary

    ; temp2 = broadcast(B[i])
    vpermb  %%temp2, %%idx_b, %%B

    ; R += A * temp2 (low 52 bits), temp1 = A * temp2 (high 52 bits)
    vpmadd52luq %%R, %%A, %%temp2
    vpxorq  %%temp1, %%temp1, %%temp1
    vpmadd52huq %%temp1, %%A, %%temp2

    ; temp2 = broadcast(R[0])
    vpermb  %%temp2, %%idx_b0, %%R

    ; R += M * temp2, temp1 += M * temp2
    vpmadd52luq %%R, %%temp2, [rel p256_modulus]
    vpmadd52huq %%temp1, %%temp2, [rel p256_modulus]

    ; temp2 = R[0] >> 52 (carry)
    vpsrlq  %%temp2{K_EL0_MASK}{z}, %%R, 52

    ; temp1 += temp2
    vpaddq  %%temp1, %%temp1, %%temp2

    ; R = R >> 64 (shift right by one limb)
    vpermb  %%R{K_SHIFT_MASK}{z}, %%idx_sr64, %%R

    ; R += temp1
    vpaddq  %%R, %%R, %%temp1
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_AMM52_DUAL_P256_BODY macro - Body of dual Montgomery multiplication
;
; This macro contains all the computational logic for dual Montgomery 
; multiplication: r1 = a1 * b1 mod p256 and r2 = a2 * b2 mod p256
;
; Prerequisites:
;   - K_EL0_MASK (k1) must be set to 0x01 (element 0 only)
;   - K_SHIFT_MASK (k2) must be set to 0x00ffffffffffffff (shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_AMM52_DUAL_P256_BODY 11
%define %%t1            %1   ;; [out] ZMM register for result of mult 1
%define %%t2            %2   ;; [out] ZMM register for result of mult 2
%define %%a1            %3   ;; [in] ZMM register with first operand 1
%define %%b1            %4   ;; [in] ZMM register with second operand 1
%define %%a2            %5   ;; [in] ZMM register with first operand 2
%define %%b2            %6   ;; [in] ZMM register with second operand 2
%define %%idx_b0        %7   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64      %8   ;; [in] ZMM register with shift index
%define %%temp1         %9   ;; [temp] ZMM register for MUL_RED_ROUND
%define %%temp2         %10  ;; [temp] ZMM register for scratch
%define %%idx_b_round   %11  ;; [temp] ZMM register for round-specific idx_b

        ;; Zero result accumulators
        vpxorq  %%t1, %%t1, %%t1
        vpxorq  %%t2, %%t2, %%t2

        ;; Round 0
        vpbroadcastq %%idx_b_round, qword [rel idx_b0]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 1
        vpbroadcastq %%idx_b_round, qword [rel idx_b1]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 2
        vpbroadcastq %%idx_b_round, qword [rel idx_b2]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 3
        vpbroadcastq %%idx_b_round, qword [rel idx_b3]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 4
        vpbroadcastq %%idx_b_round, qword [rel idx_b4]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 5
        vpbroadcastq %%idx_b_round, qword [rel idx_b5]
        MUL_RED_ROUND %%t1, %%a1, %%b1, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
        MUL_RED_ROUND %%t2, %%a2, %%b2, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_LNORM52_P256_BODY macro - Light normalization for single field element
;
; Performs carry propagation without full modular reduction.
; Uses memory operands for constants where possible to reduce register pressure.
;
; Prerequisites:
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_LNORM52_P256_BODY 5
%define %%r                 %1   ;; [in/out] ZMM register with value to normalize
%define %%idx_carry_shift   %2   ;; [in] ZMM register with carry shift index
%define %%carry             %3   ;; [temp] ZMM register for carry
%define %%KREG_tmp1         %4   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %5   ;; [clobber] k register for temporary mask

        ; Extract carry (arithmetic right shift by 52)
        vpsraq  %%carry, %%r, 52

        ; Shift carry left by one qword position
        vpermb  %%carry{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry

        ; Mask to 52 bits
        vpandq  %%r, %%r, [rel digit_mask_x8]

        ; Add carry
        vpaddq  %%r, %%r, %%carry

        ; Overflow handling (uses %%KREG_tmp1, %%KREG_tmp2)
        vpcmpuq  %%KREG_tmp1, %%r, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1

        ; Add 1 where overflow detected
        vpaddq  %%r{%%KREG_tmp2}, %%r, [rel one_x8]

        ; Final mask to 52 bits
        vpandq  %%r, %%r, [rel digit_mask_x8]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_LNORM52_DUAL_P256_BODY macro - Light normalization for two field elements
;
; Performs carry propagation on two elements without full modular reduction.
; Uses memory operands for constants where possible to reduce register pressure.
;
; Prerequisites:
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_LNORM52_DUAL_P256_BODY 7
%define %%r1                %1   ;; [in/out] ZMM register with first value to normalize
%define %%r2                %2   ;; [in/out] ZMM register with second value to normalize
%define %%idx_carry_shift   %3   ;; [in] ZMM register with carry shift index
%define %%carry1            %4   ;; [temp] ZMM register for carry 1
%define %%carry2            %5   ;; [temp] ZMM register for carry 2
%define %%KREG_tmp1         %6   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %7   ;; [clobber] k register for temporary mask

        ; Extract carries (arithmetic right shift by 52)
        vpsraq  %%carry1, %%r1, 52
        vpsraq  %%carry2, %%r2, 52

        ; Shift carries left by one qword position
        vpermb  %%carry1{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry1
        vpermb  %%carry2{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry2

        ; Mask to 52 bits
        vpandq  %%r1, %%r1, [rel digit_mask_x8]
        vpandq  %%r2, %%r2, [rel digit_mask_x8]

        ; Add carries
        vpaddq  %%r1, %%r1, %%carry1
        vpaddq  %%r2, %%r2, %%carry2

        ; Overflow handling for r1 (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch)
        vpcmpuq  %%KREG_tmp1, %%r1, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r1, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        
        ; Add 1 where overflow detected
        vpaddq  %%r1{%%KREG_tmp2}, %%r1, [rel one_x8]

        ; Overflow handling for r2 (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch)
        vpcmpuq  %%KREG_tmp1, %%r2, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r2, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1

        ; Add 1 where overflow detected
        vpaddq  %%r2{%%KREG_tmp2}, %%r2, [rel one_x8]

        ; Final mask to 52 bits
        vpandq  %%r1, %%r1, [rel digit_mask_x8]
        vpandq  %%r2, %%r2, [rel digit_mask_x8]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_AMM52_LNORM_P256_BODY macro - Body of Montgomery multiplication followed
; by a light normalization step
;
; This macro contains all the computational logic for Montgomery 
; multiplication: r = a * b mod p256 followed by carry propagation without
; full modular reduction.
;
; Prerequisites:
;   - K_EL0_MASK (k1) must be set to 0x01 (element 0 only)
;   - K_SHIFT_MASK (k2) must be set to 0x00ffffffffffffff (shift mask)
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_AMM52_LNORM_P256_BODY 12
%define %%r             %1   ;; [in/out] ZMM register with accumulator for mult
%define %%a             %2   ;; [in] ZMM register with first operand
%define %%b             %3   ;; [in] ZMM register with second operand
%define %%idx_b0        %4   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64      %5   ;; [in] ZMM register with shift index
%define %%tmp           %6   ;; [temp] ZMM register for MUL_RED_ROUND
%define %%scratch1      %7   ;; [temp] ZMM register for scratch
%define %%scratch2      %8   ;; [temp] ZMM register for scratch
%define %%idx_b_round   %9   ;; [temp] ZMM register for round-specific idx_b
%define %%GP_tmp1      %10   ;; [temp] GPR for scratch
%define %%KREG_tmp1    %11   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2    %12   ;; [clobber] k register for temporary mask

        ; Perform multiplication
        vpxorq    %%r, %%r, %%r                    ; accumulator r = 0
        IFMA_AMM52_P256_BODY %%r, %%a, %%b, %%idx_b0, %%idx_sr64, %%tmp, %%scratch1, %%idx_b_round

        ; Perform normalization
        vmovdqu64 %%scratch1, [rel idx_carry_shift]
        IFMA_LNORM52_P256_BODY %%r, %%scratch1, %%scratch2, %%KREG_tmp1, %%KREG_tmp2
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_AMS52_LNORM_NTIMES_P256_BODY macro - Body of series of N Montgomery
; squarings followed by a light normalization step.
;
; This macro contains all the computational logic for Montgomery 
; squaring: r = a * a mod p256 followed by carry propagation without
; full modular reduction.
;
; Prerequisites:
;   - K_EL0_MASK (k1) must be set to 0x01 (element 0 only)
;   - K_SHIFT_MASK (k2) must be set to 0x00ffffffffffffff (shift mask)
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_AMS52_LNORM_NTIMES_P256_BODY 13
%define %%r             %1   ;; [in/out] ZMM register with accumulator to be squared
%define %%idx_b0        %2   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64      %3   ;; [in] ZMM register with shift index
%define %%N             %4   ;; [in] immediate or GPR specifying the number of iterations
%define %%a             %5   ;; [temp] ZMM register to temporary hold squared accumulator 
%define %%tmp           %6   ;; [temp] ZMM register for MUL_RED_ROUND
%define %%scratch1      %7   ;; [temp] ZMM register for scratch
%define %%scratch2      %8   ;; [temp] ZMM register for scratch
%define %%idx_b_round   %9   ;; [temp] ZMM register for round-specific idx_b
%define %%GP_loop_cnt   %10  ;; [clobber] GPR for loop counter
%define %%GP_tmp1       %11  ;; [clobber] GPR for scratch
%define %%KREG_tmp1     %12  ;; [clobber] k register for temporary mask
%define %%KREG_tmp2     %13  ;; [clobber] k register for temporary mask

        mov DWORD(%%GP_loop_cnt), %%N
%%loop:
        vmovdqa64 %%a, %%r
        IFMA_AMM52_LNORM_P256_BODY %%r, %%a, %%a, %%idx_b0, %%idx_sr64, %%tmp, %%scratch1, \
                                   %%scratch2, %%idx_b_round, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        dec DWORD(%%GP_loop_cnt)
        jnz %%loop
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; BORROW_PROPAGATE_KREG macro - Borrow propagation using k-register operations
;
; Computes borrow propagation mask and applies -1 to elements that need it.

;   k_ge1 = elements >= 1 (don't need incoming borrow)
;   k_neg = elements < 0 (are negative, generate borrow)
;   k_out = k_neg | (~k_ge1 & (k_neg << 1))  ; propagate borrows
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro BORROW_PROPAGATE_KREG 5
%define %%r      %1   ;; [in/out] ZMM register to process
%define %%zero   %2   ;; [in] ZMM register containing zero
%define %%k_ge1  %3   ;; [temp] k register for >= 1 comparison
%define %%k_neg  %4   ;; [temp] k register for < 0 comparison
%define %%k_out  %5   ;; [temp] k register for output mask

        vpcmpq  %%k_ge1, %%r, [rel one_x8], 5                                           ;; k_ge1 = (r >= 1)
        vpcmpq  %%k_neg, %%r, %%zero, 1                                                 ;; k_neg = (r < 0)
        kshiftlb %%k_out, %%k_neg, 1                                                    ;; k_out = k_neg << 1 (propagate)
        kandn   %%k_out, %%k_ge1, %%k_out                                               ;; k_out = ~k_ge1 & (k_neg << 1)
        kor     %%k_out, %%k_out, %%k_neg                                               ;; k_out = final borrow mask
        vpaddq  %%r{%%k_out}, %%r, [rel mone_x8]                                        ;; r -= 1 where borrow needed
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_NORM52_P256_BODY macro - Full normalization for single field element
;
; Performs carry propagation, overflow handling, and borrow handling.
; Uses memory operands for constants where possible to reduce register pressure.
;
; Prerequisites:
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_NORM52_P256_BODY 7
%define %%r                 %1   ;; [in/out] ZMM register with value to normalize
%define %%idx_carry_shift   %2   ;; [in] ZMM register with carry shift index
%define %%zero              %3   ;; [in] ZMM register with zero constant
%define %%carry             %4   ;; [temp] ZMM register for carry
%define %%KREG_tmp1         %5   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %6   ;; [clobber] k register for temporary mask
%define %%KREG_tmp3         %7   ;; [clobber] k register for temporary mask

        ; Carry propagation
        vpsraq  %%carry, %%r, 52
        vpermb  %%carry{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry
        vpandq  %%r, %%r, [rel digit_mask_x8]
        vpaddq  %%r, %%r, %%carry

        ; Overflow handling (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch)
        vpcmpuq  %%KREG_tmp1, %%r, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        vpaddq   %%r{%%KREG_tmp2}, %%r, [rel one_x8]

        ; Borrow handling using k-register operations
        BORROW_PROPAGATE_KREG %%r, %%zero, %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3

        ; Final mask to 52 bits
        vpandq  %%r, %%r, [rel digit_mask_x8]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_NORM52_DUAL_P256_BODY macro - Full normalization for two field elements
;
; Performs carry propagation, overflow handling, and borrow handling on two elements.
; Uses k-register operations for borrow propagation (no GPR needed).
;
; Prerequisites:
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_NORM52_DUAL_P256_BODY 9
%define %%r1                %1   ;; [in/out] ZMM register with first value to normalize
%define %%r2                %2   ;; [in/out] ZMM register with second value to normalize
%define %%idx_carry_shift   %3   ;; [in] ZMM register with carry shift index
%define %%zero              %4   ;; [in] ZMM register with zero constant
%define %%carry1            %5   ;; [temp] ZMM register for carry 1
%define %%carry2            %6   ;; [temp] ZMM register for carry 2
%define %%KREG_tmp1         %7   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %8   ;; [clobber] k register for temporary mask
%define %%KREG_tmp3         %9   ;; [clobber] k register for temporary mask

        ; Carry propagation for both
        vpsraq  %%carry1, %%r1, 52
        vpsraq  %%carry2, %%r2, 52
        vpermb  %%carry1{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry1
        vpermb  %%carry2{K_CARRY_MASK}{z}, %%idx_carry_shift, %%carry2
        vpandq  %%r1, %%r1, [rel digit_mask_x8]
        vpandq  %%r2, %%r2, [rel digit_mask_x8]
        vpaddq  %%r1, %%r1, %%carry1
        vpaddq  %%r2, %%r2, %%carry2

        ; Overflow handling for r1 (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch)
        vpcmpuq  %%KREG_tmp1, %%r1, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r1, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        vpaddq   %%r1{%%KREG_tmp2}, %%r1, [rel one_x8]

        ; Overflow handling for r2 (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch)
        vpcmpuq  %%KREG_tmp1, %%r2, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%r2, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        vpaddq  %%r2{%%KREG_tmp2}, %%r2, [rel one_x8]

        ; Borrow handling for r1 using k-register operations (%%KREG_tmp1, %%KREG_tmp2 and %%KREG_tmp3 as scratch)
        BORROW_PROPAGATE_KREG %%r1, %%zero, %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3

        ; Borrow handling for r2 using k-register operations (%%KREG_tmp1, %%KREG_tmp2 and %%KREG_tmp3 as scratch)
        BORROW_PROPAGATE_KREG %%r2, %%zero, %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3

        ; Final mask to 52 bits
        vpandq  %%r1, %%r1, [rel digit_mask_x8]
        vpandq  %%r2, %%r2, [rel digit_mask_x8]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_HALF52_P256_BODY macro - Halving (divide by 2) for single field element
;
; Computes r = r / 2 mod p256 in Montgomery domain.
;
; Uses directly from memory:
;   [rel p256_modulus] - the P-256 prime modulus
;   [rel digit_mask_x8] - 52-bit digit mask
;   [rel one_x8] - broadcast of 1
;
; Note: K_CARRY_MASK (k3) must be set if the caller needs normalized output.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_HALF52_P256_BODY 7
%define %%r                 %1   ;; [in/out] ZMM register with value to halve
%define %%idx_sr64          %2   ;; [in] ZMM register with shift right by 64 index
%define %%idx_carry_shift   %3   ;; [in] ZMM register with carry shift index
%define %%scratch           %4   ;; [temp] ZMM register for scratch
%define %%GP_tmp1           %5   ;; [clobber] GPR for scratch
%define %%KREG_tmp1         %6   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %7   ;; [clobber] k register for temporary mask

        ; Check if A is odd (bit 0 set in first element)
        vpandq    %%scratch, %%r, [rel one_x8]
        vptestnmq %%KREG_tmp1, %%scratch, %%scratch
        knotb     %%KREG_tmp2, %%KREG_tmp1
        kmovb     DWORD(%%GP_tmp1), %%KREG_tmp2
        and       DWORD(%%GP_tmp1), 1
        neg       DWORD(%%GP_tmp1)
        kmovb     %%KREG_tmp1, DWORD(%%GP_tmp1)
        ; If odd, add modulus before dividing
        vpaddq    %%r{%%KREG_tmp1}, %%r, [rel p256_modulus]

        ; Light normalization (uses K_CARRY_MASK for carry shift)
        vpsrlq  %%scratch, %%r, 52
        vpermb  %%scratch{K_CARRY_MASK}{z}, %%idx_carry_shift, %%scratch
        vpandq  %%r, %%r, [rel digit_mask_x8]
        vpaddq  %%r, %%r, %%scratch

        ; Overflow handling (uses %%KREG_tmp1, %%KREG_tmp2 as scratch)
        vpcmpeqq %%KREG_tmp1, %%r, [rel digit_mask_x8]
        vpcmpuq  %%KREG_tmp2, %%r, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp1
        vpaddq   %%r{%%KREG_tmp1}, %%r, [rel one_x8]
        vpandq   %%r, %%r, [rel digit_mask_x8]

        ; Right shift by 1 bit (uses K_SHIFT_MASK for permute)
        vpandq  %%scratch, %%r, [rel one_x8]
        vpermb  %%scratch{K_SHIFT_MASK}{z}, %%idx_sr64, %%scratch
        vpsllq  %%scratch, %%scratch, 51
        vpsrlq  %%r, %%r, 1
        vpaddq  %%r, %%r, %%scratch
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_AMINV52_P256_BODY macro - Inversion for single field element
;
; Computes 1/z mod p256 in Montgomery domain.
;
; Clobbers: GP_loop_cnt (via IFMA_AMS52_LNORM_NTIMES_P256_BODY)
;
; Prerequisites:
;   - K_EL0_MASK (k1) must be set to 0x01 (element 0 only)
;   - K_SHIFT_MASK (k2) must be set to 0x00ffffffffffffff (shift mask)
;   - K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_AMINV52_P256_BODY 20
%define %%r_out             %1   ;; [out] ZMM register with result
%define %%z_in              %2   ;; [in] ZMM register with value to invert
%define %%idx_b0            %3   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64          %4   ;; [in] ZMM register with shift index
%define %%tmp1              %5   ;; [temp] ZMM register with temporary calculations
%define %%scratch1          %6   ;; [temp] ZMM register for scratch
%define %%scratch2          %7   ;; [temp] ZMM register for scratch
%define %%scratch3          %8   ;; [temp] ZMM register for scratch
%define %%scratch4          %9   ;; [temp] ZMM register for scratch
%define %%scratch5          %10  ;; [temp] ZMM register for scratch
%define %%e2                %11  ;; [temp] ZMM register for calculated e2
%define %%e4                %12  ;; [temp] ZMM register for calculated e4
%define %%e8                %13  ;; [temp] ZMM register for calculated e8
%define %%e16               %14  ;; [temp] ZMM register for calculated e16
%define %%e32               %15  ;; [temp] ZMM register for calculated e32
%define %%e64               %16  ;; [temp] ZMM register for calculated e64
%define %%GP_loop_cnt       %17  ;; [clobber] GPR for loop counter
%define %%GP_tmp1           %18  ;; [clobber] GPR for scratch
%define %%KREG_tmp1         %19   ;; [clobber] k register for temporary mask
%define %%KREG_tmp2         %20   ;; [clobber] k register for temporary mask

        ; sqr(tmp1, z)
        vmovdqu64 %%tmp1, %%z_in
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 1, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp1, tmp1, z)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%z_in, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e2, %%tmp1         ; e2 = tmp1 

        ; sqr(tmp1, tmp1)
        ; sqr(tmp1, tmp1)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 2, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp1, tmp1, e2)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%e2, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e4, %%tmp1         ; e4 = tmp1

        ; sqr(tmp1, tmp1)
        ; sqr(tmp1, tmp1)
        ; sqr(tmp1, tmp1)
        ; sqr(tmp1, tmp1)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 4, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp1, tmp1, e4)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%e4, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e8, %%tmp1         ; e8 = tmp1

        ; sqr_ntimes(tmp1, tmp1, 8)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 8, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp1, tmp1, e8)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%e8, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e16, %%tmp1         ; e16 = tmp1

        ; sqr_ntimes(tmp1, tmp1, 16)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 16, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp1, tmp1, e16)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%e16, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e32, %%tmp1         ; e32 = tmp1

        ; sqr_ntimes(tmp1, tmp1, 32)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 32, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
        vmovdqa64 %%e64, %%tmp1         ; e64 = tmp1

        ; mul(tmp1, tmp1, z)
        vmovdqa64 %%scratch5, %%tmp1
        IFMA_AMM52_LNORM_P256_BODY %%tmp1, %%scratch5, %%z_in, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                           %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr_ntimes(tmp1, tmp1, 192)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%tmp1, %%idx_b0, %%idx_sr64, 192, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, e64, e32)
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%e64, %%e32, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr_ntimes(tmp2, tmp2, 16)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%r_out, %%idx_b0, %%idx_sr64, 16, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, tmp2, e16)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%e16, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr_ntimes(tmp2, tmp2, 8)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%r_out, %%idx_b0, %%idx_sr64, 8, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, tmp2, e8)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%e8, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr_ntimes(tmp2, tmp2, 4)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%r_out, %%idx_b0, %%idx_sr64, 4, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, tmp2, e4)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%e4, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr(tmp2, tmp2)
        ; sqr(tmp2, tmp2)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%r_out, %%idx_b0, %%idx_sr64, 2, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, tmp2, e2)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%e2, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; sqr(tmp2, tmp2)
        ; sqr(tmp2, tmp2)
        IFMA_AMS52_LNORM_NTIMES_P256_BODY %%r_out, %%idx_b0, %%idx_sr64, 2, %%scratch5, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                          %%GP_loop_cnt, %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(tmp2, tmp2, z)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%z_in, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2

        ; mul(r, tmp1, tmp2)
        vmovdqa64 %%scratch5, %%r_out
        IFMA_AMM52_LNORM_P256_BODY %%r_out, %%scratch5, %%tmp1, %%idx_b0, %%idx_sr64, %%scratch1, %%scratch2, %%scratch3, %%scratch4, \
                                            %%GP_tmp1, %%KREG_tmp1, %%KREG_tmp2
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; DOUBLE_PART macro - Point doubling for P-256 curve
;
; Computes R = 2*P for a point P on the P-256 curve.
; NOTE: Does NOT support in-place operation (out_R must be different from in_P).
;
; Constants pre-loaded into registers:
;   idx_b0         - broadcast index for element 0 (AMM52)
;   idx_carry_shift - carry shift index (LNORM/NORM)
;   idx_sr64       - shift right 64 index (AMM52)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro DOUBLE_PART 23
%define %%out_R_X       %1   ;; [out] ZMM register for X coordinate of result R
%define %%out_R_Y       %2   ;; [out] ZMM register for Y coordinate of result R
%define %%out_R_Z       %3   ;; [out] ZMM register for Z coordinate of result R
%define %%in_P_X        %4   ;; [in] ZMM register with X coordinate of point P
%define %%in_P_Y        %5   ;; [in] ZMM register with Y coordinate of point P
%define %%in_P_Z        %6   ;; [in] ZMM register with Z coordinate of point P
%define %%y2            %7   ;; [temp] ZMM register for y2 intermediate
%define %%T             %8   ;; [temp] ZMM register for T (2*y1)
%define %%U             %9   ;; [temp] ZMM register for U
%define %%V             %10  ;; [temp] ZMM register for V (4*y1^2)
%define %%A             %11  ;; [temp] ZMM register for A (4*x1*y1^2)
%define %%B             %12  ;; [temp] ZMM register for B
%define %%H             %13  ;; [temp] ZMM register for scratch
%define %%idx_b0        %14  ;; [in] idx_b0 (must be pre-loaded)
%define %%idx_carry_shift %15  ;; [in] idx_carry_shift (must be pre-loaded)
%define %%idx_sr64      %16  ;; [in] idx_sr64 (must be pre-loaded)
%define %%GP_tmp1       %17  ;; [clobber] GPR for scratch
%define %%GP_tmp2       %18  ;; [clobber] GPR for scratch
%define %%GP_tmp3       %19  ;; [clobber] GPR for scratch
%define %%GP_tmp4       %20  ;; [clobber] GPR for scratch
%define %%KREG_tmp1     %21  ;; [clobber] k register for temporary mask
%define %%KREG_tmp2     %22  ;; [clobber] k register for temporary mask
%define %%KREG_tmp3     %23  ;; [clobber] k register for temporary mask

        vpaddq  %%T, %%in_P_Y, %%in_P_Y                                                 ;; T = 2*y1
        IFMA_LNORM52_P256_BODY %%T, %%idx_carry_shift, %%H, \
                               %%KREG_tmp1, %%KREG_tmp2                                 ;; lnorm(T)

        IFMA_AMM52_DUAL_P256_BODY %%V, %%U, %%T, %%T, %%in_P_Z, %%in_P_Z, \
                                  %%idx_b0, %%idx_sr64, %%A, %%B, %%y2                  ;; V = T^2 = 4*y1^2, U = Z^2

        vpsubq  %%B, %%in_P_X, %%U                                                      ;; B = X - U
        vpaddq  %%B, %%B, [rel p256_x2]                                                 ;; B = X - U + p256_x2
        vpaddq  %%A, %%in_P_X, %%U                                                      ;; A = X + U

        IFMA_LNORM52_DUAL_P256_BODY %%V, %%A, %%idx_carry_shift, %%out_R_Z, %%H, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(V, A)

        vpxorq  %%out_R_Z, %%out_R_Z, %%out_R_Z                                         ;; out_R_Z = 0
        IFMA_NORM52_P256_BODY %%B, %%idx_carry_shift, %%out_R_Z, %%H, \
                              %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3                     ;; norm52(B)

        vmovdqa64 %%H, %%B                                                              ;; H = B (save before AMM52)
        IFMA_AMM52_DUAL_P256_BODY %%out_R_Y, %%B, %%V, %%in_P_X, %%H, %%A, \
                                  %%idx_b0, %%idx_sr64, %%y2, %%out_R_X, %%out_R_Z     ;; out_R_Y = V*X, B = H*A

        vpaddq  %%out_R_X, %%out_R_Y, %%out_R_Y                                         ;; out_R_X = 2*out_R_Y
        vpaddq  %%H, %%B, %%B                                                           ;; H = 2*B
        vpaddq  %%B, %%B, %%H                                                           ;; B = 3*B = l1

        IFMA_LNORM52_P256_BODY %%B, %%idx_carry_shift, %%H, \
                               %%KREG_tmp1, %%KREG_tmp2                                 ;; lnorm(B)

        IFMA_AMM52_DUAL_P256_BODY %%U, %%y2, %%B, %%B, %%V, %%V, \
                                  %%idx_b0, %%idx_sr64, %%H, %%A, %%out_R_Z            ;; U = B^2, y2 = V^2

        vpsubq  %%out_R_X, %%U, %%out_R_X                                               ;; out_R_X = U - out_R_X
        vpaddq  %%out_R_X, %%out_R_X, [rel p256_x4]                                     ;; out_R_X += p256_x4

        IFMA_HALF52_P256_BODY %%y2, %%idx_sr64, %%idx_carry_shift, %%V, %%GP_tmp1, \
                              %%KREG_tmp1, %%KREG_tmp2                                  ;; half52(y2)

        vpsubq  %%U, %%out_R_Y, %%out_R_X                                               ;; U = out_R_Y - out_R_X
        vpaddq  %%U, %%U, [rel p256_x8]                                                 ;; U += p256_x8

        vpxorq  %%H, %%H, %%H                                                           ;; H = 0 (for norm52)
        IFMA_NORM52_P256_BODY %%U, %%idx_carry_shift, %%H, %%V,  \
                              %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3                     ;; norm52(U)

        IFMA_AMM52_DUAL_P256_BODY %%out_R_Z, %%A, %%T, %%in_P_Z, %%U, %%B, \
                                  %%idx_b0, %%idx_sr64, %%V, %%out_R_Y, %%H            ;; out_R_Z = T*Z, A = U*B (T preserved from L1)

        vpsubq  %%out_R_Y, %%A, %%y2                                                    ;; out_R_Y = A - y2
        vpaddq  %%out_R_Y, %%out_R_Y, [rel p256_x2]                                     ;; out_R_Y += p256_x2

        vpxorq  %%H, %%H, %%H                                                           ;; H = 0 (for norm52_dual)
        IFMA_NORM52_DUAL_P256_BODY      %%out_R_X, %%out_R_Y, %%idx_carry_shift, \
                                        %%H, %%A, %%B, %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3
        IFMA_LNORM52_P256_BODY          %%out_R_Z, %%idx_carry_shift, %%H, \
                                        %%KREG_tmp1, %%KREG_tmp2
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ADD_PART macro - Point addition for P-256 curve
;
; Computes R = P + Q for points P and Q on the P-256 curve.
; Complete P-256 point addition with all special case handling in assembly.
;
; Algorithm (Enhanced Montgomery group):
;   A = x1*z2^2    B = x2*z1^2      C = y1*z2^3      D = y2*z1^3
;   E = B - A      F = D - C
;   x3 = -E^3 - 2*A*E^2 + F^2
;   y3 = -C*E^3 + F*(A*E^2 - x3)
;   z3 = z1*z2*E
;
; Special cases handled:
;   - p_is_inf: If P.z == 0, return Q
;   - q_is_inf: If Q.z == 0, return P
;   - point_is_equal: If E == 0 AND F == 0, call DOUBLE_PART
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ADD_PART 31
%define %%out_P_X         %1   ;; [out] ZMM register with output X coordinate of point P
%define %%out_P_Y         %2   ;; [out] ZMM register with output Y coordinate of point P
%define %%out_P_Z         %3   ;; [out] ZMM register with output Z coordinate of point P
%define %%in_P_X          %4   ;; [in] ZMM register with X coordinate of point P
%define %%in_P_Y          %5   ;; [in] ZMM register with Y coordinate of point P
%define %%in_P_Z          %6   ;; [in] ZMM register with Z coordinate of point P
%define %%in_Q_X          %7   ;; [in] ZMM register with X coordinate of point Q
%define %%in_Q_Y          %8   ;; [in] ZMM register with Y coordinate of point Q
%define %%in_Q_Z          %9   ;; [in] ZMM register with Z coordinate of point Q
%define %%U1              %10  ;; [clobber] ZMM register for U1 (A = x1*z2^2)
%define %%U2              %11  ;; [clobber] ZMM register for U2 (B = x2*z1^2)
%define %%S1              %12  ;; [clobber] ZMM register for S1 (C = y1*z2^3)
%define %%S2              %13  ;; [clobber] ZMM register for S2 (D = y2*z1^3)
%define %%H               %14  ;; [clobber] ZMM register for H (E = B - A)
%define %%R               %15  ;; [clobber] ZMM register for R (F = D - C)
%define %%T1              %16  ;; [clobber] ZMM register for scratch
%define %%T2              %17  ;; [clobber] ZMM register for scratch
%define %%T3              %18  ;; [clobber] ZMM register for scratch
%define %%T4              %19  ;; [clobber] ZMM register for scratch
%define %%T5              %20  ;; [clobber] ZMM register for scratch
%define %%idx_carry_shift %21  ;; [in] idx_carry_shift (must be pre-loaded)
%define %%idx_sr64        %22  ;; [in] idx_sr64 (must be pre-loaded)
%define %%idx_b0          %23  ;; [in] idx_b0 (must be pre-loaded)
%define %%KREG_tmp1       %24  ;; [clobber] k register for temporary mask
%define %%KREG_tmp2       %25  ;; [clobber] k register for temporary mask
%define %%KREG_tmp3       %26  ;; [clobber] k register for temporary mask
%define %%KREG_tmp4       %27  ;; [clobber] k register for temporary mask
%define %%GP_tmp1         %28  ;; [clobber] GPR for scratch
%define %%GP_tmp2         %29  ;; [clobber] GPR for scratch
%define %%GP_tmp3         %30  ;; [clobber] GPR for scratch
%define %%GP_tmp4         %31  ;; [clobber] GPR for scratch

        ;; ========== Check for infinity cases first ==========
        ;; Check if P.z == 0 (p_is_inf)
        vptestmq %%KREG_tmp1, %%in_P_Z, %%in_P_Z        ;; KREG_tmp1 = mask of non-zero qwords in P.z
        kmovb   DWORD(%%GP_tmp1), %%KREG_tmp1
        and     DWORD(%%GP_tmp1), 0x1F                  ;; only check lower 5 qwords
        neg     %%GP_tmp1                               ;; negative if any bit set, CF=1
        sbb     %%GP_tmp1, %%GP_tmp1
        not     %%GP_tmp1                               ;; GP_tmp1 = 0 if any bit set, else 1
        push    %%GP_tmp1                               ;; save to restore at the macro's end

        ;; Check if Q.z == 0 (q_is_inf)
        vptestmq %%KREG_tmp2, %%in_Q_Z, %%in_Q_Z        ;; KREG_tmp2 = mask of non-zero qwords in Q.z
        kmovb   DWORD(%%GP_tmp2), %%KREG_tmp2
        and     DWORD(%%GP_tmp2), 0x1F                  ;; only check lower 5 qwords
        neg     %%GP_tmp2                               ;; negative if any bit set, CF=1
        sbb     %%GP_tmp2, %%GP_tmp2
        not     %%GP_tmp2                               ;; GP_tmp2 = 0 if any bit set, else 1
        push    %%GP_tmp2                               ;; save to restore at the macro's end

        IFMA_AMM52_DUAL_P256_BODY %%S1, %%U1, %%in_P_Y, %%in_Q_Z, %%in_Q_Z, %%in_Q_Z, \
                                  %%idx_b0, %%idx_sr64, %%T1, %%T2, %%T4                ;; S1 = y1*z2, U1 = z2^2
        IFMA_LNORM52_DUAL_P256_BODY %%S1, %%U1, %%idx_carry_shift, %%T1, %%T2, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(S1, U1)

        IFMA_AMM52_DUAL_P256_BODY %%S2, %%U2, %%in_Q_Y, %%in_P_Z, %%in_P_Z, %%in_P_Z, \
                                  %%idx_b0, %%idx_sr64, %%T1, %%T2, %%T4                ;; S2 = y2*z1, U2 = z1^2
        IFMA_LNORM52_DUAL_P256_BODY %%S2, %%U2, %%idx_carry_shift, %%T1, %%T2, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(S2, U2)

        vmovdqa64 %%T1, %%S1                                                            ;; save S1
        vmovdqa64 %%T2, %%S2                                                            ;; save S2
        IFMA_AMM52_DUAL_P256_BODY %%S1, %%S2, %%T1, %%U1, %%T2, %%U2, \
                                  %%idx_b0, %%idx_sr64, %%T3, %%T4, %%T5                ;; S1 = C = y1*z2^3, S2 = D = y2*z1^3
        IFMA_LNORM52_DUAL_P256_BODY %%S1, %%S2, %%idx_carry_shift, %%T1, %%T2, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(S1, S2)

        vmovdqa64 %%T1, %%U1                                                            ;; save U1 (z2^2)
        vmovdqa64 %%T2, %%U2                                                            ;; save U2 (z1^2)
        IFMA_AMM52_DUAL_P256_BODY %%U1, %%U2, %%in_P_X, %%T1, %%in_Q_X, %%T2, \
                                  %%idx_b0, %%idx_sr64, %%T3, %%T4, %%T5                ;; U1 = A = x1*z2^2, U2 = B = x2*z1^2
        IFMA_LNORM52_DUAL_P256_BODY %%U1, %%U2, %%idx_carry_shift, %%T1, %%T2, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(U1, U2)

        vpsubq  %%R, %%S2, %%S1                                                         ;; R = F = D - C
        vpsubq  %%H, %%U2, %%U1                                                         ;; H = E = B - A

        ;; Check for point equality: E == 0 AND F == 0
        vptestmq %%KREG_tmp3, %%R, %%R                                                  ;; KREG_tmp3 = mask of non-zero qwords in F
        vptestmq %%KREG_tmp4, %%H, %%H                                                  ;; KREG_tmp4 = mask of non-zero qwords in E
        korb    %%KREG_tmp3, %%KREG_tmp3, %%KREG_tmp4                                   ;; KREG_tmp3 = E|F (any non-zero means not equal)
        kmovb   DWORD(%%GP_tmp3), %%KREG_tmp3
        and     DWORD(%%GP_tmp3), 0x1F                                                  ;; only check lower 5 qwords
        neg     %%GP_tmp3                                                               ;; negative if not equal
        sbb     %%GP_tmp3, %%GP_tmp3
        not     %%GP_tmp3                                                               ;; GP_tmp3 = 0 if not equal, -1 if equal
        push    %%GP_tmp3                                                               ;; save to restore at the macro's end

        vpaddq  %%R, %%R, [rel p256_x2]                                                 ;; R += p256_x2 (ensure positive)
        vpaddq  %%H, %%H, [rel p256_x2]                                                 ;; H += p256_x2 (ensure positive)

        vpxorq  %%T1, %%T1, %%T1                                                        ;; T1 = 0 (for norm_dual)
        IFMA_NORM52_DUAL_P256_BODY %%R, %%H, %%idx_carry_shift, %%T1, %%T2, %%T3, \
                                   %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3                ;; norm_dual(R, H)

        IFMA_AMM52_DUAL_P256_BODY %%out_P_Z, %%U2, %%in_P_Z, %%in_Q_Z, %%H, %%H, \
                                  %%idx_b0, %%idx_sr64, %%T2, %%T3, %%T4                ;; P_Z = z1*z2, U2 = E^2
        IFMA_LNORM52_DUAL_P256_BODY %%out_P_Z, %%U2, %%idx_carry_shift, %%T1, %%T2, \
                                    %%KREG_tmp1, %%KREG_tmp2                            ;; lnorm_dual(P_Z, U2)

        vmovdqa64 %%T1, %%out_P_Z                                                       ;; save z1*z2
        IFMA_AMM52_DUAL_P256_BODY %%out_P_Z, %%S2, %%T1, %%H, %%R, %%R, \
                                  %%idx_b0, %%idx_sr64, %%T3, %%T4, %%T5                ;; P_Z = z1*z2*E, S2 = F^2

        IFMA_AMM52_P256_BODY %%T5, %%H, %%U2, %%idx_b0, %%idx_sr64, %%T3, %%T4, %%T1    ;; T5 = E^3 = E * E^2
        IFMA_LNORM52_P256_BODY %%T5, %%idx_carry_shift, %%T1, \
                               %%KREG_tmp1, %%KREG_tmp2                                 ;; lnorm(T5)

        IFMA_AMM52_DUAL_P256_BODY %%T1, %%T2, %%U1, %%U2, %%S1, %%T5, \
                                  %%idx_b0, %%idx_sr64, %%T3, %%T4, %%out_P_X           ;; T1 = A*E^2, T2 = C*E^3 (T5 is E^3)

        vpsubq  %%out_P_X, %%S2, %%T5                                                   ;; P_X = F^2 - E^3 (T5 is E^3)
        vpaddq  %%out_P_X, %%out_P_X, [rel p256_x2]                                     ;; P_X += p256_x2

        vpaddq  %%U1, %%T1, %%T1                                                        ;; U1 = 2*A*E^2

        vpsubq  %%out_P_X, %%out_P_X, %%U1                                              ;; P_X = F^2 - E^3 - 2*A*E^2
        vpaddq  %%out_P_X, %%out_P_X, [rel p256_x4]                                     ;; P_X += p256_x4

        vpsubq  %%out_P_Y, %%T1, %%out_P_X                                              ;; P_Y = A*E^2 - x3
        vpaddq  %%out_P_Y, %%out_P_Y, [rel p256_x8]                                     ;; P_Y += p256_x8

        vpxorq  %%T1, %%T1, %%T1                                                        ;; T1 = 0 (for norm)
        IFMA_NORM52_P256_BODY %%out_P_Y, %%idx_carry_shift, %%T1, %%U1, \
                              %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3                     ;; norm(P_Y)

        vpxorq  %%U1, %%U1, %%U1                                                                ;; U1 = 0 (accumulator for AMM52)
        IFMA_AMM52_P256_BODY %%U1, %%out_P_Y, %%R, %%idx_b0, %%idx_sr64, %%T3, %%T4, %%S1       ;; U1 = F*(A*E^2 - x3)

        vpsubq  %%out_P_Y, %%U1, %%T2                                                           ;; P_Y = U1 - C*E^3 (T2 still holds C*E^3)
        vpaddq  %%out_P_Y, %%out_P_Y, [rel p256_x2]                                             ;; P_Y += p256_x2

        vpxorq  %%T1, %%T1, %%T1                                                                ;; T1 = 0 (for norm_dual)
        IFMA_NORM52_DUAL_P256_BODY %%out_P_X, %%out_P_Y, %%idx_carry_shift, %%T1, %%T2, %%T3, \
                                   %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3                        ;; norm_dual(P_X, P_Y)
        IFMA_LNORM52_P256_BODY %%out_P_Z, %%idx_carry_shift, %%T1, \
                               %%KREG_tmp1, %%KREG_tmp2                                         ;; lnorm(P_Z)

        ;; Prepare the result In case points are equal - use DOUBLE_PART with separate output registers
        ;; (DOUBLE_PART doesn't support in-place operation)
        DOUBLE_PART %%U1, %%S1, %%T4, %%in_P_X, %%in_P_Y, %%in_P_Z,                     \
                    %%U2, %%S2, %%H, %%R, %%T1, %%T2, %%T3,                             \
                    %%idx_b0, %%idx_carry_shift, %%idx_sr64,                            \
                    %%GP_tmp1, %%GP_tmp2, %%GP_tmp3, %%GP_tmp4,                         \
                    %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3
        
        ;; Restore the move masks
        pop    %%GP_tmp3     
        pop    %%GP_tmp2
        pop    %%GP_tmp1
        
        ;; Copy results of doubling if points are equal
        kmovq   %%KREG_tmp3, %%GP_tmp3
        vmovdqa64 %%out_P_X{%%KREG_tmp3}, %%U1
        vmovdqa64 %%out_P_Y{%%KREG_tmp3}, %%S1
        vmovdqa64 %%out_P_Z{%%KREG_tmp3}, %%T4

        ;; if P is infinity - return Q.
        kmovq   %%KREG_tmp1, %%GP_tmp1
        vmovdqa64 %%out_P_X{%%KREG_tmp1}, %%in_Q_X    ;; out_P_X = p_is_inf ? in_Q_X : T
        vmovdqa64 %%out_P_Y{%%KREG_tmp1}, %%in_Q_Y    ;; out_P_Y = p_is_inf ? in_Q_Y : T
        vmovdqa64 %%out_P_Z{%%KREG_tmp1}, %%in_Q_Z    ;; out_P_Z = p_is_inf ? in_Q_Z : T  

        ;; if Q is infinity - return P. 
        kmovq     %%KREG_tmp2, %%GP_tmp2
        vmovdqa64 %%out_P_X{%%KREG_tmp2}, %%in_P_X    ;; out_P_X = q_is_inf ? P_X : T
        vmovdqa64 %%out_P_Y{%%KREG_tmp2}, %%in_P_Y    ;; out_P_X = q_is_inf ? P_Y : T
        vmovdqa64 %%out_P_Z{%%KREG_tmp2}, %%in_P_Z    ;; out_P_Z = q_is_inf ? P_Y : T    
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ADD_DOUBLE_PART macro - Combined point addition and doubling for P-256 curve
;
; Performs two independent EC operations in sequence:
;   out_add = P + Q  (point addition)
;   D = 2*D          (point doubling, in-place)
;
; This macro is useful for Montgomery ladder and precomputation loops where
; both operations are needed on independent data.
;
; Register allocation (total 26 ZMM registers + 4 k registers + 4 GPRs):
;   Input P:     zmm0, zmm1, zmm2       (3) - addition input, preserved
;   Input Q:     zmm3, zmm4, zmm5       (3) - addition input, preserved
;   Input/Out D: zmm6, zmm7, zmm8       (3) - doubling input, output written here
;   Output Add:  zmm9, zmm10, zmm11     (3) - addition output
;   Temps:       zmm12-zmm22            (11) - scratch registers (shared by ADD and DBL)
;   Constants:   zmm23-zmm25            (3) - idx_carry_shift, idx_sr64, idx_b0
;   K registers: 4 temp k registers (k4-k7 or any free k registers)
;   GPRs:        4 temp GPRs (rax, rbx, rcx, r8 or any free GPRs)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ADD_DOUBLE_PART 34
%define %%in_P_X      %1   ;; [in] P.X for addition
%define %%in_P_Y      %2   ;; [in] P.Y for addition
%define %%in_P_Z      %3   ;; [in] P.Z for addition
%define %%in_Q_X      %4   ;; [in] Q.X for addition
%define %%in_Q_Y      %5   ;; [in] Q.Y for addition
%define %%in_Q_Z      %6   ;; [in] Q.Z for addition
%define %%D_X         %7   ;; [in/out] D.X for doubling (in-place)
%define %%D_Y         %8   ;; [in/out] D.Y for doubling (in-place)
%define %%D_Z         %9   ;; [in/out] D.Z for doubling (in-place)
%define %%out_add_X   %10  ;; [out] addition result X
%define %%out_add_Y   %11  ;; [out] addition result Y
%define %%out_add_Z   %12  ;; [out] addition result Z
%define %%T1          %13  ;; [temp]
%define %%T2          %14  ;; [temp]
%define %%T3          %15  ;; [temp]
%define %%T4          %16  ;; [temp]
%define %%T5          %17  ;; [temp]
%define %%T6          %18  ;; [temp]
%define %%T7          %19  ;; [temp]
%define %%T8          %20  ;; [temp]
%define %%T9          %21  ;; [temp]
%define %%T10         %22  ;; [temp]
%define %%T11         %23  ;; [temp]
%define %%C2          %24  ;; [const] idx_carry_shift
%define %%C3          %25  ;; [const] idx_sr64
%define %%C4          %26  ;; [const] idx_b0
%define %%KREG_tmp1   %27  ;; [clobber] temp k register 1
%define %%KREG_tmp2   %28  ;; [clobber] temp k register 2
%define %%KREG_tmp3   %29  ;; [clobber] temp k register 3
%define %%KREG_tmp4   %30  ;; [clobber] temp k register 4
%define %%GP_tmp1     %31  ;; [clobber] temp GPR 1
%define %%GP_tmp2     %32  ;; [clobber] temp GPR 2
%define %%GP_tmp3     %33  ;; [clobber] temp GPR 3
%define %%GP_tmp4     %34  ;; [clobber] temp GPR 4

        ;; ========== STEP 1: Point Addition (out_add = P + Q) ==========
        ;; ADD_PART needs 31 registers: out_P(3), in_P(3), Q(3), temps(11), consts(3), kregs(4), gprs(4)
        ADD_PART %%out_add_X, %%out_add_Y, %%out_add_Z, %%in_P_X, %%in_P_Y, %%in_P_Z, %%in_Q_X, %%in_Q_Y, %%in_Q_Z, \
                 %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, %%T7, %%T8, %%T9, %%T10, %%T11, \
                 %%C2, %%C3, %%C4, \
                 %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3, %%KREG_tmp4, \
                 %%GP_tmp1, %%GP_tmp2, %%GP_tmp3, %%GP_tmp4

        ;; ========== STEP 2: Point Doubling (D = 2*D, in-place) ==========
        ;; Use DOUBLE_PART macro with appropriate register mapping
        ;; DOUBLE_PART needs 20 registers: out_R(3), in_P(3), temps(7), consts(3), gprs(4), kmasks(3)
        ;; For in-place operation, input and output are the same registers (D)
        DOUBLE_PART %%D_X, %%D_Y, %%D_Z, \
                    %%D_X, %%D_Y, %%D_Z, \
                    %%T1, %%T2, %%T3, %%T4, %%T5, %%T6, %%T7, \
                    %%C4, %%C2, %%C3, \
                    %%GP_tmp1, %%GP_tmp2, %%GP_tmp3, %%GP_tmp4, \
                    %%KREG_tmp1, %%KREG_tmp2, %%KREG_tmp3

%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ifma_amm52_dual_p256_asm_zmm - Dual Montgomery multiplication
;
; Computes r1 = a1 * b1 mod p256 and r2 = a2 * b2 mod p256
;
; Arguments (SysV ABI with AVX-512):
;   rdi             ;; [out] pointer to store result 1
;   rsi             ;; [in]  pointer to first operand 1 (a1)
;   rdx             ;; [in]  pointer to second operand 1 (b1)
;   rcx             ;; [out] pointer to store result 2
;   r8              ;; [in]  pointer to first operand 2 (a2)
;   r9              ;; [in]  pointer to second operand 2 (b2)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_amm52_dual_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15
        COMP_ABI 6

;; Register usage:
;;   rdi             - [in] pointer to store result 1
;;   rbx             - [in] pointer to store result 2 (saved from rcx)
;;   zmm0, rsi       - [in] first operand 1 (a1)
;;   zmm1, rdx       - [in] second operand 1 (b1)
;;   zmm4, r8        - [in] first operand 2
;;   zmm5, r9        - [in] second operand 2
;;   zmm13           - [out] result for multiplication 1 (t1)
;;   zmm14           - [out] result for multiplication 2 (t2)
;;   zmm6            - [clobbered] idx_b0
;;   zmm7            - [clobbered] idx_sr64
;;   zmm8            - [clobbered] scratch for MUL_RED_ROUND (tmp)
;;   zmm9            - [clobbered] scratch (scratch1)
;;   zmm10           - [clobbered] round-specific broadcast index (idx_b_round)

        ; Load A1, B1 and A2, B2
        vmovdqu64 zmm0, [rsi]
        vmovdqu64 zmm1, [rdx]
        vmovdqu64 zmm4, [r8]
        vmovdqu64 zmm5, [r9]

        ; Save r2 pointer
        mov     rbx, rcx

        ; Load constant index patterns
        vpbroadcastq zmm6, qword [rel idx_b0]
        vmovdqu64 zmm7, [rel idx_sr64]

        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52

        ; Perform dual Montgomery multiplication
        IFMA_AMM52_DUAL_P256_BODY zmm13, zmm14, zmm0, zmm1, zmm4, zmm5, \
                                  zmm6, zmm7, zmm8, zmm9, zmm10

        ; Store results
        vmovdqu64 [rdi], zmm13
        vmovdqu64 [rbx], zmm14

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_amm52_dual_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; IFMA_AMM52_P256_BODY macro - Body of Montgomery multiplication
;
; This macro contains all the computational logic for Montgomery 
; multiplication: r = a * b mod p256
;
; Prerequisites:
;   - K_EL0_MASK (k1) must be set to 0x01 (element 0 only)
;   - K_SHIFT_MASK (k2) must be set to 0x00ffffffffffffff (shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro IFMA_AMM52_P256_BODY 8
%define %%r             %1   ;; [out] ZMM register for result of multiplication
%define %%a             %2   ;; [in] ZMM register with first operand
%define %%b             %3   ;; [in] ZMM register with second operand
%define %%idx_b0        %4   ;; [in] ZMM register with broadcast index for element 0
%define %%idx_sr64      %5   ;; [in] ZMM register with shift index
%define %%temp1         %6   ;; [temp] ZMM register for MUL_RED_ROUND
%define %%temp2         %7   ;; [temp] ZMM register for scratch
%define %%idx_b_round   %8   ;; [temp] ZMM register for round-specific idx_b

        ;; Zero result accumulator
        vpxorq  %%r, %%r, %%r

        ;; Round 0
        vpbroadcastq %%idx_b_round, qword [rel idx_b0]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 1
        vpbroadcastq %%idx_b_round, qword [rel idx_b1]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 2
        vpbroadcastq %%idx_b_round, qword [rel idx_b2]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 3
        vpbroadcastq %%idx_b_round, qword [rel idx_b3]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 4
        vpbroadcastq %%idx_b_round, qword [rel idx_b4]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2

        ;; Round 5
        vpbroadcastq %%idx_b_round, qword [rel idx_b5]
        MUL_RED_ROUND %%r, %%a, %%b, %%idx_b_round, %%idx_b0, %%idx_sr64, %%temp1, %%temp2
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_amm52_p256_asm_zmm(
;     m512* out_pr,     ; rdi - Result (output)
;     m512* in_a,       ; rsi - Input 1
;     m512* in_b        ; rdx - Input 2
; )
;
; Performs Montgomery multiplication of 2 elements in radix 2^52 representation, 
; without normalization
;
; All intermediate values are kept in ZMM registers to avoid
; any stack memory usage for security (side-channel resistance).
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_amm52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12
        COMP_ABI 3

        ; Load A and B
        vmovdqu64 zmm0, [rsi]
        vmovdqu64 zmm1, [rdx]

        ; Result
        vpxorq      zmm2, zmm2, zmm2               ; accumulator r = 0

        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52

        ; Load constant index patterns
        vpbroadcastq zmm6, qword [rel idx_b0]      ; idx_b0 (for R[0] broadcast)
        vmovdqu64   zmm7, [rel idx_sr64]           ; idx_sr64 (for shift)

        IFMA_AMM52_P256_BODY zmm2, zmm0, zmm1, zmm6, zmm7, zmm8, zmm9, zmm10

        ; Store result
        vmovdqu64   [rdi], zmm2                   ; store r

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_amm52_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ifma_lnorm52_dual_p256_asm_zmm - Light normalization for two field elements
;
; Performs light normalization (carry propagation) on two field elements.
;
; Arguments (SysV ABI with AVX-512):
;   rdi            ;; [out] pointer to store result 1
;   rsi            ;; [in] input pointer 1
;   rdx            ;; [out] pointer to store result 2
;   rcx            ;; [in] input pointer 2
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_lnorm52_dual_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11
        COMP_ABI 4

        ; Load A1 and A2
        vmovdqu64 zmm0, [rsi]
        vmovdqu64 zmm1, [rcx]

        ; Save output pointer for r2
        mov     rbx, rdx

        ; Load idx_carry_shift (only constant that must be in register for vpermb)
        vmovdqu64 zmm2, [rel idx_carry_shift]

        ; Set up mask register for carry shift (all but first element)
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; Perform dual light normalization using macro
        ; Parameters: r1, r2, idx_carry_shift, carry1, carry2, tmp_k4, tmp_k5
        IFMA_LNORM52_DUAL_P256_BODY zmm0, zmm1, zmm2, zmm3, zmm4, k4, k5

        ; Store results
        vmovdqu64 [rdi], zmm0
        vmovdqu64 [rbx], zmm1

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_lnorm52_dual_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_lnorm52_p256_asm_zmm(
;     m512* out_pr,          ; rdi - Result pointer (output)
;     m512* in_a             ; rsi - Input pointer
; )
;
; Performs light normalization on a single field element.
; Input is passed in ZMM register directly.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_lnorm52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10
        COMP_ABI 2

        ; Load A
        vmovdqu64 zmm0, [rsi]

        ; Load idx_carry_shift (only constant that must be in register for vpermb)
        vmovdqu64 zmm2, [rel idx_carry_shift]

        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; Perform light normalization using macro
        ; Parameters: r, idx_carry_shift, carry, tmp_k4, tmp_k5
        IFMA_LNORM52_P256_BODY zmm0, zmm2, zmm3, k4, k5

        vmovdqu64 [rdi], zmm0

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_lnorm52_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_norm52_p256_asm_zmm(
;     m512* out_pr,          ; rdi - Result pointer (output)
;     m512* in_a             ; rsi - Input pointer
; )
;
; Performs full normalization on a single field element.
; Input is passed in ZMM register directly.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_norm52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11
        COMP_ABI 2

        ; Load A
        vmovdqu64 zmm0, [rsi]

        ; Load only idx_carry_shift (must be register for vpermb)
        vmovdqu64 zmm2, [rel idx_carry_shift]
        vpxorq  zmm3, zmm3, zmm3        ; zero

        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; Perform full normalization using macro
        ; Parameters: r, idx_carry_shift, zero, carry, tmp_k4, tmp_k5, tmp_k6
        IFMA_NORM52_P256_BODY zmm0, zmm2, zmm3, zmm4, k4, k5, k6

        vmovdqu64 [rdi], zmm0

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_norm52_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_norm52_dual_p256_asm(
;     m512* out_pr1,         ; rdi - Result 1 pointer (output)
;     m512* in_a1,           ; rsi - Input 1 pointer
;     m512* out_pr2,         ; rdx - Result 2 pointer (output)
;     m512* in_a2            ; rcx - Input 2 pointer
; )
;
; Performs full normalization on two field elements.
; Inputs are passed in ZMM registers directly.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_norm52_dual_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11
        COMP_ABI 4

        ; Load A1 and A2
        vmovdqu64 zmm0, [rsi]
        vmovdqu64 zmm1, [rcx]

        ; Load only idx_carry_shift (must be register for vpermb)
        vmovdqu64 zmm2, [rel idx_carry_shift]
        vpxorq  zmm3, zmm3, zmm3        ; zero

        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; Perform full normalization on both values using macro
        ; Parameters: r1, r2, idx_carry_shift, zero, carry1, carry2, tmp_k4, tmp_k5, tmp_k6
        IFMA_NORM52_DUAL_P256_BODY zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, k4, k5, k6

        vmovdqu64 [rdi], zmm0
        vmovdqu64 [rdx], zmm1

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_norm52_dual_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_half52_p256_asm_zmm(
;     m512* out_pr,          ; rdi - Result pointer (output)
;     m512* in_a             ; rsi - Input pointer
; )
;
; Compute A/2 mod p256 (halving in Montgomery domain).
; Input is passed in ZMM register directly.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_half52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8
        COMP_ABI 2

        ; Load A
        vmovdqu64 zmm0, [rsi]

        ; Load constants only needed for vpermb (idx_sr64, idx_carry_shift)
        vmovdqu64 zmm5, [rel idx_sr64]
        vmovdqu64 zmm6, [rel idx_carry_shift]

        ; Set up K mask registers required by HALF52
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; Perform half (divide by 2) using macro
        ; Parameters: r, idx_sr64, idx_carry_shift, scratch, GP_tmp1, tmp_k4, tmp_k5
        IFMA_HALF52_P256_BODY zmm0, zmm5, zmm6, zmm8, rax, k4, k5

        vmovdqu64 [rdi], zmm0

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_half52_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_aminv52_p256_asm_zmm(
;     m512* out_pr,          ; rdi - Result pointer (output)
;     m512* in_a             ; rsi - Input pointer
; )
;
; Compute 1/a mod p256 (inversion in Montgomery domain).
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_aminv52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15
        COMP_ABI 2

        ; Load A
        vmovdqu64 zmm0, [rsi]

        ; Load the unchanged constants
        vpbroadcastq zmm2, qword [rel idx_b0]   ; idx_b0 (for R[0] broadcast)
        vmovdqu64   zmm3, [rel idx_sr64]        ; idx_sr64 (for shift)
        
        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        IFMA_AMINV52_P256_BODY zmm1, zmm0, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                               zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, r10, rax, k4, k5

        ; Return the result
        vmovdqu64 [rdi], zmm1

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_aminv52_p256_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_ec_nistp256_dbl_point_asm_zmm(
;     m512* out_R_X,         ; rdi - Result X coordinate pointer (output)
;     m512* out_R_Y,         ; rsi - Result Y coordinate pointer (output)
;     m512* out_R_Z,         ; rdx - Result Z coordinate pointer (output)
;     m512* in_P_X,          ; rcx - Input pointer to X coordinate
;     m512* in_P_Y,          ; r8  - Input pointer to Y coordinate
;     m512* in_P_Z           ; r9  - Input pointer to Z coordinate
; )
;
; Computes R = 2*P for point P on P-256 curve.
; All computation is done in ZMM registers (no stack for secrets).
; Inputs: rdi = out_R_X ptr, rsi = out_R_Y ptr, rdx = out_R_Z ptr
;         rcx = in_P_X ptr, r8 = in_P_Y ptr, r9 = in_P_Z ptr
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_ec_nistp256_dbl_point_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15
        COMP_ABI 6

        ; Load input point P from pointers (cross-platform compatible)
        vmovdqu64 zmm0, [rcx]           ; P.X
        vmovdqu64 zmm1, [r8]            ; P.Y
        vmovdqu64 zmm2, [r9]            ; P.Z

        ; Temp registers: zmm3-zmm9 (y2, T, U, V, A, B, H)
        ; Output registers: zmm10, zmm11, zmm12
        ; Constant registers: zmm13=idx_b0, zmm14=idx_carry_shift, zmm15=idx_sr64

        ; Load constants required by DOUBLE_PART
        vpbroadcastq zmm13, qword [rel idx_b0]
        vmovdqu64 zmm14, [rel idx_carry_shift]
        vmovdqu64 zmm15, [rel idx_sr64]

        ; Set up all mask registers once
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only for MUL_RED_ROUND)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        ; Call the DOUBLE_PART macro - computes entire point doubling
        ; Params: out_R(3), in_P(3), temps(7), consts(3), gprs(4), kmasks(3) = 23 total
        DOUBLE_PART zmm10, zmm11, zmm12, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm13, zmm14, zmm15, \
                    rax, rcx, r8, r9, k4, k5, k6

        ; Store final results to output pointers
        vmovdqu64 [rdi], zmm10          ; store out_R_X
        vmovdqu64 [rsi], zmm11          ; store out_R_Y
        vmovdqu64 [rdx], zmm12          ; store out_R_Z

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_ec_nistp256_dbl_point_asm_zmm


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ifma_ec_nistp256_add_point_asm_zmm - Point addition for P-256 curve (in-place)
;
; Computes P = P + Q (P is modified in-place).
; Complete point addition with all special cases handled in assembly.
; Uses 20 ZMM registers in the ADD_PART macro (P(3) + Q(3) + temps(11) + consts(3)).
;
; Arguments (SysV ABI with AVX-512):
;   rdi             ;; [in/out] pointer to P.X coordinate
;   rsi             ;; [in/out] pointer to P.Y coordinate
;   rdx             ;; [in/out] pointer to P.Z coordinate
;   rcx             ;; [in] pointer to Q.X coordinate
;   r8              ;; [in] pointer to Q.Y coordinate
;   r9              ;; [in] pointer to Q.Z coordinate
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_ec_nistp256_add_point_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15,zmm16,zmm17,zmm18,zmm19,zmm20, zmm21,zmm22
        COMP_ABI 6

        ; Load input point Q from pointers (cross-platform compatible)
        vmovdqu64 zmm0, [rcx]           ; Q.X
        vmovdqu64 zmm1, [r8]            ; Q.Y
        vmovdqu64 zmm2, [r9]            ; Q.Z

        ; Load P from memory into zmm3-5 (Q is already in zmm0-2)
        vmovdqu64 zmm3, [rdi]           ; P.X
        vmovdqu64 zmm4, [rsi]           ; P.Y
        vmovdqu64 zmm5, [rdx]           ; P.Z

        ; Load constants required by ADD_PART
        vmovdqu64 zmm17, [rel idx_carry_shift]
        vmovdqu64 zmm18, [rel idx_sr64]
        vpbroadcastq zmm19, qword [rel idx_b0]

        ; Set up all mask registers once
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only for MUL_RED_ROUND)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        ; Call ADD_PART macro - computes entire point addition in-place
        ; Parameters: out_P_X, out_P_Y, out_P_Z, in_P_X, in_P_Y, in_P_Z, Q_X, Q_Y, Q_Z (in),
        ;            U1, U2, S1, S2, H, R, T1, T2, T3, T4, T5 (temps),
        ;            idx_carry_shift, idx_sr64, idx_b0 (constants),
        ;            k4, k5, k6, k7 (temp k registers), rax, rbx, rcx, r8 (temp GPRs)
        ; P is in zmm3-5 (loaded from memory), Q is in zmm0-2 (passed by value)
        ADD_PART zmm20, zmm21, zmm22, zmm3, zmm4, zmm5, zmm0, zmm1, zmm2, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, zmm16, zmm17, zmm18, zmm19, \
                 k4, k5, k6, k7, rax, rbx, rcx, r8

        ; Store final results back to P pointers (result is in zmm20, zmm21, zmm22)
        vmovdqu64 [rdi], zmm20           ; store P.X
        vmovdqu64 [rsi], zmm21           ; store P.Y
        vmovdqu64 [rdx], zmm22           ; store P.Z

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_ec_nistp256_add_point_asm_zmm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; GET_BOOTH_POINT_BODY macro - Complete booth point extraction from scalar
;
; Performs:
;   1. Extract WIN_SIZE+1 bit window from scalar at position 'bit'
;   2. Booth recode: convert wval to (sign, digit)
;   3. Constant-time point selection based on digit
;   4. Conditionally negate Y coordinate if sign != 0
;
; Window extraction (WIN_SIZE=3):
;   if (bit > 0):
;       chunk_no = (bit - 1) / 8
;       chunk_shift = (bit - 1) % 8
;       wval = (*(uint16_t*)(scalar + chunk_no) >> chunk_shift) & 0xF
;   else:  (bit == 0, last window)
;       wval = (*(uint16_t*)(scalar) << 1) & 0xF
;
; Booth recode algorithm (for WIN_SIZE=3, w=3):
;   s = ~((wval >> w) - 1)           ; s = 0xFF if wval >= 8, else 0x00
;   d = (1 << (w+1)) - wval - 1      ; d = 15 - wval
;   d = (d & s) | (wval & ~s)        ; d = (15-wval) if sign, else wval
;   d = (d >> 1) + (d & 1)           ; d = ceil(d/2)
;   sign = s & 1
;   digit = d
;
; Prerequisites:
; Precomputed points in ZMM registers:
;   zmm0-2:   P (input, preserved)
;   zmm23-25: 2P
;   zmm26-28: 3P
;   zmm29-31: 4P
; K_CARRY_MASK (k3) must be set to 0xffffffffffffff00 (carry shift mask)
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro GET_BOOTH_POINT_BODY 26
%define %%out_H_X       %1   ;; [out] ZMM register for output X coordinate
%define %%out_H_Y       %2   ;; [out] ZMM register for output Y coordinate
%define %%out_H_Z       %3   ;; [out] ZMM register for output Z coordinate
%define %%pScalar       %4   ;; [in] GPR register with pointer to scalar
%define %%bit           %5   ;; [in] GPR register with bit position
%define %%idx_carry_shift %6 ;; [in] ZMM register with carry shift index
%define %%t1            %7   ;; [clobber] ZMM register for scratch
%define %%t2            %8   ;; [clobber] ZMM register for scratch
%define %%t3            %9   ;; [clobber] ZMM register for scratch
%define %%KREG_cmp      %10  ;; [clobber] k register for comparison mask
%define %%GP_wval       %11  ;; [clobber] GPR for wval/idx (e.g., rax)
%define %%GP_chunk_no   %12  ;; [clobber] GPR for chunk_no (e.g., r8)
%define %%GP_tmp1       %13  ;; [clobber] GPR for temp (e.g., r9)
%define %%GP_tmp2       %14  ;; [clobber] GPR for temp (e.g., r10)
%define %%GP_sign       %15  ;; [clobber] GPR for sign (e.g., r11)
%define %%GP_loop_cnt   %16  ;; [clobber] GPR for loop counter (e.g., rbx)
%define %%GP_shift      %17  ;; [clobber] GPR for shift (must be rcx for cl)
%define %%GP_idx_tmp    %18  ;; [clobber] 64-bit GPR for index operations (e.g., r13)
%define %%GP_norm1      %19  ;; [clobber] GPR for NORM52
%define %%GP_norm2      %20  ;; [clobber] GPR for NORM52
%define %%GP_norm3      %21  ;; [clobber] GPR for NORM52
%define %%GP_norm4      %22  ;; [clobber] GPR for NORM52
%define %%GP_tmp3       %23  ;; [clobber] GPR for temp
%define %%KREG_tmp1     %24  ;; [clobber] k register for temporary mask
%define %%KREG_tmp2     %25  ;; [clobber] k register for temporary mask
%define %%KREG_tmp3     %26  ;; [clobber] k register for temporary mask

        ;; ========== Step 1: Extract scalar window (WIN_SIZE=3) ==========
        ; Input: %%pScalar = pExtendedScalar, %%bit = bit position
        ; Output: %%GP_wval = wval (0-15)
        ; mask = 0xF for WIN_SIZE=3

        test    DWORD(%%bit), DWORD(%%bit)
        jz      %%last_window

        ; bit > 0: normal window extraction
        ; chunk_no = (bit - 1) / 8
        ; chunk_shift = (bit - 1) % 8
        mov     DWORD(%%GP_wval), DWORD(%%bit)
        sub     DWORD(%%GP_wval), 1                  ; GP_wval = bit - 1
        mov     DWORD(%%GP_chunk_no), DWORD(%%GP_wval)
        shr     DWORD(%%GP_chunk_no), 3              ; GP_chunk_no = chunk_no = (bit-1) / 8
        and     DWORD(%%GP_wval), 7                  ; GP_wval = chunk_shift = (bit-1) % 8

        ; wval = (*(uint16_t*)(scalar + chunk_no) >> chunk_shift) & 0xF
        movzx   DWORD(%%GP_tmp1), word [%%pScalar + %%GP_chunk_no] ; GP_tmp1 = *(uint16_t*)(scalar + chunk_no)
        mov     DWORD(%%GP_shift), DWORD(%%GP_wval)         ; GP_shift = chunk_shift (for shift)
        shr     DWORD(%%GP_tmp1), cl                 ; GP_tmp1 = GP_tmp1 >> chunk_shift
        and     DWORD(%%GP_tmp1), 0xF                ; GP_tmp1 = wval & 0xF
        mov     DWORD(%%GP_wval), DWORD(%%GP_tmp1)          ; GP_wval = wval
        jmp     %%booth_recode

%%last_window:
        ; bit == 0: last window
        ; wval = (*(uint16_t*)(scalar) << 1) & 0xF
        movzx   DWORD(%%GP_wval), word [%%pScalar]   ; GP_wval = *(uint16_t*)(scalar)
        shl     DWORD(%%GP_wval), 1                  ; GP_wval = GP_wval << 1
        and     DWORD(%%GP_wval), 0xF                ; GP_wval = wval & 0xF

%%booth_recode:
        ;; ========== Step 2: Booth recode (WIN_SIZE=3) ==========
        ; Input: %%GP_wval = wval (0-15)
        ; Output: %%GP_chunk_no = digit (1-4), %%GP_sign = sign (0 or 1)

        ; s = ~((wval >> 3) - 1)
        mov     DWORD(%%GP_chunk_no), DWORD(%%GP_wval)      ; GP_chunk_no = wval
        shr     DWORD(%%GP_chunk_no), 3              ; GP_chunk_no = wval >> 3 (0 or 1)
        sub     DWORD(%%GP_chunk_no), 1              ; GP_chunk_no = (wval >> 3) - 1
        not     DWORD(%%GP_chunk_no)                 ; GP_chunk_no = s (0xFFFFFFFF if wval>=8, else 0)
        mov     DWORD(%%GP_sign), DWORD(%%GP_chunk_no)      ; GP_sign = s (save for later)
        and     DWORD(%%GP_sign), 1                  ; GP_sign = sign = s & 1

        ; d = 15 - wval
        mov     DWORD(%%GP_tmp1), 15
        sub     DWORD(%%GP_tmp1), DWORD(%%GP_wval)          ; GP_tmp1 = 15 - wval

        ; d = (d & s) | (wval & ~s)
        mov     DWORD(%%GP_tmp2), DWORD(%%GP_chunk_no)      ; GP_tmp2 = s
        not     DWORD(%%GP_tmp2)                     ; GP_tmp2 = ~s
        and     DWORD(%%GP_tmp1), DWORD(%%GP_chunk_no)      ; GP_tmp1 = (15-wval) & s
        and     DWORD(%%GP_tmp2), DWORD(%%GP_wval)          ; GP_tmp2 = wval & ~s
        or      DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)          ; GP_tmp1 = d

        ; d = (d >> 1) + (d & 1)
        mov     DWORD(%%GP_chunk_no), DWORD(%%GP_tmp1)
        and     DWORD(%%GP_chunk_no), 1              ; GP_chunk_no = d & 1
        shr     DWORD(%%GP_tmp1), 1                  ; GP_tmp1 = d >> 1
        add     DWORD(%%GP_chunk_no), DWORD(%%GP_tmp1)      ; GP_chunk_no = digit = (d >> 1) + (d & 1)

        ;; ========== Step 3: Constant-time point selection from ZMM registers ==========
        ; Precomputed points:
        ;   zmm0-2:   P (idx=0, input preserved)
        ;   zmm23-25: 2P (idx=1)
        ;   zmm26-28: 3P (idx=2)
        ;   zmm29-31: 4P (idx=3)
        ; %%GP_chunk_no = digit (1-4), %%GP_sign = sign

        ; Initialize result to zero
        vpxorq  %%out_H_X, %%out_H_X, %%out_H_X ; H.x = 0
        vpxorq  %%out_H_Y, %%out_H_Y, %%out_H_Y ; H.y = 0
        vpxorq  %%out_H_Z, %%out_H_Z, %%out_H_Z ; H.z = 0

        ; idx = digit - 1
        mov     DWORD(%%GP_wval), DWORD(%%GP_chunk_no)
        sub     DWORD(%%GP_wval), 1                  ; GP_wval = idx = digit - 1

        ; Constant-time selection from zmm registers
        ; Compare idx == 0 (P in zmm0-2)
        xor     DWORD(%%GP_tmp1), DWORD(%%GP_tmp1)
        mov     DWORD(%%GP_tmp2), -1
        cmp     DWORD(%%GP_wval), 0
        cmove   DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)
        kmovd   %%KREG_cmp, DWORD(%%GP_tmp1)
        vmovdqa64 %%out_H_X{%%KREG_cmp}, zmm0
        vmovdqa64 %%out_H_Y{%%KREG_cmp}, zmm1
        vmovdqa64 %%out_H_Z{%%KREG_cmp}, zmm2

        ; Compare idx == 1 (2P in zmm23-25)
        xor     DWORD(%%GP_tmp1), DWORD(%%GP_tmp1)
        cmp     DWORD(%%GP_wval), 1
        cmove   DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)
        kmovd   %%KREG_cmp, DWORD(%%GP_tmp1)
        vmovdqa64 %%out_H_X{%%KREG_cmp}, zmm23
        vmovdqa64 %%out_H_Y{%%KREG_cmp}, zmm24
        vmovdqa64 %%out_H_Z{%%KREG_cmp}, zmm25

        ; Compare idx == 2 (3P in zmm26-28)
        xor     DWORD(%%GP_tmp1), DWORD(%%GP_tmp1)
        cmp     DWORD(%%GP_wval), 2
        cmove   DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)
        kmovd   %%KREG_cmp, DWORD(%%GP_tmp1)
        vmovdqa64 %%out_H_X{%%KREG_cmp}, zmm26
        vmovdqa64 %%out_H_Y{%%KREG_cmp}, zmm27
        vmovdqa64 %%out_H_Z{%%KREG_cmp}, zmm28

        ; Compare idx == 3 (4P in zmm29-31)
        xor     DWORD(%%GP_tmp1), DWORD(%%GP_tmp1)
        cmp     DWORD(%%GP_wval), 3
        cmove   DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)
        kmovd   %%KREG_cmp, DWORD(%%GP_tmp1)
        vmovdqa64 %%out_H_X{%%KREG_cmp}, zmm29
        vmovdqa64 %%out_H_Y{%%KREG_cmp}, zmm30
        vmovdqa64 %%out_H_Z{%%KREG_cmp}, zmm31

        ;; ========== Step 4: Conditionally negate Y if sign != 0 ==========
        ; Negate Y: result = 4*p - Y
        vmovdqu64 %%t1, [rel p256_x4]
        vpsubq  %%t1, %%t1, %%out_H_Y   ; %%t1 = 4*p256 - Y

        ; Full normalization using 4 GPRs (optimized pattern)
        vpxorq  %%t2, %%t2, %%t2        ; zero

        ; Carry propagation
        vpsraq  %%t3, %%t1, 52
        vpermb  %%t3{K_CARRY_MASK}{z}, %%idx_carry_shift, %%t3
        vpandq  %%t1, %%t1, [rel digit_mask_x8]
        vpaddq  %%t1, %%t1, %%t3

        ; Overflow handling (uses %%KREG_tmp1 and %%KREG_tmp2 as scratch) - 2 GPRs
        vpcmpuq  %%KREG_tmp1, %%t1, [rel digit_mask_x8], 0
        vpcmpuq  %%KREG_tmp2, %%t1, [rel digit_mask_x8], 6
        kshiftlb %%KREG_tmp2, %%KREG_tmp2, 1
        kadd     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        kxor     %%KREG_tmp2, %%KREG_tmp2, %%KREG_tmp1
        vpaddq   %%t1{%%KREG_tmp2}, %%t1, [rel one_x8]

        ; Borrow handling using k-register operations only (no GPRs needed)
        ; %%KREG_tmp1 = elements >= 1 (no borrow needed from previous)
        ; %%KREG_tmp2 = elements < 0 (need to borrow)
        ; Propagate borrows: if element[i] < 0, element[i+1] needs -1 unless it's >= 1
        vpcmpq   %%KREG_tmp1, %%t1, [rel one_x8], 5     ; %%KREG_tmp1 = (t1 >= 1)
        vpcmpq   %%KREG_tmp2, %%t1, %%t2, 1             ; %%KREG_tmp2 = (t1 < 0)
        kshiftlb %%KREG_tmp3, %%KREG_tmp2, 1            ; %%KREG_tmp3 = %%KREG_tmp2 << 1 (propagate borrow to next element)
        kandn    %%KREG_tmp3, %%KREG_tmp1, %%KREG_tmp3  ; %%KREG_tmp3 = ~%%KREG_tmp1 & (%%KREG_tmp2 << 1) = needs borrow and not >= 1
        kor      %%KREG_tmp3, %%KREG_tmp3, %%KREG_tmp2  ; %%KREG_tmp3 = elements that need -1 (original negatives + propagated)
        vpaddq   %%t1{%%KREG_tmp3}, %%t1, [rel mone_x8]

        ; Final mask to 52 bits
        vpandq  %%t1, %%t1, [rel digit_mask_x8]
        
        ; Create mask based on sign: if sign != 0, use negated Y (t1), else use original Y (out_H_Y)
        xor     DWORD(%%GP_tmp1), DWORD(%%GP_tmp1)
        mov     DWORD(%%GP_tmp2), -1
        test    DWORD(%%GP_sign), DWORD(%%GP_sign)
        cmovnz  DWORD(%%GP_tmp1), DWORD(%%GP_tmp2)   ; GP_tmp1 = -1 if sign != 0, else 0
        kmovd   %%KREG_cmp, DWORD(%%GP_tmp1)
        vmovdqa64 %%out_H_Y{%%KREG_cmp}, %%t1        ; Conditionally move negated Y
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; ifma_ec_nistp256_mul_point_loop_asm_zmm - Main scalar multiplication with precomputation
;
; Performs precomputation and the complete scalar multiplication loop:
;   1. Precompute: P, 2P, 3P, 4P (kept in ZMM registers)
;   2. bit = scalarBitSize - (scalarBitSize % WIN_SIZE)
;   3. if (bit != 0) R = get_booth_point(pScalar, bit)
;   4. for (bit -= WIN_SIZE; bit >= 0; bit -= WIN_SIZE) {
;          H = get_booth_point(pScalar, bit);
;          R = 8*R + H;
;      }
;
; Precomputed points kept in registers throughout:
;   zmm0-2:   P (input, preserved)
;   zmm23-25: 2P
;   zmm26-28: 3P
;   zmm29-31: 4P
;   zmm20-22: H (booth point output)
;
; Arguments (SysV ABI with AVX-512):
;   rdi             ;; [in/out] pointer to R (P256_POINT_IFMA*)
;   rsi             ;; [in] pointer to pExtendedScalar
;   edx             ;; [in] scalarBitSize (e.g. 256 for P-256)
;   rcx             ;; [in] pointer to P.X coordinate
;   r8              ;; [in] pointer to P.Y coordinate
;   r9              ;; [in] pointer to P.Z coordinate
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define WIN_SIZE 3

align IPP_ALIGN_FACTOR
IPPASM ifma_ec_nistp256_mul_point_loop_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp,r12,r13,r14,r15
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15,zmm16,zmm17,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29,zmm30,zmm31
        COMP_ABI 6
        
        ; Arguments: rdi = pR, rsi = pScalar, edx = scalarBitSize, zmm0-2 = P
        ; Save rdi for the result write address
        push rdi

        ; Save scalarBitSize to callee-saved register (edx is clobbered by div)
        mov     r14d, edx               ; r14d = scalarBitSize

        ; Load input point P from pointers (cross-platform compatible)
        vmovdqu64 zmm0, [rcx]           ; P.X
        vmovdqu64 zmm1, [r8]            ; P.Y
        vmovdqu64 zmm2, [r9]            ; P.Z
        ; Save rcx, r8 and r9 to restore the input point during the calculations
        mov     rdi, rcx
        mov     rbp, r8
        mov     r15, r9

        ; ========== PRECOMPUTATION: Compute P, 2P, 3P, 4P ==========
        ; Input point P is in zmm0-2 (preserved throughout)

        ; Load constants for DOUBLE_PART and ADD_PART
        vmovdqu64 zmm17, [rel idx_carry_shift]
        vmovdqu64 zmm18, [rel idx_sr64]
        vpbroadcastq zmm19, qword [rel idx_b0]

        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        ; 2P -> zmm23-25
        DOUBLE_PART zmm23, zmm24, zmm25, zmm0, zmm1, zmm2, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                    zmm19, zmm17, zmm18, \
                    rax, rbx, rcx, r8, k4, k5, k6

        ; 4P = 2*(2P) -> zmm29-31 (do this before 3P to preserve 2P)
        DOUBLE_PART zmm29, zmm30, zmm31, zmm23, zmm24, zmm25, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                    zmm19, zmm17, zmm18, \
                    rax, rbx, rcx, r8, k4, k5, k6

        ; 3P = 2P + P -> zmm26-28
        vmovdqa64 zmm26, zmm23          ; copy 2P.X
        vmovdqa64 zmm27, zmm24          ; copy 2P.Y
        vmovdqa64 zmm28, zmm25          ; copy 2P.Z

        ; ADD_PART: out_P(3), in_P(3), in_Q(3), temps(11), consts(3), kregs(4), gprs(4)
        ; Q = in_P (zmm0-2, preserved)
        ADD_PART zmm26, zmm27, zmm28, zmm23, zmm24, zmm25, zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, zmm16, zmm17, zmm18, zmm19, k4, k5, k6, k7, rax, rbx, rcx, r8

        ; Precomputed points: P=zmm0-2, 2P=zmm23-25, 3P=zmm26-28, 4P=zmm29-31

        ; ========== MAIN LOOP ==========
        ; Compute bit = scalarBitSize - (scalarBitSize % WIN_SIZE)
        mov     eax, r14d
        mov     ecx, WIN_SIZE
        xor     edx, edx
        div     ecx                     ; eax = scalarBitSize / WIN_SIZE, edx = remainder
        sub     r14d, edx 

        ; First window - initialize R with first booth point
        ; Check if bit != 0
        test    r14d, r14d
        jz      .first_window_done

        ; GET_BOOTH_POINT for first window -> R (zmm3-5)
        GET_BOOTH_POINT_BODY zmm3, zmm4, zmm5, rsi, r14, zmm17, zmm6, zmm7, zmm8, k4, rax, r8, r9, r10, r11, rbx, rcx, r12, rax, r8, r9, r10, r13, k4, k5, k6

.first_window_done:
        ; Decrement bit for main loop
        sub     r14d, WIN_SIZE

.loop_start:
        ; Check loop condition: bit >= 0 (includes last window at bit=0)
        test    r14d, r14d
        js      .loop_end

        ;; ========== GET_BOOTH_POINT: Extract H from scalar at current bit position ==========
        ;; Output H to zmm20-22 (P is in zmm0-2, so we use zmm20-22 for H)
        GET_BOOTH_POINT_BODY zmm20, zmm21, zmm22, rsi, r14, zmm17, zmm6, zmm7, zmm8, k4, rax, r8, r9, r10, r11, rbx, rcx, r12, rax, r8, r9, r10, r13, k4, k5, k6

        ;; ========== DBL3_ADD: R = 8*R + H ==
        ;; DOUBLING 1: zmm3-5 -> zmm6-8
        DOUBLE_PART zmm6, zmm7, zmm8, zmm3, zmm4, zmm5, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                    zmm19, zmm17, zmm18, \
                    rax, rbx, rcx, r8, k4, k5, k6

        ;; DOUBLING 2: zmm6-8 -> zmm3-5
        DOUBLE_PART zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                    zmm19, zmm17, zmm18, \
                    rax, rbx, rcx, r8, k4, k5, k6

        ;; DOUBLING 3: zmm3-5 -> zmm6-8
        DOUBLE_PART zmm6, zmm7, zmm8, zmm3, zmm4, zmm5, \
                    zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, \
                    zmm19, zmm17, zmm18, \
                    rax, rbx, rcx, r8, k4, k5, k6

        ;; ADDITION: zmm6-8 (8*R) + zmm20-22 (H) -> zmm6-8
        ADD_PART zmm0, zmm1, zmm2, zmm6, zmm7, zmm8, zmm20, zmm21, zmm22, \
                 zmm3, zmm4, zmm5, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, zmm16, \
                 zmm17, zmm18, zmm19, \
                 k4, k5, k6, k7, rax, rbx, rcx, r8
        
        ; Move result back to zmm3-5 for next iteration
        vmovdqa64 zmm3, zmm0            ; R.X
        vmovdqa64 zmm4, zmm1            ; R.Y
        vmovdqa64 zmm5, zmm2            ; R.Z

        ; Restore P in zmm0-zmm2
        vmovdqu64 zmm0, [rdi]           ; P.X
        vmovdqu64 zmm1, [rbp]           ; P.Y
        vmovdqu64 zmm2, [r15]           ; P.Z

        ; Decrement bit counter and loop
        sub     r14d, WIN_SIZE
        jmp     .loop_start

.loop_end:
        ; ========== NORMALIZE RESULT ==========
        ; norm52_dual(R.X, R.Y) and norm52(R.Z)
        vpxorq  zmm0, zmm0, zmm0         ; zero for normalization

        ; IFMA_NORM52_DUAL_P256_BODY: r1, r2, idx_carry_shift, zero, carry1, carry2, tmp_k4, tmp_k5, tmp_k6
        IFMA_NORM52_DUAL_P256_BODY zmm3, zmm4, zmm17, zmm0, zmm6, zmm7, k4, k5, k6

        ; IFMA_NORM52_P256_BODY: r, idx_carry_shift, zero, carry, tmp_k4, tmp_k5, tmp_k6
        IFMA_NORM52_P256_BODY zmm5, zmm17, zmm0, zmm6, k4, k5, k6
        
        ; Restore address pR
        pop rdi
        ; Store normalized R to output (rdi = pR)
        vmovdqu64 [rdi], zmm3           ; R.X
        vmovdqu64 [rdi + 64], zmm4      ; R.Y
        vmovdqu64 [rdi + 128], zmm5     ; R.Z

        ; Clear secret registers
        vpxorq  zmm3, zmm3, zmm3
        vpxorq  zmm4, zmm4, zmm4
        vpxorq  zmm5, zmm5, zmm5

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_ec_nistp256_mul_point_loop_asm_zmm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_ec_nistp256_get_affine_coords_asm_zmm(
;     m512* out_R_X,              ; rdi - X affine result pointer (output)
;     m512* out_R_Y,              ; rsi - Y affine result pointer (output)
;     const P256_POINT_IFMA* A    ; rdx - Pointer to input point A
; )
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_ec_nistp256_get_affine_coords_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13,zmm14,zmm15
        COMP_ABI 3

        ; Load the input
        vmovdqu64 zmm1, [rdx + 128] ; A->z

        ; Load the unchanged constants
        vpbroadcastq zmm2, qword [rel idx_b0]   ; idx_b0 (for R[0] broadcast)
        vmovdqu64   zmm3, [rel idx_sr64]        ; idx_sr64 (for shift)

        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        ; inv(z1, A->z); /* 1/z */
        IFMA_AMINV52_P256_BODY zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15, r10, rax, k4, k5
        vmovdqa64 zmm16, zmm0
        
        ; sqr(z2, z1);   /* (1/z)^2 */
        ; lnorm(z2, z2);
        IFMA_AMS52_LNORM_NTIMES_P256_BODY zmm0, zmm2, zmm3, 1, zmm5, zmm6, zmm7, zmm8, zmm9, r10, rax, k4, k5

        ; if (NULL != rx)
        test rdi, rdi
        jz .skip_x_coord

        ; mul(*rx, a->x, z2); /* x = x/z^2 */
        ; lnorm(*rx, *rx);
        vmovdqu64 zmm4, [rdx]      ; load a->x (at offset 0)
        IFMA_AMM52_LNORM_P256_BODY zmm1, zmm0, zmm4, zmm2, zmm3, zmm5, zmm6, zmm7, zmm8, r8, k4, k5
        vmovdqu64 [rdi], zmm1

.skip_x_coord:
        ; if (NULL != ry)
        test rsi, rsi
        jz .function_end
    
        ; mul(z3, z1, z2) - compute (1/z)^3
        ; lnorm(z3, z3);
        IFMA_AMM52_LNORM_P256_BODY zmm1, zmm16, zmm0, zmm2, zmm3, zmm5, zmm6, zmm7, zmm8, r8, k4, k5
        
        ; mul(*ry, a->y, z3); /* y = y/z^3 */
        ; lnorm(*ry, *ry);
        vmovdqu64 zmm4, [rdx+64]      ; load a->x (at offset 0)
        IFMA_AMM52_LNORM_P256_BODY zmm0, zmm1, zmm4, zmm2, zmm3, zmm5, zmm6, zmm7, zmm8, r8, k4, k5

        ; Store result to *ry
        vmovdqu64 [rsi], zmm0

.function_end:
        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_ec_nistp256_get_affine_coords_asm_zmm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; void ifma_frommont52_p256_asm_zmm(
;     m512* out_ptr,    ; rdi - number in the standard representation (output)
;     m512*  in_a,      ; rsi - number in the Montgomery representation (input by reference)
; )
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align IPP_ALIGN_FACTOR
IPPASM ifma_frommont52_p256_asm_zmm,PUBLIC
%assign LOCAL_FRAME 0
        USES_GPR rsi,rdi,rbx,rbp
        USES_XMM_AVX zmm6,zmm7,zmm8,zmm9
        COMP_ABI 2

        vmovdqu64 zmm0, [rsi]

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; ifma_amm52_p256_norm(a, loadu_i64(one));
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ; Load the unchanged constants
        vpbroadcastq zmm3, qword [rel idx_b0]
        vmovdqu64   zmm4, [rel idx_sr64]        ; idx_sr64 (for shift)

        ; Set up mask registers
        mov     rax, 1
        kmovq   K_EL0_MASK, rax         ; k1 = 0x01 (element 0 only)
        mov     rax, 0x00ffffffffffffff
        kmovq   K_SHIFT_MASK, rax       ; k2 = shift mask for AMM52
        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax       ; k3 = carry shift mask for LNORM/NORM

        vmovdqu64 zmm2, [rel one]

        IFMA_AMM52_LNORM_P256_BODY zmm1, zmm0, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, r8, k4, k5

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; r = mod_reduction_p256(r);
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ; idx_sr64 (for shift)
        vmovdqu64   zmm2, [rel p256_modulus]
        ; tmp_r = a - M
        vpsubq zmm9, zmm1, zmm2

        ; Load only idx_carry_shift (must be register for vpermb)
        vmovdqu64 zmm2, [rel idx_carry_shift]
        vpxorq  zmm3, zmm3, zmm3

        mov     rax, 0xffffffffffffff00
        kmovq   K_CARRY_MASK, rax

        ; tmp_r = ifma_norm52(tmp_r)
        IFMA_NORM52_P256_BODY zmm9, zmm2, zmm3, zmm4, k4, k5, k6

        ; srli_i64(tmp_r, DIGIT_SIZE-1) >> 51
        vpsrlq zmm4, zmm9, 51


        ; lt = zero < shifted
        vpxord zmm2, zmm2, zmm2    ; zero vector
        vpcmpq k4, zmm2, zmm4, 1   ; _MM_CMPINT_LT

        ; check_bit(lt, 4)
        kmovq rax, k4
        shr   rax, 4
        and   rax, 1
        neg   rax 
        and   rax, 0xFF
        kmovq k4, rax

        ; result = mask ? a : tmp_r
        vmovdqa64 zmm9{k4}, zmm1

        vmovdqu64 [rdi], zmm9

        REST_XMM_AVX
        REST_GPR
        ret
ENDFUNC ifma_frommont52_p256_asm_zmm

%endif ; (_IPP32E >= _IPP32E_K1)
