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
;               AVX-512 (zmm) SM4-NI bulk kernels for the Intel(R) AVX10.2 tier.
;               vsm4rnds4 processes four full SM4 rounds per 128-bit lane, so a
;               zmm handles 4 independent blocks with NO cross-block transpose and
;               NO S-box synthesis. Four independent 4-block groups are interleaved
;               per round (x16) to hide the vsm4rnds4 latency.
;
;     Content:  cpSMS4_ECB_ni_512_bulk
;               cpSMS4_CTR_ni_512_bulk
;               cpSMS4_CBC_dec_ni_512_bulk
;               cpSMS4_CFB_dec_ni_512_bulk
;

%include "asmdefs.inc"
%include "ia_32e.inc"
%include "pcpvariant.inc"

%if (_IPP32E >= _IPP32E_D1)

segment .data align=IPP_ALIGN_FACTOR

; byte-reverse each 32-bit word within every 128-bit lane; pattern x4 for zmm
align 64
in_shufb_512:
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

; reverse the four output words within every 128-bit lane; pattern x4 for zmm
; also used as full 16-byte reverse (string<->numeric counter conversion, CTR)
align 64
out_shufb_512:
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00

; CTR: numeric counter -> vsm4rnds4 input form. Equals (in_shufb o full-reverse):
; converts a little-endian numeric counter straight to the byte-swapped-per-word
; big-endian block the cipher core wants, in one shuffle. Pattern x4 for zmm.
align 64
ctr_endian_swap_512:
db 12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3
db 12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3
db 12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3
db 12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3

; CTR: seed the 4 lanes of one zmm with counters base+0, base+1, base+2, base+3
; (numeric; increment lives in the low qword of each 128-bit lane). NOT a repeated
; pattern - each 16-byte lane differs.
align 64
ctr_first_inc_512:
db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

; CTR: advance every lane's counter by 4 (one x4 group). Low qword of each lane.
align 64
ctr_next_inc4_512:
db 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

; CTR: advance every lane by 8, 12 (groups 3 and 4 of one x16 iteration) and by 16
; (the per-iteration seed step). Lets the 4 groups be derived from one base in
; parallel instead of each from the one before it.
align 64
ctr_next_inc8_512:
db 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
align 64
ctr_next_inc12_512:
db 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
align 64
ctr_next_inc16_512:
db 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
db 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

; CTR: 1 in each 64-bit qword's LSB - the carry addend for the counter increment.
align 64
ctr_qword_one_512:
db 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
db 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
db 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
db 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0

segment .text align=IPP_ALIGN_FACTOR

;******************************************************************************
;* Shared macros for the bulk zmm SM4-NI kernels.
;*
;* All bulk kernels share the same three moving parts; only the per-group PRE
;* (produce cipher-input blocks) and POST (consume cipher output) differ by mode.
;* NASM expands these inline, so the emitted machine code is byte-identical to
;* the hand-written form -- factoring here costs zero cycles.
;*
;* None of these kernels touch xmm6..xmm15 (non-volatile on Win64), so they
;* have nothing to save and use no USES_XMM_AVX. Each ends with vzeroupper so
;* the caller's SSE code avoids the AVX-SSE transition penalty. A kernel moved
;* onto xmm6..xmm15 needs USES_XMM_AVX/REST_XMM_AVX naming those registers.
;******************************************************************************

; broadcast the 8 round keys into zmm16..zmm23 (loop-invariant). %1 = key ptr reg.
%macro SM4_KEYS_BCAST 1
    vbroadcasti32x4 zmm16, [%1 + 16*0]
    vbroadcasti32x4 zmm17, [%1 + 16*1]
    vbroadcasti32x4 zmm18, [%1 + 16*2]
    vbroadcasti32x4 zmm19, [%1 + 16*3]
    vbroadcasti32x4 zmm20, [%1 + 16*4]
    vbroadcasti32x4 zmm21, [%1 + 16*5]
    vbroadcasti32x4 zmm22, [%1 + 16*6]
    vbroadcasti32x4 zmm23, [%1 + 16*7]
%endmacro

; apply all 32 SM4 rounds (8x vsm4rnds4) to each data zmm passed. Keys in
; zmm16..zmm23. The data regs are interleaved WITHIN each round so N independent
; vsm4rnds4 chains stay in flight -> hides the instruction's latency (the whole
; point of x16). Works for 1, 4, or 8 data regs. In-place: %n = f(%n).
%macro SM4_ROUNDS 1-*                 ; %1.. = data zmm regs (1, 4, or 8 of them)
    %assign %%kk 16
    %rep 8
        %rep %0                        ; one vsm4rnds4 per data reg, this round key
            vsm4rnds4 %1, %1, zmm %+ %%kk
            %rotate 1                  ; after %0 rotations, args are back in order
        %endrep
    %assign %%kk (%%kk + 1)
    %endrep
%endmacro

; build k1 = byte mask (1 << %1) - 1 for a 1..3 block tail. %1 = byte-count reg
; (16/32/48), %2 = scratch gpr. Clobbers rcx (needed for the variable shift).
%macro SM4_TAILMASK 2                  ; %1 = byte count, %2 = scratch gpr
    mov   %2, 1
    mov   rcx, %1
    shl   %2, cl
    dec   %2
    kmovq k1, %2
%endmacro

;******************************************************************************
;* int cpSMS4_ECB_ni_512_bulk(Ipp8u* pOut, const Ipp8u* pInp, int len,
;*                       const Ipp32u* pRoundKey)
;*   Bulk ECB. Full coverage of any block-multiple length; returns the number
;*   of bytes processed (block-aligned len). The 8 round keys are broadcast to
;*   zmm ONCE (loop-invariant) and held in zmm16..zmm23; the hot loop then does
;*   pure vsm4rnds4 with no per-iteration key setup. Four independent 4-block
;*   groups are interleaved per round to hide vsm4rnds4 latency. A 1..3 block
;*   tail is finished with a masked zmm pass.
;******************************************************************************
%define pOut2       rdi
%define pInp2       rsi
%define lenB        rdx      ; length in bytes (edx as passed)
%define pRKey2      rcx

align IPP_ALIGN_FACTOR
IPPASM cpSMS4_ECB_ni_512_bulk,PUBLIC
    USES_GPR rsi,rdi,rdx,rcx
    COMP_ABI 4

    ; block-aligned length -> r8 = bytes to process, also the return value base
    mov   r8, lenB
    and   r8, -16                 ; floor to whole 16-byte blocks
    mov   rax, r8                 ; return value = processed bytes
    test  r8, r8
    jz    .done

    SM4_KEYS_BCAST pRKey2         ; keys -> zmm16..zmm23 (loop-invariant)

    ; byteswap masks, held in registers across the loop
    vmovdqa64 zmm24, [rel in_shufb_512]
    vmovdqa64 zmm25, [rel out_shufb_512]

    ; ---- x16 main loop: 4 groups (16 blocks = 256 bytes) per iteration ----
.loop16:
    cmp   r8, 256
    jb    .after16

    vmovdqu8 zmm0, [pInp2 + 0]
    vmovdqu8 zmm1, [pInp2 + 64]
    vmovdqu8 zmm2, [pInp2 + 128]
    vmovdqu8 zmm3, [pInp2 + 192]
    vpshufb  zmm0, zmm0, zmm24
    vpshufb  zmm1, zmm1, zmm24
    vpshufb  zmm2, zmm2, zmm24
    vpshufb  zmm3, zmm3, zmm24

    SM4_ROUNDS zmm0, zmm1, zmm2, zmm3

    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    vpshufb  zmm2, zmm2, zmm25
    vpshufb  zmm3, zmm3, zmm25
    vmovdqu8 [pOut2 + 0],   zmm0
    vmovdqu8 [pOut2 + 64],  zmm1
    vmovdqu8 [pOut2 + 128], zmm2
    vmovdqu8 [pOut2 + 192], zmm3

    add   pInp2, 256
    add   pOut2, 256
    sub   r8, 256
    jmp   .loop16
.after16:

    ; ---- x8 rung: 2 groups (8 blocks = 128 bytes), 2 chains in flight ----
    ; recovers part of the single-chain x4 penalty for the 128..192 B remainder.
    cmp   r8, 128
    jb    .after8
    vmovdqu8 zmm0, [pInp2 + 0]
    vmovdqu8 zmm1, [pInp2 + 64]
    vpshufb  zmm0, zmm0, zmm24
    vpshufb  zmm1, zmm1, zmm24
    SM4_ROUNDS zmm0, zmm1
    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    vmovdqu8 [pOut2 + 0],  zmm0
    vmovdqu8 [pOut2 + 64], zmm1
    add   pInp2, 128
    add   pOut2, 128
    sub   r8, 128
.after8:

    ; ---- x4 loop: 1 group (4 blocks = 64 bytes) per iteration ----
.loop4:
    cmp   r8, 64
    jb    .after4

    vmovdqu8 zmm0, [pInp2]
    vpshufb  zmm0, zmm0, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    vmovdqu8 [pOut2], zmm0

    add   pInp2, 64
    add   pOut2, 64
    sub   r8, 64
    jmp   .loop4
.after4:

    ; ---- masked tail: 1..3 blocks (r8 in {0,16,32,48}) ----
    test  r8, r8
    jz    .zero

    SM4_TAILMASK r8, r9           ; k1 = (1 << r8) - 1

    vmovdqu8 zmm0{k1}{z}, [pInp2]
    vpshufb  zmm0, zmm0, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    vmovdqu8 [pOut2]{k1}, zmm0

.zero:
    ; zeroize key + data regs (secret material)
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm16, zmm16, zmm16
    vpxorq zmm17, zmm17, zmm17
    vpxorq zmm18, zmm18, zmm18
    vpxorq zmm19, zmm19, zmm19
    vpxorq zmm20, zmm20, zmm20
    vpxorq zmm21, zmm21, zmm21
    vpxorq zmm22, zmm22, zmm22
    vpxorq zmm23, zmm23, zmm23

.done:
    vzeroupper
    REST_GPR
    ret
ENDFUNC cpSMS4_ECB_ni_512_bulk

;******************************************************************************
;* int cpSMS4_CTR_ni_512_bulk(Ipp8u* pOut, const Ipp8u* pInp, int len,
;*                            const Ipp32u* pRKey, const Ipp8u* pCtrMask,
;*                            Ipp8u* pCtr)
;*   Bulk SM4-CTR. Same vsm4rnds4 core as ECB (4 blocks/zmm, x16 interleave);
;*   the only additions are OFF the cipher critical path: build 4 counter blocks
;*   per group and XOR the keystream with plaintext at the end.
;*
;*   Counter model matches cpSMS4_CTR_gfni512 exactly:
;*     - counter held NUMERIC (little-endian int), 128-bit, big-endian on the wire
;*     - partial width via pCtrMask: block = ctrUnch ^ (ctr & mask),
;*       ctrUnch = (~mask) & ctrOrig holds the fixed nonce bits
;*     - increment is +1 on the low qword with carry into the high qword per lane
;*   Full coverage of any block-multiple length; returns block-aligned bytes and
;*   writes the next counter back to pCtr. A sub-16-byte final chunk stays the
;*   caller's job (return value is len & ~15).
;*
;*   numeric counter -> cipher input : one vpshufb with ctr_endian_swap_512
;*   cipher output   -> keystream    : one vpshufb with out_shufb_512 (full reverse)
;******************************************************************************
%define pOutC   rdi
%define pInpC   rsi
%define lenC    rdx
%define pRKeyC  rcx
%define pMaskC  r8
%define pCtrC   r9

; 128-bit per-lane counter increment (numeric). %1 = dst zmm, %2 = src zmm (must
; differ from dst), %3 = increment (zmm reg or memory). Adds to the low qword of
; each 128-bit lane; a low-qword unsigned wrap carries +1 into the high qword.
; Uses k2 and zmm29 (a 1 in every qword's LSB) as the carry addend.
%macro CTR_INC128 3
    CTR_INC128K %1, %2, %3, k2
%endmacro

; same, with an explicit mask register so independent chains do not share one.
%macro CTR_INC128K 4                  ; %4 = scratch k reg
    vpaddq   %1, %2, %3
    vpcmpuq  %4, %1, %2, 1          ; bit set where result < src (low-qword wrap)
    kshiftlb %4, %4, 1              ; move each lane's lo-qword carry to its hi qword
    vpaddq   %1{%4}, %1, zmm29      ; +1 into carrying high qwords only
%endmacro

; Emit the 4 counter zmms of one x16 iteration from ONE base, in parallel, then
; step the seed by 16. The old code chained group k+1 off group k, so four full
; carry latencies serialised per iteration; these four are independent. The carry
; is kept, so this stays correct for every counter width and every counter value.
; %1..%4 = dst zmms. mask=zmm26, ctrUnch=zmm27, byte-order=zmm24.
%macro CTR_BLOCK_X4 4
    vmovdqa64   %1, zmm30                                    ; group 0 = base
    CTR_INC128K %2, zmm30, [rel ctr_next_inc4_512],  k3      ; base + 4
    CTR_INC128K %3, zmm30, [rel ctr_next_inc8_512],  k4      ; base + 8
    CTR_INC128K %4, zmm30, [rel ctr_next_inc12_512], k5      ; base + 12
    ; seed += 16 through zmm31: CTR_INC128K compares its result against its source,
    ; so dst must differ from src or the carry is never detected.
    CTR_INC128K zmm31, zmm30, [rel ctr_next_inc16_512], k2
    vmovdqa64   zmm30, zmm31

    vpandq   %1, %1, zmm26
    vpandq   %2, %2, zmm26
    vpandq   %3, %3, zmm26
    vpandq   %4, %4, zmm26
    vpxorq   %1, %1, zmm27
    vpxorq   %2, %2, zmm27
    vpxorq   %3, %3, zmm27
    vpxorq   %4, %4, zmm27
    vpshufb  %1, %1, zmm24
    vpshufb  %2, %2, zmm24
    vpshufb  %3, %3, zmm24
    vpshufb  %4, %4, zmm24
%endmacro

; emit one zmm of 4 counter blocks (cipher-input form) from the running seed in
; zmm30, then advance the seed to the next 4 counters. %1 = dst zmm. The seed's
; 4 lanes hold consecutive counters; zmm28 (+4 per lane) steps all 4 forward one
; group. Off the vsm4rnds4 path. mask=zmm26, ctrUnch=zmm27, byte-order=zmm24.
%macro CTR_BLOCK 1                    ; %1 = dst zmm for the cipher-input counters
    vmovdqa64 %1, zmm30
    CTR_INC128 zmm30, %1, zmm28       ; seed lanes += 4 (advance one 4-block group)
    vpandq   %1, %1, zmm26            ; ctr & mask
    vpxorq   %1, %1, zmm27            ; ^ ctrUnch (restore fixed nonce bits)
    vpshufb  %1, %1, zmm24            ; numeric -> cipher input
%endmacro

align IPP_ALIGN_FACTOR
IPPASM cpSMS4_CTR_ni_512_bulk,PUBLIC
    USES_GPR rsi,rdi,rdx,rcx,r8,r9
    COMP_ABI 6

    ; block-aligned length -> r10 = bytes to process, also the return value
    mov   r10, lenC
    and   r10, -16
    mov   rax, r10
    test  r10, r10
    jz    .ctr_done

    SM4_KEYS_BCAST pRKeyC         ; keys -> zmm16..zmm23 (loop-invariant)

    ; loop-invariant shuffles + counter constants
    vmovdqa64 zmm24, [rel ctr_endian_swap_512]  ; numeric -> cipher input
    vmovdqa64 zmm25, [rel out_shufb_512]         ; cipher out -> keystream / string<->numeric
    vmovdqa64 zmm28, [rel ctr_next_inc4_512]     ; advance seed by 4 (one group)
    vmovdqa64 zmm29, [rel ctr_qword_one_512]     ; carry addend (1 per qword)

    ; counter setup (mirrors cpSMS4_CTR_gfni512):
    vbroadcasti32x4 zmm30, [pCtrC]               ; ctrOrig, string form
    vpshufb  zmm30, zmm30, zmm25                  ; -> numeric ctrOrig (all 4 lanes)
    vbroadcasti32x4 zmm26, [pMaskC]              ; mask, string form
    vpshufb  zmm26, zmm26, zmm25                  ; -> numeric mask
    vpandnq  zmm27, zmm26, zmm30                  ; ctrUnch = (~mask) & ctrOrig
    CTR_INC128 zmm31, zmm30, [rel ctr_first_inc_512]  ; ctrOrig + {0,1,2,3}
    vpandq   zmm30, zmm31, zmm26                  ; seed = mask & (ctrOrig + {0..3})

    ; ---- x16 main loop: 4 groups (16 blocks = 256 bytes) per iteration ----
    ; each lane of the seed holds base+{0,1,2,3}, so the four groups at base+0/4/8/12
    ; cover 16 consecutive counters and the seed then advances by 16.
.ctr_loop16:
    cmp   r10, 256
    jb    .ctr_after16

    CTR_BLOCK_X4 zmm0, zmm1, zmm2, zmm3   ; 4 groups from one base, no serial chain

    SM4_ROUNDS zmm0, zmm1, zmm2, zmm3

    ; keystream -> memory order, XOR plaintext, store
    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    vpshufb  zmm2, zmm2, zmm25
    vpshufb  zmm3, zmm3, zmm25
    vpxorq   zmm0, zmm0, [pInpC + 0]
    vpxorq   zmm1, zmm1, [pInpC + 64]
    vpxorq   zmm2, zmm2, [pInpC + 128]
    vpxorq   zmm3, zmm3, [pInpC + 192]
    vmovdqu8 [pOutC + 0],   zmm0
    vmovdqu8 [pOutC + 64],  zmm1
    vmovdqu8 [pOutC + 128], zmm2
    vmovdqu8 [pOutC + 192], zmm3

    add   pInpC, 256
    add   pOutC, 256
    sub   r10, 256
    jmp   .ctr_loop16
.ctr_after16:

    ; ---- x8 rung: 2 groups (8 blocks = 128 bytes), 2 chains in flight ----
    cmp   r10, 128
    jb    .ctr_after8
    CTR_BLOCK zmm0
    CTR_BLOCK zmm1
    SM4_ROUNDS zmm0, zmm1
    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    vpxorq   zmm0, zmm0, [pInpC + 0]
    vpxorq   zmm1, zmm1, [pInpC + 64]
    vmovdqu8 [pOutC + 0],  zmm0
    vmovdqu8 [pOutC + 64], zmm1
    add   pInpC, 128
    add   pOutC, 128
    sub   r10, 128
.ctr_after8:

    ; ---- x4 loop: 1 group (4 blocks = 64 bytes) per iteration ----
.ctr_loop4:
    cmp   r10, 64
    jb    .ctr_after4

    CTR_BLOCK zmm0
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    vpxorq   zmm0, zmm0, [pInpC]
    vmovdqu8 [pOutC], zmm0

    add   pInpC, 64
    add   pOutC, 64
    sub   r10, 64
    jmp   .ctr_loop4
.ctr_after4:

    ; ---- masked tail: 1..3 whole blocks (r10 in {0,16,32,48}) ----
    test  r10, r10
    jz    .ctr_savectr

    ; seed lanes 0..3 already hold the next consecutive counters -> use directly.
    ; do NOT advance the seed here (CTR_BLOCK would); the writeback below computes
    ; the exact next counter from the tail block count instead.
    vmovdqa64 zmm0, zmm30
    vpandq   zmm0, zmm0, zmm26
    vpxorq   zmm0, zmm0, zmm27
    vpshufb  zmm0, zmm0, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25

    SM4_TAILMASK r10, r11         ; k1 = (1 << r10) - 1 (r10 = tail bytes 16/32/48)

    vmovdqu8 zmm1{k1}{z}, [pInpC]
    vpxorq   zmm0, zmm0, zmm1
    vmovdqu8 [pOutC]{k1}, zmm0

    ; advance seed by the tail block count (r10>>4) for the counter writeback.
    ; only lane 0 is written back, so add k to lane 0's low qword. Use zmm31 as a
    ; distinct destination (CTR_INC128 needs dst != src for its carry compare).
    shr   r10, 4                     ; k = number of tail blocks (1..3)
    vmovq    xmm31, r10              ; {k, 0, 0, 0} in lane0's low qword (zero-extends)
    CTR_INC128 zmm31, zmm30, zmm31   ; zmm31 = seed + {k,0,0,0}
    vmovdqa64 zmm30, zmm31

.ctr_savectr:
    ; next counter = mask & seed  ^ ctrUnch, numeric -> string, store low 128 to pCtr
    vpandq   zmm30, zmm30, zmm26
    vpxorq   zmm30, zmm30, zmm27
    vpshufb  zmm30, zmm30, zmm25
    vmovdqu8 [pCtrC], xmm30

    ; zeroize secret material (keys + counter/keystream regs)
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm16, zmm16, zmm16
    vpxorq zmm17, zmm17, zmm17
    vpxorq zmm18, zmm18, zmm18
    vpxorq zmm19, zmm19, zmm19
    vpxorq zmm20, zmm20, zmm20
    vpxorq zmm21, zmm21, zmm21
    vpxorq zmm22, zmm22, zmm22
    vpxorq zmm23, zmm23, zmm23
    vpxorq zmm27, zmm27, zmm27
    vpxorq zmm30, zmm30, zmm30

.ctr_done:
    vzeroupper
    REST_GPR
    ret
ENDFUNC cpSMS4_CTR_ni_512_bulk

;******************************************************************************
;* int cpSMS4_CBC_dec_ni_512_bulk(Ipp8u* pOut, const Ipp8u* pInp, int len,
;*                                const Ipp32u* pRKey, Ipp8u* pIV)
;*   Bulk SM4 CBC-decrypt: P[i] = D(C[i]) ^ C[i-1], C[-1] = IV. pRKey must be the
;*   REVERSED (decrypt) round keys. Same vsm4rnds4 core + x16 interleave as ECB;
;*   the CBC chain is a pure data dependency on the CIPHERTEXT (not the plaintext),
;*   so all decrypts are independent and the only extra work -- the XOR with the
;*   previous ciphertext block -- is OFF the vsm4rnds4 critical path.
;*
;*   A zmm holds 4 consecutive ciphertext blocks [C0 C1 C2 C3] in natural order
;*   (no transpose). The XOR operand for that group is [prev C0 C1 C2]: rotate the
;*   loaded ciphertext lanes right by one (valignq ...,6 -> [C3 C0 C1 C2]) and
;*   overwrite lane 0 with the running prev (vinserti64x2). prev is then updated to
;*   C3 (this group's last ciphertext) via vextracti64x2. Full coverage; returns
;*   block-aligned bytes; writes the last ciphertext block back to pIV.
;******************************************************************************
%define pOutB   rdi
%define pInpB   rsi
%define lenBc   rdx
%define pRKeyB  rcx
%define pIVB    r8

; XOR one decrypted group (in %1, natural byte order) with the previous-ciphertext
; operand and advance the prev block. %1 = decrypted data zmm (also the store src),
; %2 = the group's loaded ciphertext zmm ([C0 C1 C2 C3]), %3 = scratch zmm.
; prev block lives in xmm31 across the loop; after this, xmm31 = C3 of this group.
%macro CBC_XOR_PREV 3                 ; %1 = dec data / out, %2 = ctext zmm, %3 = scratch zmm
    valignq      %3, %2, %2, 6         ; [C3 C0 C1 C2] (rotate lanes right by 1)
    vinserti64x2 %3, %3, xmm31, 0      ; -> [prev C0 C1 C2]  (prev in lane 0)
    vextracti64x2 xmm31, %2, 3         ; prev := C3 for the next group
    vpxorq       %1, %1, %3            ; P = D(C) ^ prevblocks
%endmacro

align IPP_ALIGN_FACTOR
IPPASM cpSMS4_CBC_dec_ni_512_bulk,PUBLIC
    USES_GPR rsi,rdi,rdx,rcx,r8
    COMP_ABI 5

    ; block-aligned length -> r10 = bytes to process, also the return value
    mov   r10, lenBc
    and   r10, -16
    mov   rax, r10
    test  r10, r10
    jz    .cbc_done

    SM4_KEYS_BCAST pRKeyB         ; reversed (decrypt) keys -> zmm16..zmm23
    vmovdqa64 zmm24, [rel in_shufb_512]
    vmovdqa64 zmm25, [rel out_shufb_512]
    vmovdqu8  xmm31, [pIVB]        ; prev := IV (natural byte order; EVEX for xmm16+)

    ; ---- x16 main loop: 4 groups (16 blocks = 256 bytes) per iteration ----
.cbc_loop16:
    cmp   r10, 256
    jb    .cbc_after16

    ; load ciphertext (natural order); keep copies in zmm4,5,26,27 for the prev-XOR
    vmovdqu8 zmm4, [pInpB + 0]
    vmovdqu8 zmm5, [pInpB + 64]
    vmovdqu8 zmm26, [pInpB + 128]
    vmovdqu8 zmm27, [pInpB + 192]
    vpshufb  zmm0, zmm4, zmm24     ; -> cipher input (byteswap per word)
    vpshufb  zmm1, zmm5, zmm24
    vpshufb  zmm2, zmm26, zmm24
    vpshufb  zmm3, zmm27, zmm24

    SM4_ROUNDS zmm0, zmm1, zmm2, zmm3

    vpshufb  zmm0, zmm0, zmm25     ; decrypted plaintext, natural byte order
    vpshufb  zmm1, zmm1, zmm25
    vpshufb  zmm2, zmm2, zmm25
    vpshufb  zmm3, zmm3, zmm25

    ; P = D(C) ^ prev-ciphertext; prev threads through xmm31 group to group.
    ; MUST run in block order (each updates the shared prev in xmm31).
    CBC_XOR_PREV zmm0, zmm4, zmm28
    CBC_XOR_PREV zmm1, zmm5, zmm28
    CBC_XOR_PREV zmm2, zmm26, zmm28
    CBC_XOR_PREV zmm3, zmm27, zmm28

    vmovdqu8 [pOutB + 0],   zmm0
    vmovdqu8 [pOutB + 64],  zmm1
    vmovdqu8 [pOutB + 128], zmm2
    vmovdqu8 [pOutB + 192], zmm3

    add   pInpB, 256
    add   pOutB, 256
    sub   r10, 256
    jmp   .cbc_loop16
.cbc_after16:

    ; ---- x8 rung: 2 groups (8 blocks = 128 bytes), 2 chains in flight ----
    cmp   r10, 128
    jb    .cbc_after8
    vmovdqu8 zmm4, [pInpB + 0]
    vmovdqu8 zmm5, [pInpB + 64]
    vpshufb  zmm0, zmm4, zmm24
    vpshufb  zmm1, zmm5, zmm24
    SM4_ROUNDS zmm0, zmm1
    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    CBC_XOR_PREV zmm0, zmm4, zmm28   ; block order matters (shared prev in xmm31)
    CBC_XOR_PREV zmm1, zmm5, zmm28
    vmovdqu8 [pOutB + 0],  zmm0
    vmovdqu8 [pOutB + 64], zmm1
    add   pInpB, 128
    add   pOutB, 128
    sub   r10, 128
.cbc_after8:

    ; ---- x4 loop: 1 group (4 blocks = 64 bytes) per iteration ----
.cbc_loop4:
    cmp   r10, 64
    jb    .cbc_after4

    vmovdqu8 zmm4, [pInpB]
    vpshufb  zmm0, zmm4, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    CBC_XOR_PREV zmm0, zmm4, zmm5
    vmovdqu8 [pOutB], zmm0

    add   pInpB, 64
    add   pOutB, 64
    sub   r10, 64
    jmp   .cbc_loop4
.cbc_after4:

    ; ---- masked tail: 1..3 whole blocks (r10 in {16,32,48}) ----
    test  r10, r10
    jz    .cbc_saveiv

    SM4_TAILMASK r10, r11         ; k1 = (1 << r10) - 1
    vmovdqu8 zmm4{k1}{z}, [pInpB]
    ; capture the last REAL ciphertext block for the IV writeback BEFORE the store
    ; (in-place: the store overwrites pInpB with plaintext) and BEFORE CBC_XOR_PREV
    ; (which clobbers xmm31). Stash in xmm6, a saved reg unused in the tail.
    ; last-block offset = (blocks-1)*16, blocks = r10>>4. r9 is free here.
    mov   r9, r10
    shr   r9, 4
    dec   r9                      ; index of last tail block (0..2)
    shl   r9, 4                   ; byte offset of last block within this chunk
    vmovdqu8 xmm6, [pInpB + r9]   ; last real ciphertext block
    vpshufb  zmm0, zmm4, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    ; prev-XOR: the tail has 1..3 blocks, unused lanes are zero-masked on store.
    ; CBC_XOR_PREV clobbers xmm31; restore it from xmm6 for the IV writeback.
    CBC_XOR_PREV zmm0, zmm4, zmm5
    vmovdqu8 [pOutB]{k1}, zmm0
    vmovdqa64 xmm31, xmm6         ; IV := last real ciphertext block

.cbc_saveiv:
    vmovdqu8 [pIVB], xmm31         ; IV := last ciphertext block

    ; zeroize secret material: keys (zmm16..23), plaintext (zmm0..3), and the
    ; ciphertext/feedback regs (zmm4,5,26..28, zmm31). The latter hold public data, but
    ; clearing them keeps every kernel here leaving the same state behind.
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm4, zmm4, zmm4
    vpxorq zmm5, zmm5, zmm5
    vpxorq zmm26, zmm26, zmm26
    vpxorq zmm27, zmm27, zmm27
    vpxorq zmm28, zmm28, zmm28
    vpxorq zmm16, zmm16, zmm16
    vpxorq zmm17, zmm17, zmm17
    vpxorq zmm18, zmm18, zmm18
    vpxorq zmm19, zmm19, zmm19
    vpxorq zmm20, zmm20, zmm20
    vpxorq zmm21, zmm21, zmm21
    vpxorq zmm22, zmm22, zmm22
    vpxorq zmm23, zmm23, zmm23
    vpxorq zmm31, zmm31, zmm31

.cbc_done:
    vzeroupper
    REST_GPR
    ret
ENDFUNC cpSMS4_CBC_dec_ni_512_bulk

;******************************************************************************
;* int cpSMS4_CFB_dec_ni_512_bulk(Ipp8u* pOut, const Ipp8u* pInp, int len,
;*                                int cfbBlkSize, const Ipp32u* pRKey, Ipp8u* pIV)
;*   Bulk SM4 CFB-decrypt, FULL-BLOCK feedback only (cfbBlkSize == 16):
;*       P[i] = C[i] ^ E(F[i]),  F[0] = IV,  F[i] = C[i-1]
;*   CFB-dec is the CBC-dec twin: the feedback vector [prev C0 C1 C2] is the SAME
;*   operand CBC-dec builds, but here it is the cipher INPUT (ENCRYPT keys) and the
;*   XOR with the ciphertext happens AFTER the cipher. Decrypts are independent
;*   (feedback is ciphertext-only), so the x16 vsm4rnds4 core runs unchanged.
;*
;*   pRKey must be the ENCRYPT (forward) round keys. cfbBlkSize MUST be 16; other
;*   sub-block CFB widths are serial and stay on the GFNI/scalar path (the caller
;*   never routes them here). Full coverage of any block-multiple length; returns
;*   block-aligned bytes and writes the last ciphertext block to pIV.
;******************************************************************************
%define pOutF   rdi
%define pInpF   rsi
%define lenF    rdx
; rcx = cfbBlkSize (ignored beyond the =16 contract), r8 = pRKey, r9 = pIV
%define pRKeyF  r8
%define pIVF    r9

; build the CFB feedback vector [prev C0 C1 C2] from the loaded ciphertext group
; and advance prev to C3. %1 = dst zmm (feedback, cipher-input-to-be), %2 = ctext
; zmm [C0 C1 C2 C3], %3 = scratch zmm. prev in xmm31; after this xmm31 = C3.
%macro CFB_FEEDBACK 3                  ; %1 = feedback dst, %2 = ctext zmm, %3 = scratch
    valignq      %1, %2, %2, 6         ; [C3 C0 C1 C2]
    vinserti64x2 %1, %1, xmm31, 0      ; -> [prev C0 C1 C2] (feedback blocks)
    vextracti64x2 xmm31, %2, 3         ; prev := C3 for the next group
%endmacro

align IPP_ALIGN_FACTOR
IPPASM cpSMS4_CFB_dec_ni_512_bulk,PUBLIC
    USES_GPR rsi,rdi,rdx,rcx,r8,r9
    COMP_ABI 6

    ; block-aligned length -> r10 = bytes to process, also the return value
    mov   r10, lenF
    and   r10, -16
    mov   rax, r10
    test  r10, r10
    jz    .cfb_done

    SM4_KEYS_BCAST pRKeyF         ; ENCRYPT keys -> zmm16..zmm23
    vmovdqa64 zmm24, [rel in_shufb_512]
    vmovdqa64 zmm25, [rel out_shufb_512]
    vmovdqu8  xmm31, [pIVF]        ; prev := IV (natural byte order)

    ; ---- x16 main loop: 4 groups (16 blocks = 256 bytes) per iteration ----
.cfb_loop16:
    cmp   r10, 256
    jb    .cfb_after16

    vmovdqu8 zmm4, [pInpF + 0]     ; ciphertext; kept for the post-XOR
    vmovdqu8 zmm5, [pInpF + 64]
    vmovdqu8 zmm26, [pInpF + 128]
    vmovdqu8 zmm27, [pInpF + 192]

    ; feedback [prev C0 C1 C2] -> cipher input; prev threads via xmm31 IN ORDER
    CFB_FEEDBACK zmm0, zmm4, zmm28
    CFB_FEEDBACK zmm1, zmm5, zmm28
    CFB_FEEDBACK zmm2, zmm26, zmm28
    CFB_FEEDBACK zmm3, zmm27, zmm28

    vpshufb  zmm0, zmm0, zmm24     ; -> cipher input byte order
    vpshufb  zmm1, zmm1, zmm24
    vpshufb  zmm2, zmm2, zmm24
    vpshufb  zmm3, zmm3, zmm24

    SM4_ROUNDS zmm0, zmm1, zmm2, zmm3   ; E(feedback) with encrypt keys

    vpshufb  zmm0, zmm0, zmm25     ; keystream, natural byte order
    vpshufb  zmm1, zmm1, zmm25
    vpshufb  zmm2, zmm2, zmm25
    vpshufb  zmm3, zmm3, zmm25
    vpxorq   zmm0, zmm0, zmm4      ; P = C ^ E(feedback)
    vpxorq   zmm1, zmm1, zmm5
    vpxorq   zmm2, zmm2, zmm26
    vpxorq   zmm3, zmm3, zmm27
    vmovdqu8 [pOutF + 0],   zmm0
    vmovdqu8 [pOutF + 64],  zmm1
    vmovdqu8 [pOutF + 128], zmm2
    vmovdqu8 [pOutF + 192], zmm3

    add   pInpF, 256
    add   pOutF, 256
    sub   r10, 256
    jmp   .cfb_loop16
.cfb_after16:

    ; ---- x8 rung: 2 groups (8 blocks = 128 bytes), 2 chains in flight ----
    cmp   r10, 128
    jb    .cfb_after8
    vmovdqu8 zmm4, [pInpF + 0]
    vmovdqu8 zmm5, [pInpF + 64]
    CFB_FEEDBACK zmm0, zmm4, zmm28   ; block order matters (shared prev in xmm31)
    CFB_FEEDBACK zmm1, zmm5, zmm28
    vpshufb  zmm0, zmm0, zmm24
    vpshufb  zmm1, zmm1, zmm24
    SM4_ROUNDS zmm0, zmm1
    vpshufb  zmm0, zmm0, zmm25
    vpshufb  zmm1, zmm1, zmm25
    vpxorq   zmm0, zmm0, zmm4
    vpxorq   zmm1, zmm1, zmm5
    vmovdqu8 [pOutF + 0],  zmm0
    vmovdqu8 [pOutF + 64], zmm1
    add   pInpF, 128
    add   pOutF, 128
    sub   r10, 128
.cfb_after8:

    ; ---- x4 loop: 1 group (4 blocks = 64 bytes) per iteration ----
.cfb_loop4:
    cmp   r10, 64
    jb    .cfb_after4

    vmovdqu8 zmm4, [pInpF]
    CFB_FEEDBACK zmm0, zmm4, zmm28
    vpshufb  zmm0, zmm0, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    vpxorq   zmm0, zmm0, zmm4
    vmovdqu8 [pOutF], zmm0

    add   pInpF, 64
    add   pOutF, 64
    sub   r10, 64
    jmp   .cfb_loop4
.cfb_after4:

    ; ---- masked tail: 1..3 whole blocks (r10 in {16,32,48}) ----
    test  r10, r10
    jz    .cfb_saveiv

    SM4_TAILMASK r10, r11         ; k1 = (1 << r10) - 1
    vmovdqu8 zmm4{k1}{z}, [pInpF]
    ; capture the last REAL ciphertext block for pIV BEFORE the aliasing store and
    ; before CFB_FEEDBACK clobbers xmm31. Stash in xmm6 (saved, unused here).
    mov   r11, r10
    shr   r11, 4
    dec   r11                     ; index of last tail block (0..2)
    shl   r11, 4                  ; byte offset within this chunk
    vmovdqu8 xmm6, [pInpF + r11]  ; last real ciphertext block
    CFB_FEEDBACK zmm0, zmm4, zmm28
    vpshufb  zmm0, zmm0, zmm24
    SM4_ROUNDS zmm0
    vpshufb  zmm0, zmm0, zmm25
    vpxorq   zmm0, zmm0, zmm4     ; P = C ^ E(feedback) (unused lanes masked on store)
    vmovdqu8 [pOutF]{k1}, zmm0
    vmovdqa64 xmm31, xmm6         ; IV := last real ciphertext block

.cfb_saveiv:
    vmovdqu8 [pIVF], xmm31         ; IV := last ciphertext block

    ; zeroize secret material: keys (zmm16..23), plaintext (zmm0..3), and the
    ; ciphertext/feedback regs (zmm4,5,26..28, zmm31). The latter hold public data, but
    ; clearing them keeps every kernel here leaving the same state behind.
    vpxorq zmm0, zmm0, zmm0
    vpxorq zmm1, zmm1, zmm1
    vpxorq zmm2, zmm2, zmm2
    vpxorq zmm3, zmm3, zmm3
    vpxorq zmm4, zmm4, zmm4
    vpxorq zmm5, zmm5, zmm5
    vpxorq zmm26, zmm26, zmm26
    vpxorq zmm27, zmm27, zmm27
    vpxorq zmm28, zmm28, zmm28
    vpxorq zmm16, zmm16, zmm16
    vpxorq zmm17, zmm17, zmm17
    vpxorq zmm18, zmm18, zmm18
    vpxorq zmm19, zmm19, zmm19
    vpxorq zmm20, zmm20, zmm20
    vpxorq zmm21, zmm21, zmm21
    vpxorq zmm22, zmm22, zmm22
    vpxorq zmm23, zmm23, zmm23
    vpxorq zmm31, zmm31, zmm31

.cfb_done:
    vzeroupper
    REST_GPR
    ret
ENDFUNC cpSMS4_CFB_dec_ni_512_bulk

%endif ;; _IPP32E >= _IPP32E_D1
