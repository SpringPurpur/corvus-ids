; features_avx2.asm - AVX2 routines for packet length statistics and TCP flag counts

; Assembled with NASM for ELF64 (Linux x86_64)
; Follows the System V AMD64 ABI throughout:
;   - Integer args: rdi, rsi, rdx, rcx, r8, r9 (then stack)
;   - Caller-saved: rax, rcx, rdx, rsi, rdi, r8-r11, xmm0-xmm7
;   - Callee-saved: rbx, rbp, r12-r15
;   -vzeroupper before every ret: avoids AVX-SSE transition penalties

section .text

; compute_pkt_len_stats_avx2

; Two-pass mean and population std over a uint16 array

;   void compute_pkt_len_stats_avx2(
;       uint16_t * buf,     ; rdi
;       uint32_t count,     ; esi
;       float *out_mean,    ; rdx
;       float *out_std      ; rcx
;   )

; Pass 1: horizontal sum of all uint16 elements - compute mean
; Pass 2: sum of (x - mean)^2 for each element - compute population std

; Processes 16 uint16 per AVX2 iteration (256-bit register = 16 * 16-bit lanes)
; Scalar tail handles count % 16 remainder

; Caller must ensure count > 0. A zero-length buffer is a logic error upstream

global compute_pkt_len_stats_avx2
compute_pkt_len_stats_avx2:
    ; rdi = buf, esi = count, rdx = out_mean, rcx = out_std
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi    ; buf
    mov r13d, esi   ; count
    mov r14, rdx    ; out_mean (save before we use rdx for scratch)
    ; rcx = out_std (saved implicitly, not clobbered until we write result)

    ; pass 1: sum all elements
    vpxor ymm0, ymm0, ymm0  ; accumulator (four 64-bit lanes)
    vpxor ymm7, ymm7, ymm7  ; zero register

    mov eax, r13d
    shr eax, 4      ; iterations = count / 16
    mov rbx, r12    ; pointer

.sum_loop:
    test eax, eax
    jz .sum_tail

    ; load 16 * uint16 (256 bits) from buf
    vmovdqu ymm1, [rbx]     ; vector move double quadword unaligned

    ; Expand each uint16 to uint32 using zero extension:
    ; vpmovzxwd (vector packed move zero extension word): lower 8 * uint16 to 8 * uint32 in ymm2
    ; upper 8 * uint16 -> 8 * uint32 in ymm3
    vextracti128 xmm4, ymm1, 1
    vpmovzxwd ymm2, xmm1        ; low 8 uint16 -> uint32
    vpmovzxwd ymm3, xmm4        ; high 8 uint16 -> uint32

    ; Accumulate into 64-bit lanes via vpsadbw trick:
    ; vpsadbw computes sum of absolute differences against zero,
    ; effectively a horizontal byte sum that fits in 64 bit lanes
    ; For uint32 sums we use vpaddd to add uint32 chunks then
    ; horizontal-reduce to 64-bit at the end
    vpaddd ymm2, ymm2, ymm3     ; add pairs into 8 * uint32
    ; reduce 8 * uint32 to 4 * uint64
    vpxor ymm5, ymm5, ymm5
    vpmovzxdq ymm5, xmm2    ; low 4 * uint32 -> uint64
    vextracti128 xmm6, ymm2, 1
    vpmovzxdq ymm6, xmm6    ; high 4 * uint32 -> uint64

    vpaddq ymm5, ymm5, ymm6
    vpaddq ymm0, ymm0, ymm5     ; accumulate into ymm0

    add rbx, 32     ; advance 16 * 2 bytes
    dec eax
    jmp .sum_loop

.sum_tail:
    ; scalar tail: remaining (count % 16 elements)
    mov eax, r13d
    and eax, 15     ; remainder
    xor r8d, r8d    ; scalar accumulator
.sum_scalar:
    test eax, eax
    jz .sum_reduce
    movzx r9d, word [rbx]
    add r8d, r9d
    add rbx, 2
    dec eax
    jmp .sum_scalar

.sum_reduce:
    ; horizontal sum of ymm0 (four uint64 lanes) into rax
    vextracti128 xmm1, ymm0, 1
    vpaddq xmm0, xmm0, xmm1
    ; xmm0 = [a, b]; a+b
    vpunpckhqdq xmm1, xmm0, xmm0
    paddq xmm0, xmm1
    movq rax, xmm0  ; rax = total sum

    add rax, r8     ; add scalar tail

    ; mean = sum / count
    cvtsi2ss xmm0, rax  ; sum as float
    cvtsi2ss xmm1, r13d ; count as float
    divss xmm0, xmm1    ; xmm0 = mean
    movss [r14], xmm0   ;*out_mean = mean

    ; pass 2: sum of squared deviations
    ; sum_sq = sum((x_i - mean)^2) using float arithmetic
    vbroadcastss ymm8, xmm0     ; broadcast mean to all 8 float lanes

    vpxor ymm9, ymm9, ymm9      ; float accumulator (8 * float lanes)
    mov eax, r13d
    shr eax, 3                  ; iterations = count / 8 (8 uint16 per xmm load)
    mov rbx, r12                ; reset pointer

.sq_loop:
    test eax, eax
    jz .sq_tail

    ; load 8 * uint16 (128 bits) from buf, zero extend to int32, convert to float
    vmovdqu xmm1, [rbx]     ; 8 * uint16
    vpmovzxwd ymm2, xmm1    ; 8 * int32
    vcvtdq2ps ymm2, ymm2    ; 8 * float

    vsubps ymm2, ymm2, ymm8 ; x - mean
    vmulps ymm2, ymm2, ymm2 ; (x - mean)^2
    vaddps ymm9, ymm9, ymm2 ; accumulate

    add rbx, 16     ; advance 8 * 2 bytes
    dec eax
    jmp .sq_loop

.sq_tail:
    ; Scalar tail for remaining elements
    mov eax, r13d
    and eax, 7
    vxorps xmm3, xmm3, xmm3     ; scalar float accumulation
    movss xmm4, [r14]   ; mean

.sq_scalar:
    test eax, eax
    jz .sq_reduce
    movzx r9d, word [rbx]
    vcvtsi2ss xmm5, xmm5, r9d
    vsubss xmm5, xmm5, xmm4
    vmulss xmm5, xmm5, xmm5
    vaddss xmm3, xmm3, xmm5
    add rbx, 2
    dec eax
    jmp .sq_scalar

.sq_reduce:
    ; horizontal sum of ymm9 (8 * float) into xmm0
    vextractf128 xmm0, ymm9, 1
    vaddps xmm0, xmm0, xmm9     ; 4-wide
    ; reduce 4 * float to 1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vaddss xmm0, xmm0, xmm3     ; add scalar tail

    ; std = sqrt(sum_sq / count)
    cvtsi2ss xmm1, r13d
    vdivss xmm0, xmm0, xmm1
    vsqrtss xmm0, xmm0, xmm0
    movss [rcx], xmm0   ; *out_std = std

    pop r14
    pop r13
    pop r12
    pop rbx
    vzeroupper
    ret

; count_tcp_flags_avx2

; Count occurences of each TCP flag bit across an array of flags bytes

;   void count_tcp_flags_avx2(
;       uint8_t *flags,     ; rdi - array of TCP flags bytes
;       uint32_t count,     ; esi - number of bytes
;       uint32_t *fin,      ; rdx
;       uint32_t *syn,      ; rcx
;       uint32_t *rst,      ; r8
;       uint32_t *psh,      ; r9
;       uint32_t *ack,      ; [rsp+8] (7th arg, on stack after call)
;       uint32_t *urg       ; [rsp+16] (8th arg)
;   )

; Strategy: for each bit position, broadcast a mask byte (for example, 0x01 for FIN),
; AND each 32-byte chunk with the mask, then use vpsadbw to horizontally sum
; the resulting 0 or 1 bytes into 64-bit accumulators.
; Processes 32 bytes per iteration. Scalar tail for count % 32

global count_tcp_flags_avx2
count_tcp_flags_avx2:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi    ; flags array
    mov r13d, esi   ; count
    mov r14, rdx    ; *fin
    mov r15, rcx    ; *syn
    ; r8 = *rst     ; unchanged from arg
    ; r9 = *psh
    ; 7th arg *ack = [rsp + 8 + 48] (48 = 6 pushes * 8)
    ; 8th arg *urg = [rsp + 16 + 48]
    mov rbx, [rsp + 56] ; *ack
    mov rbp, [rsp + 64] ; *urg

    ; accumulator registers: ymm0=FIN, ymm1=SYN, ymm2=RST, ymm3=PSH, ymm4=ACK, ymm5=URG
    vpxor ymm0, ymm0, ymm0
    vpxor ymm1, ymm1, ymm1
    vpxor ymm2, ymm2, ymm2
    vpxor ymm3, ymm3, ymm3
    vpxor ymm4, ymm4, ymm4
    vpxor ymm5, ymm5, ymm5
    vpxor ymm15, ymm15, ymm15   ; zero for vpsadbw

    ; broadcast mask bytes for each flag
    mov eax, 0x01
    vmovd xmm6, eax
    vpbroadcastb ymm6, xmm6 ; FIN mask = 0x01...01

    mov eax, 0x02
    vmovd xmm7, eax
    vpbroadcastb ymm7, xmm7 ; SYN mask = 0x02...02

    mov eax, 0x04
    vmovd xmm8, eax
    vpbroadcastb ymm8, xmm8 ; RST mask

    mov eax, 0x08
    vmovd xmm9, eax
    vpbroadcastb ymm9, xmm9 ; PSH mask

    mov eax, 0x10
    vmovd xmm10, eax
    vpbroadcastb ymm10, xmm10 ; ACK mask

    mov eax, 0x20
    vmovd xmm11, eax
    vpbroadcastb ymm11, xmm11 ; URG

    mov ecx, r13d
    shr ecx, 5      ; iterations = count / 32
    mov rdi, r12    ; pointer

.flag_loop:
    test ecx, ecx
    jz .flag_tail

    vmovdqu ymm12, [rdi]    ; 32 flag bytes

    ; For each flag: AND with mask (gives 0x00 or flag_bit), then
    ; shift right to normalise to 0/1, then vpsadbw to sum bytes.
    ; vpsadbw sums absolute differences vs zero = sum of 0/1 bytes,
    ; producing four 64-bit lane parial sums

    ; FIN (bit 0 - already 0 or 1 after AND + normalise)
    vpand ymm13, ymm12, ymm6
    ; bit 0 is already 0x00 or 0x01 - no shift needed
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm0, ymm0, ymm13

    ; SYN (bit 1 - shift right 1)
    vpand ymm13, ymm12, ymm7
    vpsrlw ymm13, ymm13, 1
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm1, ymm1, ymm13

    ; RST (bit 2 - shift right 2)
    vpand ymm13, ymm12, ymm8
    vpsrlw ymm13, ymm13, 2
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm2, ymm2, ymm13

    ; PSH (bit 3 - shift right 3)
    vpand ymm13, ymm12, ymm9
    vpsrlw ymm13, ymm13, 3
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm3, ymm3, ymm13

    ; ACK (bit 4 - shift right 4)
    vpand ymm13, ymm12, ymm10
    vpsrlw ymm13, ymm13, 4
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm4, ymm4, ymm13

    ; URG (bit 5 - shift right 5)
    vpand ymm13, ymm12, ymm11
    vpsrlw ymm13, ymm13, 5
    vpsadbw ymm13, ymm13, ymm15
    vpaddq ymm5, ymm5, ymm13

    add rdi, 32
    dec ecx
    jmp .flag_loop

.flag_tail:
    ; scalar tail for remaining bytes
    mov ecx, r13d
    and ecx, 31
    xor eax, eax    ; FIN
    xor edx, edx    ; SYN
    ; use r10-r11 for RST/PSH, rsi for ACK/URG (caller-saved, safe here)
    xor r10d, r10d      ; zeroes the upper 64-bit registers too
    xor r11d, r11d
    xor esi, esi
    xor r13d, r13d

.flag_scalar:
    test ecx, ecx
    jz .flag_done
    movzx r12d, byte [rdi]
    ; bt sets CF to the specified bit; adc reg, 0 adds CF to the counter
    bt r12d, 0
    adc eax, 0  ; FIN
    bt r12d, 1
    adc edx, 0  ; SYN
    bt r12d, 2
    adc r10d, 0 ; RST
    bt r12d, 3
    adc r11d, 0 ; PSH
    bt r12d, 4
    adc esi, 0  ; ACK
    bt r12d, 5
    adc r13d, 0 ; URG
    inc rdi
    dec ecx
    jmp .flag_scalar

.flag_done:
    ; horizontal reduce each ymm accumulator and add scalar tail

    ; reduce each ymm accumulator to uint32 and add scalar tail
    ; FIN
    vextracti128 xmm13, ymm0, 1
    paddq xmm0, xmm13
    movhlps xmm14, xmm0
    paddq xmm0, xmm14
    movq r12, xmm0
    add eax, r12d
    mov [r14], eax  ; *fin

    ; SYN
    vextracti128 xmm13, ymm1, 1
    paddq xmm1, xmm13
    movhlps xmm14, xmm1
    paddq xmm1, xmm14
    movq r12, xmm1
    add edx, r12d
    mov [r15], edx  ; *syn

    ; RST
    vextracti128 xmm13, ymm2, 1
    paddq xmm2, xmm13
    movhlps xmm14, xmm2
    paddq xmm2, xmm14
    movq r12, xmm2
    add r10d, r12d
    mov [r8], r10d  ; *rst

    ; PSH
    vextracti128 xmm13, ymm3, 1
    paddq xmm3, xmm13
    movhlps xmm14, xmm3
    paddq xmm3, xmm14
    movq r12, xmm3
    add r11d, r12d
    mov [r9], r11d  ; *psh

    ; ACK
    vextracti128 xmm13, ymm4, 1
    paddq xmm4, xmm13
    movhlps xmm14, xmm4
    paddq xmm4, xmm14
    movq r12, xmm4
    add esi, r12d
    mov [rbx], esi  ; *ack

    ; URG
    vextracti128 xmm13, ymm5, 1
    paddq xmm5, xmm13
    movhlps xmm14, xmm5
    paddq xmm5, xmm14
    movq r12, xmm5
    add r13d, r12d
    mov [rbp], r13d ; *urg

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    vzeroupper
    ret

; Mark stack as non-executable - required by the GNU toolchain for ELF objects
; that omit .note.GNU-stack. Without this, the linker assumes an executable
; stack and emits a deprecation warning
section .note.GNU-stack noalloc noexec nowrite progbits