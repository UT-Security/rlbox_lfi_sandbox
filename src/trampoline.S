#include "lfi_ctx_offsets.h"

.text

#if defined(__x86_64__) || defined(_M_X64)

.global lfi_trampoline
lfi_trampoline:
	endbr64

	// save callee-saved registers
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	// one dummy push as the lfi runtime expects this
	pushq %rbp

	// push the trampoline return onto the host stack
	leaq .return(%rip), %r11
	pushq %r11

	// Load context
	movq lfi_myctx@gottpoff(%rip), %r11
	movq %fs:(%r11), %r11

	// Clear non param registers, except the tmp reg r11
	xorq %rax, %rax
	xorq %rbx, %rbx
	xorq %rbp, %rbp
	xorq %r10, %r10
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15
	// Clear direction flag before call or return
	cld
	// Clear the x87, MMX, and SSE state.
	fxrstor fxrstor_default_state(%rip)
	// Clear the AVX state that the "fxrstor" instruction doesn't cover.
	vzeroupper

	// Load params
	movq  LFI_CONTEXT_OFFSET_RDI(%r11) , %rdi
	movq  LFI_CONTEXT_OFFSET_RSI(%r11) , %rsi
	movq  LFI_CONTEXT_OFFSET_RDX(%r11) , %rdx
	movq  LFI_CONTEXT_OFFSET_RCX(%r11) , %rcx
	movq  LFI_CONTEXT_OFFSET_R8(%r11)  , %r8
	movq  LFI_CONTEXT_OFFSET_R9(%r11)  , %r9
	movsd LFI_CONTEXT_OFFSET_XMM0(%r11), %xmm0
	movsd LFI_CONTEXT_OFFSET_XMM1(%r11), %xmm1
	movsd LFI_CONTEXT_OFFSET_XMM2(%r11), %xmm2
	movsd LFI_CONTEXT_OFFSET_XMM3(%r11), %xmm3
	movsd LFI_CONTEXT_OFFSET_XMM4(%r11), %xmm4
	movsd LFI_CONTEXT_OFFSET_XMM5(%r11), %xmm5
	movsd LFI_CONTEXT_OFFSET_XMM6(%r11), %xmm6
	movsd LFI_CONTEXT_OFFSET_XMM7(%r11), %xmm7

	// save old rsp and load new rsp
	// save this to context as this value is needed for nested calls
	movq %rsp, LFI_CONTEXT_OFFSET_HOST_SP(%r11)
	movq LFI_CONTEXT_OFFSET_RSP(%r11)  , %rsp

	// set r14 and gs as the sandbox base address
	movq  LFI_CONTEXT_OFFSET_R14(%r11) , %r14
	wrgsbase %r14

	// load address of the lfi_retfn function that will make the return rtcall
	movq lfi_retfn@gottpoff(%rip), %r11
	movq %fs:(%r11), %r11
	// push this as the return address onto the user stack
	pushq %r11

	// load address of the function
	movq lfi_targetfn@gottpoff(%rip), %r11
	movq %fs:(%r11), %r11

	// jump to the sandbox function. It will return via a runtime call
	jmpq *%r11

.return:
	// Load context
	movq lfi_myctx@gottpoff(%rip), %r11
	movq %fs:(%r11), %r11

	// restore old stack -- already done by lfi rt
	// movq LFI_CONTEXT_OFFSET_RSP(%r11), %rsp

	// Save return registers
	movq  %rax, LFI_CONTEXT_OFFSET_RAX(%r11)
	movq  %rdx, LFI_CONTEXT_OFFSET_RDX(%r11)
	movsd  %xmm0, LFI_CONTEXT_OFFSET_XMM0(%r11)
	movsd  %xmm1, LFI_CONTEXT_OFFSET_XMM1(%r11)

	// Clear direction flag before call or return
	cld
	// Clear the x87, MMX, and SSE state.
	fxrstor fxrstor_default_state(%rip)

	// Undo dummy push
	popq %rbp
	// restore callee-saved registers
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	ret

.global lfi_callback
lfi_callback:
	// Entrypoint for callbacks. Callback target is in %r10.
	endbr64

	// Load context in r11
	movq lfi_myctx@gottpoff(%rip), %r11
	movq %fs:(%r11), %r11

	// Save params
	movq %rdi  , LFI_CONTEXT_OFFSET_RDI(%r11)
	movq %rsi  , LFI_CONTEXT_OFFSET_RSI(%r11)
	movq %rdx  , LFI_CONTEXT_OFFSET_RDX(%r11)
	movq %rcx  , LFI_CONTEXT_OFFSET_RCX(%r11)
	movq %r8   , LFI_CONTEXT_OFFSET_R8(%r11)
	movq %r9   , LFI_CONTEXT_OFFSET_R9(%r11)
	movsd %xmm0, LFI_CONTEXT_OFFSET_XMM0(%r11)
	movsd %xmm1, LFI_CONTEXT_OFFSET_XMM1(%r11)
	movsd %xmm2, LFI_CONTEXT_OFFSET_XMM2(%r11)
	movsd %xmm3, LFI_CONTEXT_OFFSET_XMM3(%r11)
	movsd %xmm4, LFI_CONTEXT_OFFSET_XMM4(%r11)
	movsd %xmm5, LFI_CONTEXT_OFFSET_XMM5(%r11)
	movsd %xmm6, LFI_CONTEXT_OFFSET_XMM6(%r11)
	movsd %xmm7, LFI_CONTEXT_OFFSET_XMM7(%r11)

	// Clear direction flag before call or return
	cld
	// Clear the x87, MMX, and SSE state.
	fxrstor fxrstor_default_state(%rip)

	// save old rsp and load new rsp
	// save this to context as this value is needed for nested calls
	movq %rsp, LFI_CONTEXT_OFFSET_RSP(%r11)
	movq LFI_CONTEXT_OFFSET_HOST_SP(%r11), %rsp

	// save context which will also align the stack
	pushq %r11

	// invoke target function
	callq *%r10

	// restore context
	popq %r11

	// Zero non-callee save registers except r11 and return registers
	xorq %rcx, %rcx
	xorq %rsi, %rsi
	xorq %rdi, %rdi
	xorq %r8,  %r8
	xorq %r9,  %r9
	xorq %r10, %r10

	// Clear direction flag before call or return
	cld
	// Clear the x87, MMX, and SSE state.
	fxrstor fxrstor_default_state(%rip)
	// Clear the AVX state that the "fxrstor" instruction doesn't cover.
	vzeroupper

	// Load return registers
	movq LFI_CONTEXT_OFFSET_RAX(%r11), %rax
	movq LFI_CONTEXT_OFFSET_RDX(%r11), %rdx
	movsd LFI_CONTEXT_OFFSET_XMM0(%r11), %xmm0
	movsd LFI_CONTEXT_OFFSET_XMM1(%r11), %xmm1

	// Restore the sandbox stack
	movq LFI_CONTEXT_OFFSET_RSP(%r11), %rsp

	// Do a masked return
	popq %r11
	andl $0xffffffe0, %r11d
	orq %r14, %r11
	jmpq *%r11

.section .rodata, "a"
/*
This is the memory block for "fxrstor" to read.  The only contents that matter
are the fcw and mxcsr words. The mxcsr_mask word is ignored by the hardware, so
there is no need to get the hardware-supplied value for that.  The hardware
requires that this address be aligned to 16 bytes.  Align it further to 64 bytes
to get potential cache benefits.
*/
        .balign 64
fxrstor_default_state:
         .byte 0x7f // fcw
         .byte 0x03 // fcw
        .space 22
        .byte 0x80 // mxcsr
        .byte 0x1f // mxcsr
        .space 486


#elif defined(__aarch64__) || defined(_M_ARM64)

// todo: floating point state?

.global lfi_trampoline
lfi_trampoline:
	bti jc

	// save callee-saved registers
	stp d8, d9,   [sp, #-16]!
	stp d10, d11, [sp, #-16]!
	stp d12, d13, [sp, #-16]!
	stp d14, d15, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	stp x29, x30, [sp, #-16]!

	// push the trampoline return onto the host stack
	adr x30, .return
	stp xzr, x30, [sp, #-16]!

	mrs x16, tpidr_el0
	// Load context in x17
	adrp x0, :tlsdesc:lfi_myctx
	ldr x17, [x0, :tlsdesc_lo12:lfi_myctx]
	add x0, x0, :tlsdesc_lo12:lfi_myctx
	.tlsdesccall lfi_myctx
	blr x17
	ldr x17, [x16, x0]

	// lfi_retfn in x30
	adrp x0, :tlsdesc:lfi_retfn
	ldr x30, [x0, :tlsdesc_lo12:lfi_retfn]
	add x0, x0, :tlsdesc_lo12:lfi_retfn
	.tlsdesccall lfi_retfn
	blr x30
	ldr x30, [x16, x0]

	// lfi_targetfn in x10
	adrp x0, :tlsdesc:lfi_targetfn
	ldr x10, [x0, :tlsdesc_lo12:lfi_targetfn]
	add x0, x0, :tlsdesc_lo12:lfi_targetfn
	.tlsdesccall lfi_targetfn
	blr x10
	ldr x10, [x16, x0]

	// Clear non param registers, except the tmp reg x10, x16, x17, x30
	mov x9, #0
	mov x11, #0
	mov x12, #0
	mov x13, #0
	mov x14, #0
	mov x15, #0
	mov x16, #0
	mov x19, #0
	mov x20, #0
	mov x21, #0
	mov x22, #0
	mov x23, #0
	mov x24, #0
	mov x25, #0
	mov x26, #0
	mov x27, #0
	mov x28, #0
	mov x29, #0
	movi d8, #0
	movi d9, #0
	movi d10, #0
	movi d11, #0
	movi d12, #0
	movi d13, #0
	movi d14, #0
	movi d15, #0

	// Load params
	ldr x0, [x17, LFI_CONTEXT_OFFSET_X0]
	ldr x1, [x17, LFI_CONTEXT_OFFSET_X1]
	ldr x2, [x17, LFI_CONTEXT_OFFSET_X2]
	ldr x3, [x17, LFI_CONTEXT_OFFSET_X3]
	ldr x4, [x17, LFI_CONTEXT_OFFSET_X4]
	ldr x5, [x17, LFI_CONTEXT_OFFSET_X5]
	ldr x6, [x17, LFI_CONTEXT_OFFSET_X6]
	ldr x7, [x17, LFI_CONTEXT_OFFSET_X7]
	ldr x8, [x17, LFI_CONTEXT_OFFSET_X8]
	ldr d0, [x17, LFI_CONTEXT_OFFSET_Q0]
	ldr d1, [x17, LFI_CONTEXT_OFFSET_Q1]
	ldr d2, [x17, LFI_CONTEXT_OFFSET_Q2]
	ldr d3, [x17, LFI_CONTEXT_OFFSET_Q3]
	ldr d4, [x17, LFI_CONTEXT_OFFSET_Q4]
	ldr d5, [x17, LFI_CONTEXT_OFFSET_Q5]
	ldr d6, [x17, LFI_CONTEXT_OFFSET_Q6]
	ldr d7, [x17, LFI_CONTEXT_OFFSET_Q7]

	// save old rsp and load new rsp
	// save this to context as this value is needed for nested calls
	mov x16, sp
	str x16, [x17, LFI_CONTEXT_OFFSET_HOST_SP]
	ldr x16, [x17, LFI_CONTEXT_OFFSET_SP]
	mov sp, x16

	// set x21 as the sandbox base address
	ldr x21, [x17, LFI_CONTEXT_OFFSET_X21]
	// set address pointer to a valid value
	mov x18, x21

	// load address of the lfi_retfn function that will make the return rtcall
	// already set in x30

	// clear other temporary registers
	mov x16, #0
	mov x17, #0

	// jump to the sandbox function. It will return via a runtime call
	br x10

.return:
	// Save x0
	mov x19, x0

	// Load context
	mrs x16, tpidr_el0
	adrp x0, :tlsdesc:lfi_myctx
	ldr x17, [x0, :tlsdesc_lo12:lfi_myctx]
	add x0, x0, :tlsdesc_lo12:lfi_myctx
	.tlsdesccall lfi_myctx
	blr x17
	ldr x17, [x16, x0]

	// Restore x0
	mov x0, x19

	// restore old stack
	ldr x16, [x17, LFI_CONTEXT_OFFSET_HOST_SP]
	mov sp, x16

	// Save return registers
	str  x0, [x17, LFI_CONTEXT_OFFSET_X0]
	str  x1, [x17, LFI_CONTEXT_OFFSET_X1]
	// Save floating point
	str  d0, [x17, LFI_CONTEXT_OFFSET_Q0]
	str  d1, [x17, LFI_CONTEXT_OFFSET_Q1]

	// restore callee-saved registers
	ldp x29, x30, [sp], 16
	ldp x27, x28, [sp], 16
	ldp x25, x26, [sp], 16
	ldp x23, x24, [sp], 16
	ldp x21, x22, [sp], 16
	ldp x19, x20, [sp], 16
	ldp d14, d15, [sp], 16
	ldp d12, d13, [sp], 16
	ldp d10, d11, [sp], 16
	ldp d8, d9,   [sp], 16
	br x30

.global lfi_callback
lfi_callback:
	.inst 0x0000dead
	// bti jc

	// // Save x0
	// mov x19, x0

	// // Load context
	// mrs x16, tpidr_el0
	// adrp x0, :tlsdesc:lfi_myctx
	// ldr x17, [x0, :tlsdesc_lo12:lfi_myctx]
	// add x0, x0, :tlsdesc_lo12:lfi_myctx
	// .tlsdesccall lfi_myctx
	// blr x17
	// ldr x17, [x16, x0]

	// // Restore x0
	// mov x0, x19

	// // Save params
	// str x0, [x17, LFI_CONTEXT_OFFSET_X0]
	// str x1, [x17, LFI_CONTEXT_OFFSET_X1]
	// str x2, [x17, LFI_CONTEXT_OFFSET_X2]
	// str x3, [x17, LFI_CONTEXT_OFFSET_X3]
	// str x4, [x17, LFI_CONTEXT_OFFSET_X4]
	// str x5, [x17, LFI_CONTEXT_OFFSET_X5]
	// str x6, [x17, LFI_CONTEXT_OFFSET_X6]
	// str x7, [x17, LFI_CONTEXT_OFFSET_X7]
	// str x8, [x17, LFI_CONTEXT_OFFSET_X8]
	// str d0, [x17, LFI_CONTEXT_OFFSET_Q0]
	// str d1, [x17, LFI_CONTEXT_OFFSET_Q1]
	// str d2, [x17, LFI_CONTEXT_OFFSET_Q2]
	// str d3, [x17, LFI_CONTEXT_OFFSET_Q3]
	// str d4, [x17, LFI_CONTEXT_OFFSET_Q4]
	// str d5, [x17, LFI_CONTEXT_OFFSET_Q5]
	// str d6, [x17, LFI_CONTEXT_OFFSET_Q6]
	// str d7, [x17, LFI_CONTEXT_OFFSET_Q7]

	// // save old rsp and load new rsp
	// // save this to context as this value is needed for nested calls
	// mov x16, sp
	// str x16, [x17, LFI_CONTEXT_OFFSET_SP]
	// ldr x16, [x17, LFI_CONTEXT_OFFSET_HOST_SP]
	// mov sp, x16

	// // save context and extra reg to align the stack
	// stp x17, x30, [sp, #-16]!

	// // load address of the target function
	// mrs x16, tpidr_el0
	// adrp x0, :tlsdesc:callback_func
	// ldr x17, [x0, :tlsdesc_lo12:callback_func]
	// add x0, x0, :tlsdesc_lo12:callback_func
	// .tlsdesccall callback_func
	// blr x17
	// ldr x17, [x16, x0]
	// // invoke
	// blr x17

	// // restore context
	// ldp x17, x30, [sp], 16

	// // Zero non-callee save registers except x17 and return registers
	// mov x2, #0
	// mov x3, #0
	// mov x4, #0
	// mov x5, #0
	// mov x6, #0
	// mov x7, #0
	// mov x8, #0
	// mov x9, #0
	// mov x10, #0
	// mov x11, #0
	// mov x12, #0
	// mov x13, #0
	// mov x14, #0
	// mov x15, #0
	// mov x16, #0
	// mov x18, #0
	// mov x29, #0
	// movi d0, #0
	// movi d1, #0
	// movi d2, #0
	// movi d3, #0
	// movi d4, #0
	// movi d5, #0
	// movi d6, #0
	// movi d7, #0
	// mov v8.d[1], xzr
	// mov v9.d[1], xzr
	// mov v10.d[1], xzr
	// mov v11.d[1], xzr
	// mov v12.d[1], xzr
	// mov v13.d[1], xzr
	// mov v14.d[1], xzr
	// mov v15.d[1], xzr
	// movi d16, #0
	// movi d17, #0
	// movi d18, #0
	// movi d19, #0
	// movi d20, #0
	// movi d21, #0
	// movi d22, #0
	// movi d23, #0
	// movi d24, #0
	// movi d25, #0
	// movi d26, #0
	// movi d27, #0
	// movi d28, #0
	// movi d29, #0
	// movi d30, #0
	// movi d31, #0

	// // Load return registers
	// ldr x0, [x17, LFI_CONTEXT_OFFSET_X0]
	// ldr x1, [x17, LFI_CONTEXT_OFFSET_X1]
	// ldr d0, [x17, LFI_CONTEXT_OFFSET_Q0]
	// ldr d1, [x17, LFI_CONTEXT_OFFSET_Q1]

	// // Restore the sandbox stack
	// ldr x16, [x17, LFI_CONTEXT_OFFSET_SP]
	// mov sp, x16

	// br x30

#else
#error "Unknown architecture"
#endif


.section .note.GNU-stack,"",@progbits
