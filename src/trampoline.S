#include "lfi_ctx_offsets.h"

.text

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

	// Clear non param reg except the tmp reg r11
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
	movq %rsp, LFI_CONTEXT_OFFSET_HOST_RSP(%r11)
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

// .global lfi_callback
// lfi_callback:
// 	endbr64

// 	// Load context
// 	movq lfi_myctx@gottpoff(%rip), %r11
// 	movq %fs:(%r11), %r11

// 	// Save params
// 	movq %rdi  , LFI_CONTEXT_OFFSET_RDI(%r11)
// 	movq %rsi  , LFI_CONTEXT_OFFSET_RSI(%r11)
// 	movq %rdx  , LFI_CONTEXT_OFFSET_RDX(%r11)
// 	movq %rcx  , LFI_CONTEXT_OFFSET_RCX(%r11)
// 	movq %r8   , LFI_CONTEXT_OFFSET_R8(%r11)
// 	movq %r9   , LFI_CONTEXT_OFFSET_R9(%r11)
// 	movsd %xmm0, LFI_CONTEXT_OFFSET_XMM0(%r11)
// 	movsd %xmm1, LFI_CONTEXT_OFFSET_XMM1(%r11)
// 	movsd %xmm2, LFI_CONTEXT_OFFSET_XMM2(%r11)
// 	movsd %xmm3, LFI_CONTEXT_OFFSET_XMM3(%r11)
// 	movsd %xmm4, LFI_CONTEXT_OFFSET_XMM4(%r11)
// 	movsd %xmm5, LFI_CONTEXT_OFFSET_XMM5(%r11)
// 	movsd %xmm6, LFI_CONTEXT_OFFSET_XMM6(%r11)
// 	movsd %xmm7, LFI_CONTEXT_OFFSET_XMM7(%r11)


// 	// Clear direction flag before call or return
// 	cld
// 	// Clear the x87, MMX, and SSE state.
// 	fxrstor fxrstor_default_state(%rip)

// 	// save old rsp and load new rsp
// 	// save this to context as this value is needed for nested calls
// 	movq %rsp, LFI_CONTEXT_OFFSET_RSP(%r11)
// 	movq LFI_CONTEXT_OFFSET_HOST_RSP(%r11), %rsp

// 	// save context which will also align the stack
// 	pushq %r11

// 	// load address of the target function and invoke
// 	movq callback_func@gottpoff(%rip), %r11
// 	movq %fs:(%r11), %r11
// 	callq *%r11

// 	// restore context
// 	popq %r11

// 	// Zero non-callee save registers except r11 and return registers
// 	xorq %rcx, %rcx
// 	xorq %rsi, %rsi
// 	xorq %rdi, %rdi
// 	xorq %r8,  %r8
// 	xorq %r9,  %r9
// 	xorq %r10, %r10

// 	// Clear direction flag before call or return
// 	cld
// 	// Clear the x87, MMX, and SSE state.
// 	fxrstor fxrstor_default_state(%rip)
// 	// Clear the AVX state that the "fxrstor" instruction doesn't cover.
// 	vzeroupper

// 	// Load return registers
// 	movq LFI_CONTEXT_OFFSET_RAX(%r11), %rax
// 	movq LFI_CONTEXT_OFFSET_RDX(%r11), %rdx
// 	movsd LFI_CONTEXT_OFFSET_XMM0(%r11), %xmm0

// 	// Restore the sandbox stack
// 	movq LFI_CONTEXT_OFFSET_RSP(%r11), %rsp

// 	// TODO: UNSAFE!
// 	ret

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

.section .note.GNU-stack,"",@progbits
