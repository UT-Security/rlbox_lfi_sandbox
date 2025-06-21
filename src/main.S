.text

#if defined(__x86_64__) || defined(_M_X64)

.p2align 5
.global main
main:
	mov $60, %rax
	syscall

.p2align 5
.global _lfi_retfn
_lfi_retfn:
	#lfi:rtcall_return

#elif defined(__aarch64__) || defined(_M_ARM64)

.p2align 4
.global main
main:
	mov x8, #94
	svc #0

.p2align 4
.global _lfi_retfn
_lfi_retfn:
	#lfi:rtcall_return

#else
#error "Unknown architecture"
#endif

.data

.section .note.GNU-stack,"",@progbits
