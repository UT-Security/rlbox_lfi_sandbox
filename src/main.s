.text

.p2align 5
.global main
main:
	mov $60, %rax
	syscall

.p2align 5
.global _lfi_retfn
_lfi_retfn:
	//lfi:rtcall_return

.data

.section .note.GNU-stack,"",@progbits
