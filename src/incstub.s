.section .rodata
.global ${INCSTUB_FILENAME}_start
.global ${INCSTUB_FILENAME}_end
${INCSTUB_FILENAME}_start:
    .incbin "${INCSTUB_FILENAME}"
${INCSTUB_FILENAME}_end:

.section .note.GNU-stack,"",@progbits
