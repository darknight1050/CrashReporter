.text
.p2align 2
.global crash_reporter_call_on_stack
.hidden crash_reporter_call_on_stack
.type crash_reporter_call_on_stack, %function
crash_reporter_call_on_stack:
    .cfi_startproc
    // x29 survives the callback and also lets unwinders cross the stack switch.
    stp x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset x29, -16
    .cfi_offset x30, -8
    mov x29, sp
    .cfi_def_cfa_register x29
    mov x9, x0
    mov x10, x1
    mov x0, x2
    mov sp, x9
    blr x10
    mov sp, x29
    .cfi_def_cfa_register sp
    ldp x29, x30, [sp], #16
    .cfi_def_cfa_offset 0
    .cfi_restore x29
    .cfi_restore x30
    ret
    .cfi_endproc
.size crash_reporter_call_on_stack, .-crash_reporter_call_on_stack
.section .note.GNU-stack,"",%progbits
