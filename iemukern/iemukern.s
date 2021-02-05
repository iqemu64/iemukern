
.data
.align 2
.private_extern _next_vm_fault_enter
_next_vm_fault_enter:   .quad 0

.text
.globl _orig_vm_fault_enter

.align 2, 0x90


_orig_vm_fault_enter:

pushq %rbp
movq %rsp, %rbp
pushq %r15
pushq %r14
pushq %r13
pushq %r12

movq _next_vm_fault_enter(%rip), %rax
jmpq *%rax
