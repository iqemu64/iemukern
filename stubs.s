//
//  stubs.s
//  iemukern
//
//  Created by Jay Wong on 10/3/14.
//  Copyright (c) 2014 Jay Wong. All rights reserved.
//

/*
// These codes are deprecated as I found a more sane
// way of doing it. But I left them for reference in
// case we are doing an in-function hook.

#include <architecture/i386/asm_help.h>

.globl __load_machfile

.align 2, 0x90
__load_machfile:

pushq %rdi
pushq %rsi
pushq %rdx
pushq %rcx
pushq %r8
pushq %r9

movq %rsi, %rdi   // argument mach_header
CALL_EXTERN(_Myload_machfile)

popq %r9
popq %r8
popq %rcx
popq %rdx
popq %rsi
popq %rdi

pushq %rbp
movq %rsp, %rbp
pushq %r15
movabsq (_g_load_machfile_ret), %rax
jmpq *%rax
*/