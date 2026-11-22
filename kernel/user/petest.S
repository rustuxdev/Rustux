# Rustux NT-personality selftest — speaks the REAL Windows x64
# syscall convention: the ntdll stub does `mov r10, rcx`, so arg1
# arrives in r10, args 2-4 in rdx/r8/r9, args 5+ on the user stack
# at [rsp+0x28] (return addr + four-slot shadow space). Returns are
# NTSTATUS in rax. Service numbers are the Win10 x64 table.
# This file assembles to flat code; tools/mkpe.py wraps it as PE32+.
    .section .text
    .globl _start
_start:
    sub $0x68, %rsp             # arg area + alignment

    # Personality proof: gs:[0x30] is TEB.Self — nonzero only if the
    # NT loader mapped the TEB and MSR_GS_BASE followed the task.
    mov %gs:0x30, %rax
    test %rax, %rax
    jne 1f
    lea noteb(%rip), %rcx
    mov $noteb_len, %edx
    jmp fail_msg

1:
    # NtWriteFile(stdout=2, NULL,NULL,NULL, NULL, msg, len, NULL,NULL)
    mov $2, %r10
    xor %edx, %edx
    xor %r8d, %r8d
    xor %r9d, %r9d
    movq $0, 0x28(%rsp)         # iosb
    lea msg(%rip), %rax
    mov %rax, 0x30(%rsp)        # buffer
    movq $msg_len, 0x38(%rsp)   # length
    movq $0, 0x40(%rsp)         # byteoffset
    movq $0, 0x48(%rsp)         # key
    mov $8, %eax                # NtWriteFile
    syscall
    test %eax, %eax             # NTSTATUS < 0 = failure
    jns 2f
    lea wfail(%rip), %rcx
    mov $wfail_len, %edx
    jmp fail_msg

2:
    # NtAllocateVirtualMemory(-1, &slot, 0, &sz, COMMIT|RESERVE, RW)
    mov $-1, %r10
    lea slot(%rip), %rdx
    xor %r8d, %r8d
    lea sz(%rip), %r9
    movq $0x3000, 0x28(%rsp)    # MEM_COMMIT|MEM_RESERVE
    movq $4, 0x30(%rsp)         # PAGE_READWRITE
    mov $0x18, %eax
    syscall
    test %eax, %eax
    jns 3f
    lea afail(%rip), %rcx
    mov $afail_len, %edx
    jmp fail_msg
3:
    # Fault-check the committed page.
    mov slot(%rip), %rax
    test %rax, %rax
    je 4f
    movb $0x41, (%rax)
    cmpb $0x41, (%rax)
    je 4f
    lea vfail(%rip), %rcx
    mov $vfail_len, %edx
    jmp fail_msg
4:
    # NtDelayExecution(alertable=0, &ivl) — ivl = -100000 (10ms).
    xor %r10d, %r10d
    lea ivl(%rip), %rdx
    mov $0x34, %eax
    syscall

    # Second write proves the deadline wait returned to userspace.
    mov $2, %r10
    xor %edx, %edx
    xor %r8d, %r8d
    xor %r9d, %r9d
    movq $0, 0x28(%rsp)
    lea msg2(%rip), %rax
    mov %rax, 0x30(%rsp)
    movq $msg2_len, 0x38(%rsp)
    movq $0, 0x40(%rsp)
    movq $0, 0x48(%rsp)
    mov $8, %eax
    syscall

    # NtTerminateProcess(-1, 0)
    mov $-1, %r10
    xor %edx, %edx
    mov $0x2c, %eax
    syscall

fail_msg:
    # rcx=buf, edx=len — emit the failure string then exit(1).
    mov %rcx, %rsi
    mov %edx, %edi
    mov $2, %r10
    xor %edx, %edx
    xor %r8d, %r8d
    xor %r9d, %r9d
    movq $0, 0x28(%rsp)
    mov %rsi, 0x30(%rsp)
    mov %rdi, 0x38(%rsp)
    movq $0, 0x40(%rsp)
    movq $0, 0x48(%rsp)
    mov $8, %eax
    syscall
    mov $-1, %r10
    mov $1, %edx
    mov $0x2c, %eax
    syscall

msg:    .ascii "petest: NT personality + TEB OK\n"
        .set msg_len, . - msg
msg2:   .ascii "petest: alloc+delay OK, terminating\n"
        .set msg2_len, . - msg2
noteb:  .ascii "petest: FAIL gs:[0x30] == 0\n"
        .set noteb_len, . - noteb
wfail:  .ascii "petest: FAIL NtWriteFile\n"
        .set wfail_len, . - wfail
afail:  .ascii "petest: FAIL NtAllocateVirtualMemory\n"
        .set afail_len, . - afail
vfail:  .ascii "petest: FAIL committed page unreadable\n"
        .set vfail_len, . - vfail
        .align 8
slot:   .quad 0
sz:     .quad 0x2000
ivl:    .quad -100000           # 10ms in 100-ns units
