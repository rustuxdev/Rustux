# Rustux userspace: getdents64 + Dir-OFD selftest.
# Lists the archive root and walks linux_dirent64 records at CPL3.
# nr in rax; args rdi,rsi,rdx. getdents64=217. Exit code = failures.
    .section .text
    .globl _start
_start:
    xor %r15d, %r15d            # failures

    # open("/") -> dir fd (expect 3)
    mov $2, %eax
    lea root(%rip), %rdi
    xor %esi, %esi              # O_RDONLY
    xor %edx, %edx
    syscall
    cmp $3, %rax
    je 1f
    inc %r15d
1:
    mov %rax, %r14              # dir fd

    # read(dirfd, buf, 4) -> -21 EISDIR
    mov %r14, %rdi
    lea -4096(%rsp), %rsi
    mov $4, %edx
    xor %eax, %eax
    syscall
    cmp $-21, %rax
    je 2f
    inc %r15d
2:
    # getdents64(dirfd, buf, 1024) -> n > 0
    mov %r14, %rdi
    lea -4096(%rsp), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    test %rax, %rax
    jg 3f
    inc %r15d
3:
    mov %rax, %r13              # bytes returned
    # walk the reclen chain — the archive guarantees 73 root
    # records: "\.", "..", "proc", every flat member, plus the
    # implicit lib64/lib dirs. Other tasks can only ADD records
    # (VFiles/VDIRS are global) — so a >= floor, never ==.
    lea -4096(%rsp), %rbx       # cursor
    xor %ebp, %ebp              # record count
4:
    movzwl 16(%rbx), %ecx       # d_reclen
    add %rcx, %rbx
    inc %ebp
    lea -4096(%rsp), %rax
    add %r13, %rax              # buf end
    cmp %rax, %rbx
    jb 4b
    cmp $73, %ebp
    jae 5f
    inc %r15d
5:
    # first record is "." — d_type==4 (DT_DIR), name '.'
    cmpb $4, -4096+18(%rsp)
    jne 51f
    cmpb $0x2e, -4096+19(%rsp)
    je 6f
51: inc %r15d
6:
    # getdents again -> 0 once drained: concurrent tasks can ADD
    # root records between calls (VFiles/VDIRS are global), so a
    # nonzero return is just new entries past pos — drain until EOF
    # with a bound. Only a stream that never ends is a failure.
    mov $256, %r12d
61:
    mov %r14, %rdi
    lea -4096(%rsp), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    test %rax, %rax
    je 7f
    dec %r12d
    jnz 61b
    inc %r15d
7:
    # lseek(dirfd, 0, SEEK_SET) -> 0 (rewind); getdents -> >0 again
    mov %r14, %rdi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %eax
    syscall
    test %rax, %rax
    je 8f
    inc %r15d
8:
    mov %r14, %rdi
    lea -4096(%rsp), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    test %rax, %rax
    jg 9f
    inc %r15d
9:
    # getdents64(1, ...) -> -20 ENOTDIR (console is not a dir)
    mov $1, %edi
    lea -4096(%rsp), %rsi
    mov $128, %edx
    mov $217, %eax
    syscall
    cmp $-20, %rax
    je 10f
    inc %r15d
10:
    # getdents64(99, ...) -> -9 EBADF
    mov $99, %edi
    lea -4096(%rsp), %rsi
    mov $128, %edx
    mov $217, %eax
    syscall
    cmp $-9, %rax
    je 11f
    inc %r15d
11:
    # report + exit(failures)
    mov $1, %eax
    mov $1, %edi
    lea msg(%rip), %rsi
    mov $(msg_end - msg), %edx
    syscall
    mov $60, %eax
    mov %r15d, %edi
    syscall
    ud2                         # unreachable
root:
    .ascii "/\0"
msg:
    .ascii "lstest: getdents checks done\n"
msg_end:
