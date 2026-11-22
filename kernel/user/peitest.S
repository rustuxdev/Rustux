# Rustux NT import/reloc selftest — a PE32+ image with a REAL import
# descriptor importing NtWriteFile/NtTerminateProcess from ntdll.dll,
# plus one DIR64 base-relocation slot. Calls go through the IAT like
# compiled code (`call *iat_x(%rip)`), in the standard Win64 ABI:
# args rcx/rdx/r8/r9, stack args at [rsp+0x20], 0x20 shadow space.
# mkpe.py finds the IMPDIR00/RELOC markers to fill the data dirs.
    .section .text
    .globl _start
_start:
    sub $0x68, %rsp

    # Reloc check: ptr_slot was written as image_base+RVA; the
    # loader's DIR64 fixup must turn it into this task's load VA.
    mov ptr_slot(%rip), %rax
    lea reloc_target(%rip), %rcx
    cmp %rcx, %rax
    je 1f
    lea rfail(%rip), %rcx
    mov $rfail_len, %edx
    jmp fail

1:
    # NtWriteFile(2, NULL,NULL,NULL, NULL, msg, len, NULL, NULL)
    # — called through the IAT exactly like a compiled binary.
    mov $2, %ecx                # handle
    xor %edx, %edx              # event
    xor %r8d, %r8d              # apc
    xor %r9d, %r9d              # apcctx
    movq $0, 0x20(%rsp)         # iosb
    lea msg(%rip), %rax
    mov %rax, 0x28(%rsp)        # buffer
    movq $msg_len, 0x30(%rsp)   # length
    movq $0, 0x38(%rsp)         # byteoffset
    movq $0, 0x40(%rsp)         # key
    call *iat_write(%rip)
    test %eax, %eax             # NTSTATUS
    jns 2f
    lea wfail(%rip), %rcx
    mov $wfail_len, %edx
    jmp fail
2:
    # Second imported call — the relocated pointer's own bytes are
    # the message, proving the fixup landed before entry.
    mov $2, %ecx
    xor %edx, %edx
    xor %r8d, %r8d
    xor %r9d, %r9d
    movq $0, 0x20(%rsp)
    mov ptr_slot(%rip), %rax    # &reloc_target via the patched slot
    mov %rax, 0x28(%rsp)
    movq $rt_len, 0x30(%rsp)
    movq $0, 0x38(%rsp)
    movq $0, 0x40(%rsp)
    call *iat_write(%rip)
    test %eax, %eax
    jns 3f
    lea wfail(%rip), %rcx
    mov $wfail_len, %edx
    jmp fail
3:
    # NtTerminateProcess(-1, 0) via IAT.
    mov $-1, %rcx
    xor %edx, %edx
    call *iat_term(%rip)

fail:
    mov %rcx, %rsi
    mov %edx, %edi
    mov $2, %ecx
    xor %edx, %edx
    xor %r8d, %r8d
    xor %r9d, %r9d
    movq $0, 0x20(%rsp)
    mov %rsi, 0x28(%rsp)
    mov %rdi, 0x30(%rsp)
    movq $0, 0x38(%rsp)
    movq $0, 0x40(%rsp)
    call *iat_write(%rip)
    mov $-1, %rcx
    mov $1, %edx
    call *iat_term(%rip)

msg:    .ascii "peitest: imports resolved via IAT\n"
        .set msg_len, . - msg
reloc_target:
        .ascii "peitest: DIR64 reloc patched\n"
        .set rt_len, . - reloc_target
rfail:  .ascii "peitest: FAIL DIR64 slot not rebased\n"
        .set rfail_len, . - rfail
wfail:  .ascii "peitest: FAIL imported NtWriteFile\n"
        .set wfail_len, . - wfail

        .align 8
# ptr_slot holds image_base+RVA of reloc_target — the loader's DIR64
# fixup (delta = bias - image_base) turns it into the load VA.
# mkpe.py emits the image with ImageBase 0x140000000, so the slot
# value is 0x140000000 + (reloc_target - _start) + 0x1000.
ptr_slot:
        .quad reloc_target - _start + 0x140000000 + 0x1000

# --- import structures (magic marker -> mkpe.py writes dir[IMPORT])
        .ascii "IMPDIR00"
imp_desc:                       # IMAGE_IMPORT_DESCRIPTOR: ntdll.dll
        .long ilt - _start + 0x1000   # OriginalFirstThunk (RVA)
        .long 0                       # TimeDateStamp
        .long 0                       # ForwarderChain
        .long dllname - _start + 0x1000  # Name (RVA)
        .long iat - _start + 0x1000   # FirstThunk (RVA)
        .fill 20, 1, 0                # terminator descriptor
        .align 8
ilt:    .quad fn_write - _start + 0x1000
        .quad fn_term - _start + 0x1000
        .quad 0
iat:
iat_write:
        .quad fn_write - _start + 0x1000   # loader patches -> stub
iat_term:
        .quad fn_term - _start + 0x1000
        .quad 0
dllname: .ascii "ntdll.dll"
        .byte 0
        .align 2
fn_write: .word 0
        .ascii "NtWriteFile"
        .byte 0
        .align 2
fn_term: .word 0
        .ascii "NtTerminateProcess"
        .byte 0

# --- base relocation block (marker -> mkpe.py writes dir[BASERELOC])
        .align 8
        .ascii "RELOC\0\0\0"
reloc_blk:
        .long 0x1000                  # page RVA (our only page)
        .long 12                      # block size (hdr + 2 entries)
        .word 0xA000 | (ptr_slot - _start)   # DIR64, offset in page
        .word 0x0000                  # ABSOLUTE pad
