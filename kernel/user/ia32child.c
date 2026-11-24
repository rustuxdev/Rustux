// 32-bit exec target for ia32test's fork+execve+wait4 proof: a
// separate ELFCLASS32 image at the canonical i386 base 0x08048000.
// Prints one line through int 0x80 and exits 7 so the parent can
// check the wait status end-to-end.

__attribute__((used)) const char msg[] = "ia32: child exec'd\n";

__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "movl $4, %eax\n\t"   // write
        "movl $1, %ebx\n\t"   // fd 1
        "movl $msg, %ecx\n\t" // msg address
        "movl $19, %edx\n\t"  // sizeof(msg) - 1
        "int $0x80\n\t"
        "movl $1, %eax\n\t"   // exit
        "movl $7, %ebx\n\t"   // status 7
        "int $0x80\n\t");
}
