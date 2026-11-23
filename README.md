# Rustux

<p align="center">
  <img src="docs/logo.png" alt="Rustux logo" width="220">
</p>

An incremental reimplementation of the Linux kernel in Rust, verified against
the original C kernel's recorded behavior — the first kernel to speak
IPv8 on the wire, and already running native Windows `.exe` binaries
alongside Linux ELF with no Wine in sight.

The C kernel source is the reference and stays untouched in a separate tree
(`$LINUX_REF`, default `~/linux-ref`). Each unit is ported one at a time with
[rust-anything](https://github.com/erkamyaman/rust-anything): the original's
behavior is recorded to `cases.jsonl`, the Rust port must match every recorded
case (`diff`) and pass `gate` before it is adopted.

<p align="center">
  <img src="docs/assets/rustux-boot.gif" alt="Rustux booting under OVMF/QEMU — GOP framebuffer console: memory map, APIC, PCI, e1000 DHCP, then the 61-task userspace suite including a real static BusyBox, GNU bash, and native PE .exe tasks">
</p>

*Booting under OVMF/QEMU: memory map, APIC and PCI bring-up, the e1000
driver doing ARP/IPv4 ping/DHCP over slirp, then the 61-task userspace
test suite — including real BusyBox applets, dash, dynamically
linked GNU bash 5.2, and the NT-personality `.exe` fixtures — on the
GOP framebuffer console (recorded headless via QMP screendump).*

<p align="center">
  <img src="docs/assets/rustux-bash.gif" alt="Interactive GNU bash 5.2 running on Rustux — login prompt, commands typed on the serial console, job control">
</p>

*A scripted session driving real GNU bash 5.2 (`make run-demo`):
every output byte is produced by actual bash under real fork/exec,
dynamic ld.so, pipes and job control (`jobs`, `kill %1`) — live
interactive input over the 16550 UART is `make run-bash` (headless
QEMU cannot feed serial input while a capture channel is attached,
so the session is scripted guest-side).*

<p align="center">
  <img src="docs/assets/rustux-doom.gif" alt="DOOM running on Rustux — the original id engine driving the GOP framebuffer through /dev/fb0">
</p>

*Yes, it runs DOOM.* The original id Software engine (the GPL'd
doomgeneric tree) built static-pie against the new `/dev/fb0` fbdev
device — Linux fb major 29 with real `FBIOGET_VSCREENINFO`/
`FBIOGET_FSCREENINFO` ioctls and positional `write()` frames — plus
the original `DOOM.WAD` game data. The attract demo plays E1M1
full-screen on the GOP framebuffer (`make run-doom`; drop your own
WAD at `kernel/user/doom.wad`).

## A world's first

Rustux carries the first known working implementation of
[draft-thain-ipv8](https://datatracker.ietf.org/doc/draft-thain-ipv8/):
the version-8 header, 32-bit Route Number + 32-bit local addressing,
and native EtherType `0x8080` — proven live between two Rustux
QEMU guests on a socket link:

```
B: ipv8: echo req from rn0x1 10.0.0.1 seq=1 -> replied
A: ipv8: echo reply rn0x2 10.0.0.2 seq=1 (71B native 0x8080)
```

Honest scope: IPv8 is an individual IETF Internet-Draft, not a
standard; its companion protocols (ARP8, ICMPv8, DHCP8, routing)
were never submitted, so Rustux implements only what the draft
actually specifies, plus clearly-labeled first-implementation
choices. IPv8 is an experimental differentiator — IPv6 remains on
the roadmap for real-world compatibility.

## Where the kernel is today

A `#![no_std]` UEFI kernel that boots under OVMF with its own GDT/IDT,
identity-mapped page tables, buddy allocator and slab heap, ACPI/LAPIC/
I/O-APIC interrupt routing, printk ring buffer, PCI enumeration, and an
e1000e NIC driver with real TX/RX DMA rings, MSI-X interrupt delivery,
ARP, IPv4, ICMP echo, and UDP/TCP over e1000 and loopback — plus the
IPv8 path above.

On top of that sits a growing Linux-ABI userspace: ring-3 tasks running
ELFs from a cpio initrd — static-PIE binaries and dynamically linked
ones via `PT_INTERP`/ld.so — a 120+-call syscall surface covering
`fork`/`execve`/`waitpid`, real signals with a sigreturn restorer
trampoline — including queued signals (`sigqueue`/`sigqueueinfo`,
`SA_SIGINFO` siginfo_t with real `si_code`/`si_pid`/`si_value`),
`brk`/anonymous and file-backed `mmap`/`munmap`/`mprotect`,
a hierarchical VFS with real symlinks (`symlink`/`symlinkat`,
`readlink`, `lstat` `S_IFLNK`, relative/absolute targets,
ELOOP-bounded resolution) and a generated `/proc` (per-pid
`stat`/`status`/`comm`/`cmdline`/`statm`/`fd`/`fdinfo`, the
`exe`/`cwd`/`root`/`self` links, real utime/stime accounting,
`uptime`/`meminfo`/`loadavg`/`stat`/`cpuinfo`/`mounts`),
pipes, sockets (`socket`/`bind`/
`listen`/`accept`/`connect`, `poll`/`ppoll`/`pselect6`, `epoll`,
`eventfd`, `timerfd`, `signalfd`, `inotify`, `getsockname`/
`getpeername`, `sendfile`), real `statfs`/`fstatfs` capacity
(`df` prints the frame allocator's numbers), a real `/dev` with character
devices (`mknod`, `/dev/null`/`zero`/`full`/`{,u}random`/`tty`/
`console`, `st_rdev`, `DT_CHR`), file metadata
(`chmod`/`chown`/`lchown`/`utimensat`, umask-applied modes,
real atime/mtime/ctime — `ls -l` shows it), `rseq`, a keyboard- and
UART-driven terminal
with a canonical/raw line discipline and full termios, real process
groups, sessions and a controlling tty (`/dev/tty`, `tcsetpgrp`,
SIGTTIN, SIGTTOU with TOSTOP — the whole job-control model), `clone`
flags up to full pthread-style thread groups (`CLONE_VM|FS|FILES|
SIGHAND|THREAD`, `SETTLS`, futex wait/wake, `CHILD_CLEARTID`), and real
`vfork` semantics — a shared-mm child running on the parent's stack
while the parent sleeps, Unix98 PTYs
(`posix_openpt`/`TIOCGPTN`/`TIOCGPTPEER`/`unlockpt`, pts indexes,
hangup semantics), a polled ATA PIO driver behind real `/dev/sda`
and `/dev/sr0` block nodes (`CDROMEJECT` included), and a GOP
framebuffer xterm-subset console that ncurses targets.
The suite boots a real static **BusyBox**,
real Debian **dash**, and dynamically linked **GNU bash 5.2** — 72
tasks, all passing; `make run-bash` boots an
interactive `-bash` login shell on the serial console.
Beyond the suite, `make run-apt` proves real Debian package
management end to end — `apt-get update`/`apt install` fetch from
deb.debian.org over slirp and dpkg unpacks/configures the package
under a kernel pty — and `make run-iso` builds a bootable
**live/install ISO**: El Torito media that offers a live bash
session or an ATA install to disk, ejects itself, and reboots into
the installed system.

And the kernel is **dual-personality**: next to the Linux ABI sits a
native NT personality — real PE32+ `.exe` binaries running on a
kernel-owned Windows syscall table, with no Wine-style userspace shim
(its own section below).

Every rung is also security-reviewed: a scoped audit of the diff plus a
check of that subsystem's published kernel CVEs — each gets a written
verdict in [docs/cve-matrix.md](docs/cve-matrix.md) (structurally
absent, explicitly mitigated, or a documented divergence), gathered
into a flat ledger of 136 unique CVEs so far.

## A second personality: native Windows `.exe`, no Wine

Wine exists because the kernel underneath it can't speak NT — so an
entire reimplementation of the Win32 stack has to live in userspace.
Rustux speaks NT itself. A PE32+ `.exe` is a first-class executable
format next to ELF: the kernel loads the image, dispatches a
Windows-x64 syscall table, and answers in NTSTATUS. The Win32 layer
shrinks to a thin argument-marshalling thunk instead of a
compatibility tower.

What runs today, end to end:

- **PE32+ loader** — imports, relocations, TLS directory; a normal
  `gcc -O2` MinGW binary with real CRT startup runs its `main` and
  returns.
- **NT syscall surface** — a Windows-x64 service-number table with
  NTSTATUS returns and the `r10`-arg1/stack-args convention:
  `NtReadFile`/`NtWriteFile`/`NtClose`, `NtAllocateVirtualMemory`,
  `NtDelayExecution`, `NtTerminateProcess`/`NtTerminateThread`, plus
  kernel services for files, directories, sections and VM.
- **Real NT object model** — TEB/PEB mapped per process
  (`gs:[0x30]` reads the TEB), per-process handle tables, waitable
  process and thread objects carrying real exit codes.
- **Threads and processes** — `CreateThread` with suspend/resume,
  `CreateProcessA` with `CREATE_SUSPENDED` + `ResumeThread`,
  `WaitForSingleObject` on thread *and* process handles,
  `GetExitCodeProcess`. A Win32 parent spawns a child `.exe`, waits
  on its handle and reads its exit code — natively.
- **The DLL stack Windows binaries link against** — imports resolve
  against synthetic `ntdll.dll`, `kernel32.dll`, `kernelbase.dll` and
  `api-ms-win-*` sets, served by generated Win32→NT translation
  thunks; `msvcrt.dll`/`ucrtbase.dll` resolve against a CRT surface
  (`__getmainargs`, `_initterm`, `malloc`/`free`, `_errno`,
  `puts`/`fwrite`, ...) backed by a writable thunk-state page for
  argv/envp/`FILE[]`/TLS.
- **`LoadLibrary` + the full `DllMain` lifecycle** — dependent-DLL
  loading with a real reference graph, `DLL_PROCESS_ATTACH`/`DETACH`
  and `DLL_THREAD_ATTACH`/`DETACH` in Windows order, and
  `PIMAGE_TLS_CALLBACK` arrays fired through the same notifications —
  MinGW's `__thread` destructor list works.
- **Native NT heap, VM and file services** — reserve/commit/decommit
  virtual memory, section objects, NT file and directory APIs.

Honest scope: this is groundwork, not Windows compatibility — the
surface is a growing subset proved by real MinGW-compiled fixtures
(spawn/wait/exit-code/suspend-resume all verified in the suite), not
arbitrary Windows applications. Ordering details are checked against
real `ntdll` behavior so the architecture is right before the surface
is wide. Linux remains the primary target.

## Milestone timeline

The git history reads like a speedrun — from the first boot proof to
GNU bash and native `.exe` tasks in five days:

| When | Milestone |
|---|---|
| **Nov 18** | **The porting engine.** A bootable `#![no_std]` UEFI kernel plus the first verified C→Rust port — then the `lib/` utility layer arrives in gated waves: math/div64, CRC, SipHash/xxHash/jhash, bitmap, rbtree, string, SHA-1/2 + HMAC, kfifo, llist, seqbuf — each unit `diff`'ed against the C original's recorded behavior before adoption. |
| **Nov 19** | **The data-structure core lands.** rhashtable, xarray, idr, radix/maple tree, genradix, interval tree, assoc-array, kstrtox + string_helpers, percpu counters, printk ring — the foundational libraries every later subsystem stands on, all gate-green. |
| **Nov 20** | **Hardware → wire → ring 3, in one day.** fbcon + boot logo, ExitBootServices, own page tables, buddy + slab/kmalloc, GDT/IDT, LAPIC timer, IST guard stack, the Rustux rename; ACPI + I/O APIC, PS/2 keyboard, PCI, e1000e TX/RX DMA + MSI-X; ARP, IPv4/ICMP ping, **world-first IPv8 on the wire**, IPv6/NDP, UDP + a real DHCP lease, TCP handshake, ChaCha20 CSPRNG — then ring 3: ELF loader, syscall boundary, initrd rootfs, preemptive scheduler, `fork`/`wait4`, pipes, signals, per-task fault isolation, FPU context, poll, UDP+TCP sockets, `brk`/`mmap`, and the glibc-startup ABI. |
| **Nov 21** | **A real Linux userspace.** pthread-class `clone` flags + futex + `CHILD_CLEARTID` + `CLONE_VM`, hierarchical VFS, file-backed `mmap`, real `vfork` — then real **BusyBox**, `PT_INTERP` dynamic `ld.so`, Debian **dash** and **GNU bash 5.2** (interactive `-bash` on the serial console); process groups/sessions, tty line discipline + full job control (`SIGTTOU`/`TOSTOP`); epoll, eventfd, timerfd, signalfd, inotify; a generated `/proc`. |
| **Nov 22** | **Last POSIX gaps → the second personality.** Queued signals, real `statfs`, VFS symlinks, file metadata, char devices + a real `/dev` — then the NT personality lands whole: PE32+ `.exe` loader, NT syscall table with NTSTATUS returns, TEB/PEB, handle tables, the Win32/CRT thunk layer (real MinGW exes end-to-end), NT file/dir/heap/VM services, threads with suspend/resume, section objects, `LoadLibrary` + the full `DllMain` attach/detach lifecycle, TLS callbacks, `CreateProcessA`. The suite stands at 61 tasks, all passing. |
| **Nov 23** | **A real Debian system, installable.** Real `apt-get update` + `apt install` over slirp — DNS, TCP, the full dpkg toolchain (dpkg/dpkg-deb/dpkg-query/dpkg-split + GNU tar + ldconfig) running a package's unpack/configure under a real kernel pty. Unix98 PTYs (`/dev/ptmx`, `/dev/pts/N`, `TIOCGPTN`/`TIOCGPTPEER`, `unlockpt`, termios, hangup). A polled ATA PIO driver → `/dev/sda` block device + `/dev/sr0` with the `CDROMEJECT` ioctl. A GOP framebuffer terminal (xterm subset: SGR colors + persistent bold, DEC line drawing, scroll regions, alt screen, `REP`) that runs color-coded ncurses `htop` over `/proc/<pid>/task` with correct idle-vs-busy CPU accounting. And a **bootable live/install ISO** — OVMF El Torito media with a demo menu: live bash session or stream-to-disk install, eject, reboot onto the installed system. The installed disk skips the menu and boots straight to `login:` — real `/etc/passwd` + `/etc/shadow` + `crypt()` authentication (SHA-512-crypt, termios echo-off), then bash as pid 1. The suite stands at 72 tasks, all passing. |
| **Nov 23 (cont.)** | **It runs DOOM.** The GOP framebuffer becomes a real `/dev/fb0` fbdev device (major 29: `FBIOGET_VSCREENINFO`/`FSCREENINFO`, positional write, seekable), and the original id DOOM engine — doomgeneric, built static-pie — plays the E1M1 attract demo full-screen from the original `DOOM.WAD`. Plus the platform-compat rung: distro-structure xorriso ISO (BIOS+UEFI El Torito, hybrid MBR/GPT) and console-mirrored fault reports for serial-less machines. |
| **Every rung** | A scoped security audit plus a cve.now sweep of that subsystem's published kernel CVEs — 137 unique CVEs recorded in [docs/cves-addressed.md](docs/cves-addressed.md) so far. |

## Acknowledgements

- **Linus Torvalds** — for the Linux kernel itself
  ([torvalds/linux](https://github.com/torvalds/linux)), the reference this
  project reimplements unit by unit.
- **[@erkamyaman_ng](https://x.com/erkamyaman_ng)** — for
  [rust-anything](https://github.com/erkamyaman/rust-anything), the
  record/diff/gate porting toolchain that drives every verified port here.

## Layout

- `kernel/` — the kernel itself; a `#![no_std]` UEFI application today
- `ports/` — per-unit work areas: extracted C harness + the verified Rust crate
- `docs/` — [kernel-map.md](docs/kernel-map.md) (subsystem inventory),
  [roadmap.md](docs/roadmap.md) (port order),
  [cve-matrix.md](docs/cve-matrix.md) (per-rung CVE rationale),
  [cves-addressed.md](docs/cves-addressed.md) (flat ledger of every CVE
  checked and protected against — regenerated by
  [tools/cve-ledger.py](tools/cve-ledger.py))
- [HANDOVER.md](HANDOVER.md) — per-rung continuation notes + ABI matrix
- `test/zorin/` — real-OS acceptance fixtures + ladder (see `test/zorin/README.md`)

## Build & test (Ubuntu 24.04 / Zorin OS 18.1)

Verified on Zorin OS 18.1 (Ubuntu 24.04 base) with gcc 13.3, QEMU 8.2.2 + OVMF,
cargo 1.100 via rustup:

```sh
rustup target add x86_64-unknown-uefi
sudo apt install qemu-system-x86 ovmf mtools gcc make

cargo test -p klib   # 327 unit tests for the ported klib modules
make run             # builds kernel.efi -> esp.img, boots under OVMF in QEMU;
                     # PASS when the kernel exits QEMU with status 33
make run-bash        # solo image: an interactive -bash login shell on
                     # the serial console — type into the terminal
make run-apt         # real apt-get update + install hello-traditional
                     # over slirp; dpkg unpacks under a kernel pty
make run-iso         # builds rustux-demo.iso, installs it to target.img
                     # in one QEMU session, then boots the installed disk
./boot-demo.sh iso   # same ISO demo with a visible QEMU window
make run-ttout       # solo image: the TOSTOP/SIGTTOU write-gate test
                     # (must own the machine; see HANDOVER run-91)
```

The kernel prints its boot proofs to COM1 and to a GOP framebuffer text
console (VGA 8x16 font from `lib/fonts/font_8x16.c`), runs its NIC
datapath and protocol self-tests live (ARP round-trip, IPv4 ping against
QEMU slirp, MSI-X receive interrupt), then exits via `isa-debug-exit` —
a `-display gtk` QEMU window shows the boot logo and the kernel's own
console output.

Rustux is GPL-2.0-only (`LICENSE`): its ported units are derivative
works of GPL-2.0-only kernel code.
