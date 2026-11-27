# Rustux

<p align="center">
  <a href="https://youtu.be/2G_8bwKKcFk">
    <img src="https://img.youtube.com/vi/2G_8bwKKcFk/maxresdefault.jpg" width="880"
      alt="Rustux in 52 seconds — watch on YouTube">
  </a>
</p>

*▶ [Watch Rustux in 52 seconds](https://youtu.be/2G_8bwKKcFk): OVMF
boot footage, the record→port→diff→gate method, real
bash/BusyBox/apt, the self-installing ext2 disk with
`apt install -y nginx` at exit 0, DOOM on `/dev/fb0`, the native NT
`.exe` personality, the Nov 26 driver + IPC shelf, and IPv8 on the
wire.*

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
  <img src="docs/assets/rustux-doom-attract.gif" alt="DOOM running on Rustux — the original id engine driving the GOP framebuffer through /dev/fb0">
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
ones via `PT_INTERP`/ld.so — a ~150-call syscall surface (plus a
parallel ia32 `int 0x80` table running real 32-bit ELF32 binaries on
low-4GiB compat address spaces) covering
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
hangup semantics), real shared memory (`MAP_SHARED|MAP_ANONYMOUS`
refcounted segments — fork aliases the same frames, private
mappings stay private — plus `memfd_create` with `F_SEAL_*`,
SysV SHM/MSG/SEM), the modern mm shelf
(`mremap`, `madvise`, `mincore`, `mlock*`/`munlock*`,
`process_madvise`, `mseal`, `cachestat`, `memfd_secret`), the
xattr family (`*xattr` + `*xattrat`), the modern syscall shelf
(`clone3`, `close_range`, `epoll_pwait2`, `openat2` with
RESOLVE_*, `process_mrelease`, `pidfd_*`, `futex_waitv`,
`fchmodat2`, `select`, `sched_setattr`/`getattr`, `msync`,
`process_vm_readv`/`writev`, `copy_file_range`, `splice`/`tee`/
`vmsplice`, `fallocate`, `preadv`/`pwritev`, `sigaltstack`,
`execveat` + real credential handover, POSIX per-process
timers, `waitid`), and socket families beyond TCP — `AF_UNIX`
stream/dgram/`socketpair` with `SCM_RIGHTS` fd-passing,
`SOCK_SEQPACKET`, `AF_PACKET`, `AF_NETLINK` route dumps,
`/dev/net/tun`, `recvmmsg`.
The block stack runs from polled ATA PIO through AHCI/SATA,
virtio-blk and NVMe (admin + I/O queues, write path, MSI-X,
multi-namespace, TRIM/discard + flush) behind real
`/dev/sdN`/`vdN`/`nvmeXnYpN` nodes, with a GPT partition scan,
partition minors, SG_IO + virtio-scsi passthrough, `/dev/loopN`
and the CDROM ioctl family; the rest of the virtio fleet is
there too (net datapath with IRQ-driven RX + control queue,
input → evdev, console `/dev/hvc0`, balloon, rng, the modern
non-transitional transport). ext2/ext3/ext4 readers feed a real
`mount()` and partition views, and a GOP framebuffer
xterm-subset console hosts ncurses.
The suite boots a real static **BusyBox** (x86-64 *and* i386),
real Debian **dash**, and dynamically linked **GNU bash 5.2** —
110 tasks, all passing; `make run-bash` boots an
interactive `-bash` login shell on the serial console.
Beyond the suite, `make run-apt` proves real Debian package
management end to end — `apt-get update`/`apt install` fetch from
deb.debian.org over slirp and dpkg unpacks/configures the package
under a kernel pty — and `make run-iso` builds a bootable
**live/install ISO**: El Torito media that offers a live bash
session or an install to disk, ejects itself, and reboots into
the installed system. The install writes a real MBR partition
table and an ext2 root (the kernel mounts it, pivots in, and pid
1 runs from the installed tree behind `login:` SHA-512-crypt
auth) — and on that installed system `apt install -y nginx`
runs the full Debian dependency chain, maintainer scripts and
all, to exit 0: **nginx 1.22.1, installed by real dpkg**.

And the kernel is **dual-personality**: next to the Linux ABI sits a
native NT personality — real PE32+ `.exe` binaries running on a
kernel-owned Windows syscall table, with no Wine-style userspace shim
(its own section below).

Every rung is also security-reviewed: a scoped audit of the diff plus a
check of that subsystem's published kernel CVEs — each gets a written
verdict in [docs/cve-matrix.md](docs/cve-matrix.md) (structurally
absent, explicitly mitigated, or a documented divergence), gathered
into a flat ledger of 493 unique CVEs so far.

**The pace, and what is still missing.** ~600 commits and 341 audited
rungs landed in ten days — the git log is the honest measure of that.
Still absent, deliberately: `AF_INET6` sockets (the NIC drivers carry
an IPv6 link-local + NDP selftest, but the socket family isn't wired —
an nginx `listen [::]` is a real `EAFNOSUPPORT`), SMP (single CPU —
LAPIC timer, no INIT-SIPI AP bring-up), in-kernel filesystem writes
(ext2/ext3/ext4 are read paths; installs write disk from a userspace
mke2, and the installed root rehydrates into a RAM overlay — nothing
writes back yet), mount/user namespaces, cgroups, capabilities,
io_uring, USB, a GPU stack beyond the GOP framebuffer, and swap. Those
are structural rungs, not syscalls — they are where the work goes next.

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
| **Nov 24** | **Two more boot paths and a second ABI.** Legacy BIOS boot via GRUB Multiboot2, then the ia32 compat foundation: ELF32 loader, `int 0x80` syscall ABI, low-4GiB compat address spaces (private PDPT under pml4 slot 0), the physmap supervisor mirror of all RAM, and `set_thread_area` TLS with per-task GDT slots — real i386 BusyBox runs natively. |
| **Nov 25** | **The install lands, then Debian fights back.** The ia32 ABI completes — compat clone/threads, i386 signal frames + sigreturn, compat struct shims, vfork/fcntl64/pipe2/wait4 — a real i386 shell runs external commands and pipelines. The block layer arrives: ATA multi-drive then a real AHCI/SATA driver. ext2: mke2fs parser → `mount()` + partition views → the installer streams real payloads into a fresh ext2 root on an MBR-partitioned disk that boots. Installed-root pivot: the ext2 tree copies into the RAM fs and pid 1 runs from the installed system. Then the proof — `apt update` + `apt install` on the installed system end-to-end (NSS/DNS, mke2 hardlinks), `/bin/sh` becomes real dash (BusyBox `SH_STANDALONE` was shadowing `/usr/bin/dpkg` inside maintainer scripts), an initrd integrity net (crc32 manifest + load-time sidecar verify), `#!` interpreter resolution, update-alternatives — `apt install nano`, then **`apt install -y nginx` exits 0**: a TCP-orphan socket-table sweep (the ENFILE leak), VFILES/VDIRS capacity, the Debian base-passwd set, service stubs + `getent`, `FIONBIO`. And `MAP_SHARED|MAP_ANONYMOUS` becomes real — refcounted shm segments, fork aliases the same frames (phys-verified ownership), private mappings stay private. |
| **Nov 26** | **The driver and IPC shelf.** ext3/ext4 reader + virtio-blk; the virtio fleet — net datapath + IRQ-RX + control queue, input → evdev, console `/dev/hvc0`, balloon, rng, modern (non-transitional) transport; NVMe admin+IO queues with write path, MSI-X, multi-namespace, discard/TRIM + flush; GPT partitions + `/dev` minors (`sda1`, `vda`, `nvme0n1pN`); SG_IO, virtio-scsi, `/dev/loopN`, the CDROM ioctl family. Then sockets wide: `AF_PACKET`, `AF_UNIX` (stream/dgram/socketpair + `SCM_RIGHTS` fd-passing), `SOCK_SEQPACKET`, `recvmmsg`, `AF_NETLINK` route dumps, `/dev/net/tun`. And the modern syscall shelf: `memfd_create` + sealing, `pidfd`, `clone3`, `close_range`, `epoll_pwait2`, `openat2` RESOLVE_* + `process_mrelease`, `futex_waitv`, `mremap`/`madvise`/`mincore`/`mlock`/`process_madvise`/`mseal`/`cachestat`, the xattr family + `memfd_secret`, `select`, `sched_setattr`, `msync`, SysV SHM/MSG/SEM, `process_vm_*`, `copy_file_range`, `splice`/`tee`/`vmsplice`, `fallocate`, `preadv`/`pwritev`, `sigaltstack`, `execveat`, POSIX per-process timers, POSIX message queues, `waitid`, `chroot`, `getdents` + `setrlimit` + `syslog`, `kcmp`, `name_to_handle_at`/`open_by_handle_at`, `acct` + `personality` + `adjtimex`, `unshare`, a real mount table — `mount`/`umount2` + MS_RDONLY enforcement, `statmount`/`listmount`/`quotactl`, and the detached-mount API `open_tree`/`move_mount`/`fspick`/`mount_setattr` — over a hundred suite tasks. |
| **Nov 27** | **The syscall tail closes.** `pivot_root` + the fs-context API + `quotactl_fd`; the keyctl trio (`add_key`/`request_key`/`keyctl`); `sysfs`; a real **seccomp** filter engine; Linux **AIO**; `ioperm`/`iopl` with TSS bitmap plumbing; **`ptrace`** (the last big missing subsystem); **io_uring** with synchronous completion; `vhangup`; `modify_ldt` with real per-task LDTs; **`userfaultfd`**; `perf_event_open` counting mode; real `EPOLLET` + `EPOLLONESHOT`; `msgrcv` **MSG_COPY**; the NUMA pair (`move_pages`/`migrate_pages`); x86_64 `set_thread_area`/`get_thread_area`; **fanotify** (FID-class groups, inode/dir marks, event ring); **`SA_RESTART`** syscall-restart semantics; **`O_TMPFILE`** unnamed inodes; real **`O_PATH`** name-reference fds (`FdKind::Path` — every I/O op EBADF, stat/dirfd/`fchdir`/`AT_EMPTY_PATH` work through them) plus a `newfstatat` `AT_EMPTY_PATH` fix. And the **pty accounting flake family** finally root-caused and closed — a wrong-index `flatten().position()` in the pty retire path's peer-node lookup could silently unlink *any innocent file* (explaining run-346's vanishing file), plus slave/master open-count leaks that stranded pairs; hardened with post-mint counting, virgin-pair rollback, and OFD-keyed minor pinning. Then the deepest bug found yet: the kernel never saved/restored DS/ES across task switches — a compat task's LDT selector leaked its cached segment base into the next compat task (every data access biased by the descriptor base) — found via a new stall watchdog, fixed by per-task ds/es/gs save+revalidate on every switch path. Then **CLOCK_REALTIME absolute-deadline semantics** — `clock_nanosleep`/`timerfd`/`timer_settime`/`FUTEX_WAIT_BITSET` all accepted REALTIME but read the epoch as boot ticks (~54-year sleeps); one shared `abstime_deadline` helper now converts per create-time clockid — and a real ABI bug the new tests caught: `clock_nanosleep` returned *positive* errnos in rax so glibc's negating wrapper read every EINVAL/EFAULT/EINTR back as *success* — flipped to `-errno`. |
| **Every rung** | A scoped security audit plus a cve.now sweep of that subsystem's published kernel CVEs — 494 unique CVEs recorded in [docs/cves-addressed.md](docs/cves-addressed.md) so far. |

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
