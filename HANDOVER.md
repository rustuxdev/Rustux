# Handover — Rustux port project (formerly linux-rust)

**Goal:** rebuild the Linux kernel in Rust as a drop-in replacement — not Rust-in-Linux support. Strategy: port `lib/` and subsystem units one at a time with differential verification (`rust-anything` record → diff → gate), adopt verified ports into `klib`, prove each under QEMU boot, audit, commit. Long tail leads to mm/sched/fs/net/drivers parity.

**Last commit:** `6b5e9f6` sched: preemptive round-robin — UCtx context switch via timer IRQ. Prior: `8541d13` execve, `d55104a` its docs.

**Naming:** the project/repo brand is Rustux; on-disk directory names may still be `linux-rust` (Windows checkout `C:\Users\Davy\Documents\GitHub\linux-rust`, audit artifact dir `security-audit-skill/linux-rust` — rename at leisure; git does not care). The kernel's eventual runtime identity (`uname` etc.) is a separate Linux-compatibility decision, independent of the project name.

## Environments

| host | path | role |
|------|------|------|
| Primary host | `$REPO` (this checkout, dir still named `linux-rust`) | primary repo, port jobs run here |
| Primary host | `$LINUX_REF` | Linux reference tree (torvalds clone or scoped subset); `check-sources.sh` reads `${LINUX_REF:-$HOME/linux-ref}` |
| Linux dev VM | `~/rustux` | git checkout — sync via `git pull` (origin = GitHub `MasterX1582/Rustux`, public); native build+test+boot host |
| Linux dev VM | `~/linux-ref` | scoped ref tree (lib/, include/, arch/x86/include/, Kbuild/Kconfig/Makefile) — the `$LINUX_REF` default |
| Linux dev VM | `~/recv/recv.py` | HTTP PUT receiver on `:9876` — `curl -T file http://<VM_IP>:9876/name` |
| Linux dev VM | `~/rustux/test/zorin/fixtures/` | Zorin 18.1 ISO fixtures: vmlinuz 6.17, initrd (4-layer: AMD ucode → Intel ucode → modules/firmware cpio → gzip'd casper userspace), grub.cfg; dissection docs in `test/zorin/README.md` |

VM toolchain: gcc 13.3, clang 18.1, QEMU 8.2.2+OVMF, mtools, cargo 1.100 (`~/.cargo/bin`), rust-anything 2.0.0, passwordless sudo. Verify on VM: `cargo test -p klib` and `make run` (boot → exit 33 = PASS). NOTE: cargo/rustup need `export PATH=$HOME/.cargo/bin:$PATH`.

## Port pipeline (per unit)

`ports/<pkg>/` holds: upstream C copy + `check-sources.sh` (byte-identical verify vs ref tree), `selftest.c` (userspace harness), `wrappers.c` (FFI scalars), `rust/wrappers-rs/` (port crate, `#![forbid(unsafe_code)]` preferred), `cases.jsonl` (recorded corpus), `verify-all.sh`. Reference exemplars: `ports/lib-siphash/` (newest, clean layout) and `ports/lib-idr-radix/`.

Gate bar: `rust-anything diff` 100% case match + `rust-anything gate` all checks. Then serial adoption: generator/extractor script → `klib/src/<mod>.rs` + `<mod>_tests.inc` → register in `klib/src/lib.rs` → boot proof in `kernel/src/main.rs` → `cargo test -p klib` + `make run` → scoped security-audit run → commit.

## Port status (as of 2159f67)

All four wave-2 parallel ports **landed**: siphash (`0149328`, klib::hash already identical), genradix+interval_tree (`eb55a9b`, 899/899), assoc_array (`6097eab`, 1383/1383), strtox-helpers (`a4d19df`, 11667/11667, merge-adopted). Port packages stay in `ports/` as regression fixtures.

Adopted so far (in klib): math/div64/gcd/int-pow/lcm/primes, bcd, bitops, bitmap, crc, hash(+siphash), rbtree, string, sha1/256/512+hmac, kfifo, llist, seq_buf, fmt, rhashtable, xarray, idr, radix_tree, maple_tree, percpu_counter, prb (printk ringbuf), genradix, interval_tree, assoc_array, kstrtox, string_helpers, font. **327 tests.**

## Kernel runtime status (as of 2159f67)

- Consoles: COM1 serial (`kernel/src/uart.rs`) + GOP framebuffer text console (`kernel/src/fbcon.rs`, `klib::font` = generated `lib/fonts/font_8x16.c` glyphs via `extract_font.py`). `Console` in `main.rs` fans every write to both. Committed `e7486d7`, audit run-21 clean.
- Boot logo (`2159f67`, audit run-25 clean; new Rustux shield + bg-agnostic fill pending run-29): `gen_logo.ps1` learns the background color range from edge pixels then 4-connected flood-fills it to alpha 0 → transparent `docs/logo.png` + 96×143 RGB const `kernel/src/logo_data.rs`; `fbcon::splash()` draws it centered at top and a `top` row bound makes `scroll()` move only the text region (fbcon-style pinned logo). Verified by QEMU monitor `screendump` on the VM.
- `ExitBootServices` claimed (`ea5cfcf`, audit run-22 clean): kernel leaves UEFI boot services, takes the final memory map, prints usable/reclaimable/largest-region summary. Post-exit output still reaches both consoles (COM1 = port I/O, fb = GOP BAR memory; the uefi crate's `MemoryMapOwned` drop is post-EBS-safe).
- Own page tables + buddy allocator (`e8946f8`, audit run-23 clean; buddy upgrade audit run-27 clean): `kernel/src/mm.rs` builds a 4-level identity map 0..max(4 GiB, map top) with 2 MiB pages (multi-PDPT layout — QEMU's ~1 TiB PCI-hole descriptor needs >512 entries), switches CR3, and pools every conventional frame minus the carve into a Linux-style buddy allocator (`free_area[order]` lists, split-on-alloc, merge-on-free via address-buddy, largest-aligned seeding). Boot proof: order-0 + order-2 contiguous alloc/write/free, count conserved.
- kmalloc/slab heap (audit run-28 clean): `kernel/src/kalloc.rs` — size-class caches 32..4096 carved from buddy blocks, direct blocks for larger requests, 16-byte per-allocation header so kfree needs no size hint (the struct-page role), irqsave/irqrestore on every op. Boot proof: freelist reuse, zalloc zero-fill, 12 KiB direct-block round-trip.
- Own GDT + IDT (`f26b2e4`, audit run-24 clean): `kernel/src/cpu.rs` flat 64-bit GDT (KCODE=0x08, KDATA=0x10, CS reload via `lretq`), 256-entry IDT, naked asm stubs → shared dispatcher → Rust reporter; installed AFTER ExitBootServices (firmware reloads GDTR/IDTR and raises timer IRQs internally — installing earlier triple-faults). UEFI target is Windows x64 ABI: stub args go in rcx/rdx, not rdi/rsi. #UD proof catches, advances rip, resumes. Vector 8 (#DF) runs on a dedicated IST1 stack via a TSS in GDT slots 3-4 (`ltr`) — a #DF on a corrupt stack can now report instead of triple-faulting (audit run-27).
- LAPIC periodic timer (audit run-26 clean): `kernel/src/apic.rs` masks the legacy PIC, enables the LAPIC (IA32_APIC_BASE; xAPIC MMIO + x2APIC MSR paths — x2APIC coded but unexercised on QEMU), calibrates the timer against PIT ch2 (~63 MHz counter), arms 100 Hz periodic on vec 0xf0 (spurious 0xff). IRQs route through dedicated IDT stubs; `dispatch` saves/restores every caller-saved reg (incl. the interrupted rcx — stubs are pure push-immediate now; an earlier `mov rcx, rsp` clobbered it and made the tick wait read a garbage bound). Boot proof: `sti` + hlt-wait delivers exactly 50 ticks, #UD resume intact.
- IPv4/ICMP ping (audit run-39 clean, standard — wire parser): `kernel/src/net.rs` — csum16, `parse_ipv4` (version/IHL/total_len bounds, checksum fold, fragments dropped — no reassembly queue by design), `parse_icmp` (checksum), `build_echo_request`. ARP reply seeds GW_MAC/GW_IP atomics (ARP cache entry #1). `ping_selftest` TXes a checksummed echo request and validates the reply end-to-end (EOP/len gate, proto/src/dst/ty/code/id/seq). Boot: `ping reply 10.0.2.2 seq=1 id=0x7278 64B icmp_rest=11B`.
- IPv8 two-guest exchange (audit run-40 clean, standard — wire parser; `f5f0c71`+`b669b15`): `net.rs` gains `parse_ipv8` (draft-thain-ipv8 header — v8, IHL>=7, Src/Dst RouteNumber + local addrs, checksum fold, frag reject) + `build_ipv8_echo` on EtherType 0x8080. `e1000::ipv8_demo` picks role by MAC last byte (:01 initiator broadcasts — ARP8 has no spec — and retries; :02 responder learns sender MAC from the frame and unicasts reply; else skip). PROOF on QEMU socket netdev pair: B `echo req from rn0x1 10.0.0.1 seq=1 -> replied`, A `echo reply rn0x2 10.0.0.2 seq=1 (71B native 0x8080)`. Side effect: exposed+fixed a REAL latent bug — RX repost wrote RDT=d+1 collapsing [RDH,RDT) to empty after 1 frame (ring starvation; invisible to all earlier <=2-frame tests); repost is now RDT=d (consumed slot = new single-desc gap). ARP8/ICMPv8/DHCP8 companion drafts were never submitted — don't invent their semantics. GPL-2.0-only LICENSE added.
- IPv6 link-local + NDP + ICMPv6 echo (audit run-41 clean, standard; `03f3db5`+`c4bfb5f`): `net.rs` gains parse_ipv6 (fixed 40B header, payload_len bounds, NO extension headers — consumers require NH_ICMPV6 directly), ll_addr EUI-64, solicited-node mcast, csum6 pseudo-header (sum-of-complements == complement-of-total; residual 0|0xffff both valid via csum6_ok), build_ns/na/echo6. `e1000::ipv6_selftest` same MAC role gate: initiator must resolve the peer via a real NS->NA exchange (hop==255, solicited dst, target==us) before echoing. PROOF on the socket pair: B `NS for us -> sent NA`, A `NA received`, B `echo req seq=7 -> replied`, A `echo reply seq=7 (79B native 0x86dd)`. Two real bugs found by the proof: build_ns/na returned 82 not 86 (option tail truncated on wire) and csum6 `== 0` would reject negative-zero residuals.
- UDP + IPv4 DHCP (audit run-42 clean, standard): `net.rs` gains parse_udp (ulen-bounded), csum4 pseudo-header (neg-zero via csum6_ok, field==0 legal), build_udp4 (csum field zeroed pre-checksum — CVE-2025-38432 shape). `e1000::build_dhcp`/`parse_dhcp` (len>=241, op==2, XID+cookie match, fully bounded option walk) + `dhcp_selftest`: DISCOVER->OFFER->REQUEST->ACK against slirp, UDP csum verified on RX, retransmit-bounded. PROOF: `dhcp: ACK 10.0.2.15 mask 255.255.255.0 gw 10.0.2.2 lease 86400s` — a real lease, not the hardcoded constant. Socket-demo MACs skip (no DHCP server on the link). NV-42-1: fixed XID + first-OFFER trust is self-test-scoped.
- TCP/IPv4 mini-stack (audit run-43 clean, standard; `11231e1`): `net.rs` gains parse_tcp (data-offset bounded, options region can't escape the segment) + build_tcp4 (zeroed csum field). `e1000::tcp_selftest` two-guest state machine: :01 active-opens :02 port 7 — SYN -> SYN|ACK (MSS option walked bounded, wscale ignored) -> ACK -> 15B PSH data -> echoed -> FIN -> FIN|ACK -> ACK. Every segment gated on TCP checksum + exact seq+ack + peer MAC/IP/ports; RST aborts; bounded per-phase retransmit. PROOF on socket pair: B `SYN dport7 mss=1460 -> SYN|ACK / established / 15B data -> echoed / FIN -> FIN|ACK / closed clean`, A `SYN|ACK -> established / echo verified -> FIN / closed clean`. ISN = rdtsc^const (NV-43-1: production needs hash ISN — klib::siphash already gated).
- demo_net build gate + SipHash ISN (audit run-44 clean; `4f3597f`): the socket-link demos (ipv8/ipv6/tcp selftests) now exist only under `RUSTFLAGS=--cfg demo_net` — `make run`/`make demo` set it, `make build` ships a kernel with zero demo paths (verified by .efi string scan). Closes NV-40-1/41-1/43-2. TCP ISN = `klib::hash::siphash_3u32(4-tuple, rdtsc, boot-key)` — the secure_tcp_seq pattern; closes NV-43-1. Residual NV-44-1: key derives from per-call rdtsc, wants a seeded RNG when one exists.
- CSPRNG (audit run-45 clean, standard): `kernel/src/rand.rs` — RDRAND-seeded ChaCha20 (CPUID-gated, bounded retry, honest weak-seed log on fallback; Makefile adds `qemu64,+rdrand` so QEMU exposes it). Boot line: `rand: CSPRNG seeded (rdrand)`. Consumers: TCP ISN now `siphash(4-tuple, t, per-boot-key)` drawn once at init (NV-44-1 closed); DHCP XID per-run random replacing the compile-time constant, plus ACK cross-checked against OFFER's server-id+yiaddr (NV-42-1 closed to the protocol-inherent race). NV-45-1: no reseed/IRQ-safety until non-boot consumers exist.
- Persistent TCP listener (audit run-46 clean, standard; `e96407b`): listener returns to LISTEN after clean close and issues a fresh SipHash ISN per accepted connection; initiator runs two sequential connections. PROOF: A `conn 1 closed -> reconnect (isn 0xc58e8872)` then `conn 2 closed clean (persistent server verified)` — two independent validated lifecycles on one boot.
- e1000 MSI-X (audit run-37 clean, standard profile — IRQ-on-packet): pci.rs MSI-X helpers (msix_cap/msix_set/msix_enable + write16 dword-RMW; classic MSI code removed — QEMU's e1000e notifies MSI-X only). IVAR 0x8 maps RXQ0 -> table[0] -> vector 0xf3; IMS unmasks RXQ0|OTHER; INTx disabled. Two real bugs found + fixed by diagnostic readback: (1) CF8/CFC moves aligned dwords only — write32 at unaligned offsets silently hits the wrong dword, so sub-dword access now uses read8/16 extraction + write16 RMW; (2) tx_once's IMC=u32::MAX re-masked the causes irq_selftest had just unmasked — masking is now caller-owned. Proof: `1 MSI IRQs on vec 0xf3 (1 rx-caused), reply received` at t=0.500.
- e1000 RX datapath (audit run-36 clean, standard profile — inbound DMA): legacy RX ring (8 descs x 2048B buddy-page buffers, RDBAL/RDLEN/RDH/RDT, RCTL EN|UPE|MPE|BAM promiscuous for the proof, RDT=d repost (gap ratchets with consumption; the d+1 form starved the ring — fixed b669b15)). arp_selftest broadcasts ARP who-has 10.0.2.2 and polls: `rx ARP op2 from 10.0.2.2 mac 52:55:0a:00:02:02 (68B desc0)` — QEMU slirp's reply DMA'd into our buffer. Non-ARP frames are logged + reposted.
- e1000 TX datapath (audit run-35 clean, standard profile — first DMA): reset via CTRL.RST (self-clearing poll), legacy 16-B TX descriptor ring carved from a buddy page (identity map => addr==phys), TDBAL/TDLEN/TDH/TDT programming, one 60-byte broadcast frame -> `tx DONE (TDH 1/TDT 1)` — the NIC DMA'd the packet out of RAM and wrote DD back. probe() now takes is_mmio(base,size): main validates the BAR against UEFI CONVENTIONAL ranges (closes run-33/34 carry). Skeleton notes: ring page intentionally kept; RX ring + real NIC IRQ next.
- e1000e probe (audit run-34 clean): `kernel/src/e1000.rs` — finds 8086:10d3, sets CMD_MEM_SPACE|CMD_BUS_MASTER via pci::command_or, reads MAC from RAL0/RAH0 through BAR0 MMIO (volatile). Boot prints `mac 52:54:00:12:34:56` (QEMU default) + link UP. pci.rs gained write32/find/command_or/bar_raw. Carried needs_validation: check BAR vs UEFI memory map before driver *writes* MMIO.
- PCI enumeration (audit run-33 clean): `kernel/src/pci.rs` — CF8/CFC config reads (inl/outl added to pio.rs), depth-first bus walk following bridge secondary-bus numbers (depth-capped), BAR decode incl. 64-bit BARs, class-name table. QEMU Q35 enumerates correctly: host bridge 8086:29c0, VGA 1234:1111, **e1000e NIC 8086:10d3** (MMIO @0x810a0000 — real driver target), ICH9 LPC 8086:2918. Follow-up before driver MMIO: validate BAR against the UEFI memory map.
- printk ring + panic path (audit run-32 clean): `kernel/src/log.rs` — all log output goes through `klib::prb` (reserve/commit append, `read_valid` FIFO drain); every ring op runs inside `irq_save/irq_restore` (the port is a sequential model of the C cmpxchg ring — kalloc-style serialization makes it IRQ-safe). `[secs.frac]` timestamps stamp records at append time from LAPIC ticks. `kprintln!(con, ...)` replaced all 57 boot `writeln!`s. Panic handler bypasses the ring (fresh UART or stored console, cli+hlt). Boot: `52 records, 0 dropped`, exception-path lines correctly carry no timestamp.
- PS/2 keyboard via IOAPIC (audit run-31 clean): `kernel/src/kbd.rs` — i8042 init (flush OBF, cmd byte: IRQ-enable on + kbd-interface-disable cleared, 0xf4 enable-scanning), IRQ1 -> GSI via ISO-aware `gsi_for_irq`, vec 0xf2. Handler: OBF-checked port read -> lock-free SPSC scancode ring -> EOI; all decode consumer-side (set-1 tables + shift + E0 skip). Boot: bounded ~3s echo window — proven on VM via QEMU `sendkey`: 48 IRQs -> 24 decoded chars echoed live. `kernel/src/pio.rs` shares inb/outb now used by apic + kbd.
- ACPI + I/O APIC device IRQs (audit run-30, standard profile — firmware-data trust boundary): `kernel/src/acpi.rs` grabs RSDP from the UEFI config table pre-EBS, checksum-verifies RSDP/XSDT/MADT, walks MADT records (min-length + end-bounds per record). `apic.rs` gained IOREGSEL/IOWIN MMIO + `ioapic_route` (page-aligned high-MMIO addr + GSI-within-redirs guards; mask->program->unmask; ISO flags -> polarity/trigger bits) + `arm_pit` (ch0 mode-2 ~100 Hz). Boot proof: QEMU MADT shows IRQ0->GSI2, route programmed on vec 0xf1, exactly 50 PIT IRQs delivered via I/O APIC alongside 50 LAPIC timer ticks. x2APIC >8-bit APIC-ids for redir dest noted needs_validation.
- Visible demo on VM: `~/boot-demo.sh` (GTK window + serial; launch with `DISPLAY=:0 XAUTHORITY=/run/user/1000/.mutter-Xwaylandauth.*` if no session env). Headless pass/fail: `make run` (exit 33). VM MCP (LinuxMCP-VM-3) provides shell/PTY/fs/desktop control when sshd is down.

## Conventions that matter

- **Generators are authoritative.** `extract_*.py` at repo root regenerate `klib/src/*.rs` — hardening fixes go in the extractor, never edit generated files directly. `.replace()` calls are assert-guarded (drift can't silently no-op).
- **Adversarial hardening patterns** (apply to new ports): `wrapping_*` where C wraps; arena-index routing to scratch nodes (`nat`/`nmat`, `nidx`/`spare`) for crafted pointers; iteration caps (`MAS_ITER_LIMIT`-style `__lim`) on pointer-chasing/retry loops; clamp table/slot/mark/type indexes; bounds on copy/zero helpers; widen-then-multiply for `batch*ncpu`-style arithmetic.
- **Security mandate (standing rule):** every executable-code change → scoped `security-audit` run (quick profile; standard for crypto/auth/etc.), artifacts to `<AUDIT_DIR>/linux-rust/run-N\` (outside the target repo) (next free N; run-28 closed — runs 18-28 covered the wave-2 adoptions, fbcon, EBS, mm, cpu, boot logo, LAPIC timer, IST + buddy, kmalloc). Fix confirmed findings or record as needs_validation before commit.
- **Commits:** signed `Generated with [Devin]` + co-author trailer. One commit per adoption wave.
- **Delegation model:** port jobs run as parallel background subagents, one `ports/` dir each, no shared-file edits. Adoption/wiring/boot/audit/commit stay serial. Rate limits killed 3 of 4 jobs this round — resume by re-dispatching with the resume-step above; their on-disk progress survives.

## Next steps

1. Kernel runtime: GDT/IDT (`f26b2e4`), LAPIC timer, IST #DF, buddy, kmalloc, ACPI+MADT parse, I/O APIC routing (50 PIT device IRQs) DONE. Next: early-drain printk into `klib::prb`, then real drivers on the IOAPIC path (PS/2 kbd IRQ1, AHCI/e1000), MSI via MADT-independent PCI cfg.
2. Interrupt/timer + early printk drain into `klib::prb`, panic path → both consoles.
3. Queue next lib units per `docs/roadmap.md` (Wave-1 remainder or Wave-2 core services: timer wheels, workqueues, sched math — needs userspace shims).
4. Zorin acceptance ladder (see `test/zorin/README.md`): M0 fixtures done → next rungs are boot our kernel under the real grub cmdline, initrd cpio/gzip readers, eventually casper init (M6 desktop = drop-in milestone).

## Warnings

- Native Windows build of klib has a pre-existing `c_ulong` u32/u64 platform mismatch (`slow_is_prime_number`); verify on WSL/Linux only.
- DrvFs is slow; large tars of the ref tree stall — use scoped tarballs or git bundles (worked well).
- VM apt mirror must be `mirrors.kernel.org` (default `be.archive.ubuntu.com` is blocked by egress allowlist; github/crates.io/kernel.org/debian/qemu.org all reachable).
- A stray untracked `nul` file sits in the repo root (Windows artifact) — ignore/delete.

## 2026-07-16 — Ring-3 userspace milestone (run-47)

- : hostile-input-bounded ELF64/EXEC parser (phdr extent
  checked arithmetic, phnum<=64, entry confined to user VA window).
- : per-process PML4 (kernel slots copied
  supervisor-only), PT_LOAD page-permission mapping (W^X via NX),
  64KiB user stack,  — the deny-by-default user-pointer gate.
- :  (user-rsp stash + dedicated
  8KiB kernel stack, Windows-x64 marshal),  (frame save +
  cr3 switch + iretq),  (sys_exit unwind path).
  Handlers: write(1/2, range-validated, 4KiB cap) + exit.
- : user code/data GDT slots (0x33/0x2b), TSS.rsp0 = INTR_STACK
  for CPL3 interrupts, wrmsr/rdmsr + 
  (STAR=0x20:0x08 sysret/syscall bases, LSTAR, SFMASK=0x700, EFER SCE|NXE).
-  — zeroed-page allocator for tables/user pages.
-  + Makefile: static ELF64 @0x555500000000,
  embedded via include_bytes; write+exit syscalls proved end-to-end.
- Debug lesson of record: x86_64-unknown-uefi = **Windows x64 ABI**
  (args rcx/rdx/r8/r9, NOT SysV) — asm taking args must marshal
  accordingly; caught because user_enter loaded CR3 with arg2
  (Windows rdx) instead of SysV rdx. Verified via QEMU -d int.
- cve.now pre-port check (binfmt/copy_to_user classes); audit run-47:
  0 confirmed, NV-47-1/2/3/4 (SMAP/SMEP, per-task stacks, FS/GS, frame
  reclaim — all gated on the future task model).


## 2026-07-17 — initrd/cpio loader (run-48)
- `kernel/src/cpio.rs`: hostile-input newc (070701/070702) parser, fail-closed.
  Verified-NUL filename terminator (CVE-2024-53142 class), bounded fields,
  checked extents, 256-entry cap, TRAILER!!! stop. 10-case hostile test suite
  (rustc --test, standalone) all pass — incl. a nuance case proving trailing-pad
  truncation is legal while data truncation is rejected.
- `load_initrd()`: reads `initrd.cpio` from the ESP via SimpleFS before
  ExitBootServices into LOADER_DATA pages (never pooled -> survives EBS
  identity-mapped). Cap 1 MiB.
- `tools/mkinitrd.py` packs `kernel/user/hello.elf` as arcname `init`; Makefile
  mcopy's it onto the ESP root. user::run now sources `init` from the archive
  with embedded-ELF fallback. PROOF: `initrd: 5000B`, no fallback line,
  ring-3 hello+exit PASS.
- Audit run-48 (standard, deserialization boundary): 0 confirmed; NV-48-1
  (re-audit if buddy ever pools LOADER_DATA), NV-48-2 (unsigned archive =
  boot-config trust), NV-48-3 (exact-1MiB cap edge).

## 2026-07-17 — syscall-boundary selftest + Linux-ABI register fix (run-49)
- `kernel/user/selftest.S`: second initrd entry exercising the syscall gates
  from CPL3 — EBADF/EFAULT/EINVAL/ENOSYS exact-errno checks plus an r10
  sentinel proving register preservation; exits with failure count.
- Real bug found + fixed: the entry stub preserved only rcx/r11/rdi, but the
  Rust handler runs under the Windows x64 ABI and was free to clobber
  rdx/rsi/r8/r9/r10 — deviating from Linux (syscall may clobber only
  rax/rcx/r11). Stub now saves/restores the full volatile set with explicit
  16-byte call alignment. Selftest `exit(0)` = all 5 checks pass.
- Makefile: `kernel/user/%.elf` pattern rule; initrd now packs `init` +
  `selftest` (10056B). PROOF: both entries run, `selftest run done`, PASS.
- cve.now: CVE-2006-0744 (sysret uncanonical rcx) is harmless by construction
  (rcx is the CPU-saved next-instruction rip) — recorded as NV-49-1 against
  any future rcx-touching syscall. Audit run-49 (standard): 0 confirmed.

## 2026-11-20 — task/process abstraction + frame reclaim (run-50)
- `kernel/src/user.rs`: `Proc` -> owned `Task` (pml4, entry, stacks, ranges).
  `Task::reap()` walks only user PML4 slots 128..255 and frees every leaf and
  table frame plus the per-task kstack — the page table IS the ledger
  (CVE-2022-50661: teardown freeing designed in). Shared kernel slots 0..127
  are never touched. `PHYS_MASK` (0x000f_ffff_ffff_f000) replaces `& !0xfff`
  when extracting frame addresses — the old mask kept the NX bit and
  fabricated non-canonical "addresses" out of read-only PTEs.
- `kernel/src/syscall.rs`: shared `SYS_STACK` replaced by per-task
  kmalloc'd `CUR_KSTACK` set before each entry. **`user_enter`/`user_terminate`
  now also save/restore `rdi`+`rsi`** — see below.
- `kernel/src/cpio.rs`: `entry_at`/`entries()` iterator — the initrd is now
  the process table; main.rs runs every archive entry as a sequential task
  with spawn/done lines and before/after frame accounting.
- `kernel/src/cpu.rs`: `init_syscall` zeroes FS/GS/KGS bases (no firmware
  leftovers into user state); exception reporter now prints cr2.
- `kernel/src/kalloc.rs`: `free_frame` (buddy order-0 wrapper) for reap.
- REAL BUG of the rung — F-50-1, second instance of the Windows-ABI trap:
  rsi/rdi are callee-saved under Windows x64 but argument registers under
  SysV. `user_enter` didn't preserve them; the compiler legally kept `&CUR`
  in rsi across `syscall::enter()`, and the syscall path left the saved
  user rip (0x555500000023) in rsi on return — take()'s memcpy read a user
  VA under the kernel table (#PF) or silently mis-sourced (reap skipped,
  fake 60-frame "leak"). Caught via COM1 markers + cr2 + caller-stack dump.
  Fix: push/pop rdi,rsi. Boot proof x3:
  `tasks: 2 ran, frames 18345 -> 18345 after reap (zero leak)`.
- Audit run-50 (standard, privilege boundary + teardown): 1 confirmed
  (F-50-1, fixed in-diff); NV-50-1..5 carried/reframed; closes NV-47-2/3/4
  and NV-49-2.

## fd table + initrd-as-rootfs (read/open/close) — run-51
- `kernel/src/user.rs`: Task carries a bounded 16-slot fd table —
  `Fd::{Stdin(EOF), Console(serial), File{initrd slice, pos}}`; slots
  0/1/2 pre-seeded. Range table gains a writable bit: PT_LOAD PF_W and
  the stack are writable, so read() targets are gated by range_ok_w —
  the Linux rule that you can't read() into a read-only mapping.
- `kernel/src/syscall.rs`: read(0)/open(2)/close(3) added; write now
  gates on the fd OBJECT (fd_is_console) not the number 1/2 — so a
  file landed in slot 1 still correctly gets EBADF on write (Linux
  O_RDONLY semantics). sys_open does getname-style copy: byte-wise
  under the pointer gate, 256B cap -> ENAMETOOLONG, O_RDONLY only,
  leading '/' tolerated over the flat archive namespace.
- `kernel/src/main.rs`: the cpio archive doubles as the read-only
  rootfs — INITRD static set once (LOADER_DATA lives forever, so
  Fd::File is a borrow, no refcount); non-ELF entries are data files
  and skipped as tasks.
- `kernel/user/fstest.S` + motd.txt prove the path end-to-end from
  CPL3: open /motd.txt -> fd3, read>0 and echoed, read(1) EBADF,
  ENOENT on missing, write-to-file EBADF, close 0 then EBADF —
  exit(0). Third archive entry ran as a task; motd.txt skipped.
- Frame accounting still exact: frames 18360 -> 18360 after reap.
- Audit run-51 (standard): 0 confirmed; RC-51-1..4 rejected with
  reasons (path wrap, TOCTOU, slot reuse, ../ traversal); NV-51-1..3
  (file refcount when heap-backed, SMAP reliance for copy_to_user,
  fd-sharing rules for fork/clone). cve.now: CVE-2025-68814 drove the
  getname/cleanup discipline.

## open-file descriptions (lseek/dup/dup2) — run-52
- `kernel/src/user.rs`: the fd slot is now an index into a per-task
  open-file table — the Linux files_struct/`struct file` split.
  `OpenFile {kind, pos, refs}` holds the seek offset, so dup'd slots
  genuinely share position. FdKind::{Stdin, Console, File} unchanged;
  std streams still pre-seeded 0/1/2.
- `kernel/src/syscall.rs`: lseek(8), dup(32), dup2(33). lseek takes
  a signed off: SEEK_SET/CUR/END via checked_add, EINVAL on a
  negative result, seek-past-EOF is legal (reads then EOF). ESPIPE
  for Stdin/Console like Linux devices. dup picks the lowest free
  slot; dup2 validates old first, releases the target's ref, and is
  a no-op when old==new — all inside a FIXED 16-slot table, which is
  the CVE-2025-39756 lesson applied: a user-chosen fd number can
  never size an allocation here.
- `kernel/user/fstest.S` grew to 19 checks with the real fidelity
  proof: read 'M' via fd3, 'O' via dup'd fd4, 'T' via dup2'd fd9
  after close(fd4) — the OFD survives with remaining refs and the
  offset is genuinely shared. dup(99)->EBADF, dup2(3,9999)->EBADF.
- Debug path worth noting: the first run showed exit(9) and a DBG
  printk trace proved every new syscall was returning correct EBADF —
  the NEW checks were running on fd3 AFTER the close test had closed
  it. Test bug, not kernel bug; reopening motd.txt fixed it. The
  errno discipline the rung enforces is what made the diagnosis
  one serial trace instead of a guessing game.
- Audit run-52 (standard): 0 confirmed; RC-52-1..4 rejected with
  reasons; NV-52-1..3 (OFD share policy for fork — replaces NV-51-3,
  OFD flags for O_APPEND/cloexec, atomic refs under scheduler).
  cve.now: CVE-2025-39756 was the design input for the fixed bound.

## getdents64 + Dir OFD — run-53
- `kernel/src/user.rs`: `FdKind::Dir` — `open("/")` (or ".") yields a
  directory OFD whose pos is the index of the next archive entry
  (Linux's opaque-cookie semantics; ours is just an index). `read`
  on a Dir -> EISDIR; `lseek` allows SEEK_SET 0 only (rewind).
- `fd_getdents`: emits linux_dirent64 records (ino/off/reclen/type/
  name). The whole user buffer is validated writable first, then each
  record's reclen is checked against the remaining space BEFORE any
  byte lands — no partial records ever. Pad bytes between the name
  NUL and reclen end are zeroed — the uninitialized-padding infoleak
  class closed by construction. EINVAL when count can't hold one
  record, count capped at 4096, 0 at EOF.
- `kernel/user/lstest.S`: 11 checks — open("/") gives a Dir, EISDIR
  on read, a full reclen-chain walk counting exactly 5 archive
  entries (init/selftest/fstest/lstest/motd.txt), DT_REG + 'init'
  first-name verification, EOF, rewind-and-reread, ENOTDIR on a
  console fd, EBADF on a bad fd. exit(0) first boot.
- cve.now: getdents/filldir queries returned no entries — the bounds
  and padding disciplines were applied anyway (no match is not
  evidence of absence).
- Audit run-53 (standard): 0 confirmed; RC-53-1..4 rejected;
  NV-53-1..2 (O(n) re-parse per call — fine at initrd scale;
  synthetic ino/off until a real inode table exists).
- 4 tasks, zero-leak streak unbroken: frames 18346 -> 18346.

## execve — image replacement + sysret redirect — run-54
- `kernel/src/syscall.rs`: the user rip now round-trips through a
  `SAVED_UIP` static — stored at entry, reloaded into rcx before
  sysretq. A syscall can therefore REDIRECT where the user resumes,
  which is exactly what exec needs. Canonicality holds because the
  only writers are the stub (CPU-saved rip) and `exec_return`
  (elf::parse-bounded entry) — the CVE-2006-0744 class stays dead.
- `ZERO_CTX`: exec'd images get a fully zeroed GPR file + r11=0x202
  — Linux ABI, and it keeps the caller's registers out of a fresh
  image's hands.
- `sys_execve`: shared getname path-copy, fs_lookup, then
  elf::parse BEFORE the reset — ENOEXEC on a bad image leaves the
  task alive (Linux semantics). Post-reset failure can only be
  allocator exhaustion -> sys_exit(127) kills the task, run() reaps.
- `kernel/src/user.rs`: `free_user_mappings` split out of `reap`
  (also clears the PML4 user slots so the space can be reused);
  `exec()` = free + load_inner + cr3 reload (flush stale user
  translations — without it the TLB could name freed frames) +
  exec_return. fds/OFDs survive exec, the Linux way.
- `kernel/user/exectest.S`: ENOENT returns to the same image (-2),
  ENOEXEC on motd.txt (-8), then execve("/init") — the boot log
  shows `exectest: execing /init` immediately followed by the
  exec'd image's own `hello from ring 3` and its exit(0).
- cve.now: CVE-2022-49264 (argv==NULL) recorded for the future
  stack-args rung — argv/envp are accepted but ignored today.
- Audit run-54 (standard, privilege path): 0 confirmed; RC-54-1..5
  rejected with reasons; NV-54-1..4 (SAVED_UIP canonicality for
  future writers — supersedes NV-49-1's redirect surface, argv/
  envp, cloexec sweep, per-image kernel-state invariant).
- 5 tasks, zero-leak streak unbroken: frames 18359 -> 18359.

## Milestone: preemptive round-robin scheduler (run-55)

The biggest single architectural step since ring-3: tasks no longer
run to completion — the LAPIC timer preempts them.

- `UCtx` (15 GPRs + iret frame) is the unit of scheduling. The
  `sched_dispatch` IRQ path for vector 0xf0 pushes the entire
  register file, `user::tick` snapshots it into the current task's
  ctx and round-robin picks the next Runnable task; `sched_iret`
  (cr3 + rsp=ctx + pops + iretq) is the one resume for launches,
  preemptions, and exits. Fresh tasks get a fabricated ctx
  (`rip=entry`, cs=0x33, ss=0x2b, rflags=0x202).
- `TASKS[16]` + `CUR_I` replace singleton `CUR`; `TaskState` is just
  Runnable|Exited. `pick_next` reaps zombies (never the running
  task — its kstack is underfoot) before scanning round-robin.
- `sys_exit` now switches task-to-task directly (dead kstack
  abandoned, reaped later); the last exit unwinds to the kernel
  frame `sched_launch` saved — same contract as `user_terminate`.
- Preemption discipline: `cs&3==0` frames only tick — syscall
  context is non-preemptible (IF masked by SFMASK end-to-end) and
  kernel context likewise — the CVE-2024-58090 rule by design.
- `log::drain_task()` — main is parked inside `sched_launch` for
  the entire task phase, so user output now flushes from syscall
  context instead of being lost to ring wrap.
- Boot proof: 7 concurrent tasks; log shows tick switches mid-run
  (exectest preempted inside 'execing /init', resumed to print the
  exec'd image), a `tick 6->0` round-robin wrap, ~160 spinA<->spinB
  transitions interleaving 'a'/'b' output; all exit(0);
  frames 18354 -> 18354 (zero leak).
- Audit run-55 (standard): 0 confirmed, 6 rejected candidates,
  NV-55-1..4 (FPU/SSE not in UCtx — required before real binaries;
  per-syscall statics are transaction-local only while syscall ctx
  is non-preemptible; CUR_KSTACK same; UART flood bound).

This closes NV-50-2 (the singleton-statics scheduling blocker) —
the task model now supports fork/clone/wait as the next rung.

## fork + wait4 + getpid (commit pending, audit run-56)

- The syscall entry stub now builds a COMPLETE `UCtx` on the kernel
  stack (15 GPRs + iret frame) and calls `handle_syscall(&mut UCtx)`;
  the return value goes back through `ctx.rax`. This retires
  `SAVED_UIP`/`ZERO_CTX` and the partial-save scheme — every syscall
  that redirects a task now does it by rewriting one struct:
  exec (`*ctx = UCtx::launch`), fork (copy + `rax=0`), wait4 (block,
  `rax=pid` on wake).
- `fork()`: new task slot, fresh page-table tree with a verbatim
  deep copy of the parent's user half (kernel slots shared by
  reference), `fds` copied but pointing at the SAME global OFDs —
  `OFDS[64]` replaces the per-task OFD table so offsets/refs are
  shared exactly like Linux `struct file`. Failure paths free the
  partial tree without touching OFD refs.
- `wait4(pid, status, flags)`: collects a zombie (status =
  `exit_code<<8` via the pre-validated user pointer), ECHILD when no
  matching children exist, otherwise `Blocked` — the exiting child's
  `task_exit` writes the status through `translate()` into the
  parent's (inactive) tables, sets the parent's `ctx.rax = pid`,
  and marks it Runnable. Orphans get ppid=0 and reap immediately.
- `TaskState` gains `Blocked`; `pick_next` reaps only zombies whose
  parent can't collect them; `block_switch` idles on `sti;hlt;cli`
  when nothing is runnable.
- Boot proof: forktest child prints, exits 42; parent collects
  `status=0x2a00`, shared-offset read returns 'T' (child's read
  advanced the joint OFD), second wait4 -> ECHILD, exit(0).
  8 tasks, frames before == after (zero leak).
- Audit run-56 (standard): 0 confirmed, 7 rejected, NV-56-1..6
  (eager copy has no COW; clone flags + WNOHANG + O_CLOEXEC
  unimplemented; hlt-idle instead of wait queues; unbounded pid
  counter; FPU ctx still absent — carried; all-blocked deadlock
  possible without signals).

## pipes (commit pending, audit run-57)

- `FdKind::Pipe{id,write}` + `PIPES[8]`: each pipe is one kernel
  frame as a monotonic head/tail ring. `pipe(22)`/`pipe2(293)`
  mint two OFDs — the ends are dup'able/fork-sharable like files,
  with endpoint counts tracked per-OFD (dup shares, fork bumps).
- **Blocking io generalizes the wait4 mechanism**: `wait_on`
  (WaitOn enum — Child/PipeRead/PipeWrite) + `wait_ptr/len` hold
  the sleeping syscall's user buffer; the WAKER does per-byte
  `translate()` through the sleeper's page tables — data crosses
  between address spaces while only the waker's is mapped — and
  deposits the count in `ctx.rax`. `pipe_wake` settles both
  directions monotonically.
- Endpoint semantics: writer count 0 -> blocked readers wake EOF(0);
  reader count 0 -> blocked writers and new writes get EPIPE(-32);
  <=PIPE_BUF writes are atomic (block until the whole len fits).
- `fd_read`/`fd_write` take the syscall ctx now; `sys_write`
  delegates non-console fds. `ofd_release` owns endpoint teardown
  for all ref drops (close/reap/dup2).
- Boot proof: `pipetest` — pipe2 EINVAL flags; parent BLOCKS on
  read, child writes "hello" through its own address space into the
  parent's (child exit(7) visible first in the log), wait4 0x700,
  EOF after writer close, EPIPE with no readers; exit(0), zero leak.
- Audit run-57 (standard): 0 confirmed, 9 rejected, NV-57-1..5
  (O_NONBLOCK/O_CLOEXEC unimplemented, >4KiB writes, SIGPIPE,
  per-byte translate perf, no readiness API).

## signals (commit pending, audit run-58)

- `rt_sigaction(13)` / `rt_sigreturn(15)` / `kill(62)`. Task grows
  `pending` (bit sig-1, sigs 1..=31) and `handlers[31]` (0=SIG_DFL,
  1=SIG_IGN, else a user handler VA).
- **Delivery at every resume point**: `deliver_current` runs at the
  end of each syscall; `deliver_for` runs inside `pick_ready` and
  the timer `tick`, so a signal pending on a *non-running* task
  lands before it resumes. A default-fatal signal marks the task
  Exited right there; a handler pushes `[signo][interrupted UCtx]`
  (168B) onto the task's own user stack through its own tables
  (inactive spaces included), then redirects rip=handler,
  rsp=frame, rdi=signo. One signal per resume, Linux-style.
- **rt_sigreturn treats the frame as hostile user memory** — the
  whole point of the CVE-2014-9322 / SROP family: it restores the
  pushed UCtx but pins cs=0x33/ss=0x2b, clears TF/NT/IOPL, bounds
  rip and rsp to canonical user ranges (rsp may sit at stack_top,
  so the byte BELOW it must be writable). A bad frame kills the
  task with SIGSEGV.
- **Real wstatus**: `exit_status` holds `code<<8` for exit() and
  the bare signo for signal death — wait4 reports 15 for the
  SIGTERM'd child. `task_exit_inner` pends SIGCHLD on the parent
  (default-ignore, or delivered to a caught handler).
- **EINTR model**: `kill` wakes a Blocked task with rax=-EINTR only
  when the signal's disposition isn't ignored (SIG_IGN or
  default-ignore signals never interrupt a sleep); all three block
  paths (wait4, pipe read, pipe write) also check `pending` BEFORE
  sleeping. The woken ctx delivers the handler at next pick;
  sigreturn resumes the interrupted call's -EINTR return.
- Disposition lifecycle: fork inherits handlers but not pending;
  exec resets caught handlers to default and preserves SIG_IGN.
  SIGKILL/SIGSTOP refuse every disposition change.
- Boot proof: `sigtest` — sigaction install/EINVAL/uncatchable,
  ESRCH; parent blocked on empty pipe -> child's kill -> handler
  writes marker -> sigreturn -> read returns -EINTR; child's
  self-SIGTERM dies silently, wait4 collects status 15;
  exit(0), zero leak.
- Audit run-58 (standard): 0 confirmed after one self-review fix
  (SIGKILL was SIG_IGN-able -> unkillable-by-signal task; now
  EINVAL like Linux), 6 rejected candidates, NV-58-1..5 (no
  credential check on kill — no UID model yet; no
  sigprocmask/siginfo/SA_* flags or SA_RESTART; user faults still
  halt the kernel — a forged sigframe rip at an unmapped/NX page is
  a new trigger of that pre-existing class; sigreturn accepts rsp
  in any writable range like Linux; signals coalesce by mask —
  queued counts absent).

## per-task fault isolation (commit pending, audit run-59)

- A user-mode exception used to hit `report_frame`'s halt path and
  take down the whole kernel — any null deref, ud2, or int3 was a
  trivial machine-kill (and after signals, a forged sigframe rip
  was a new trigger of the same class).
- `report_frame` now checks `cs & 3`: a CPL3 fault calls
  `user::fault_die(signo)` — same teardown as a signal death
  (bare-signo wstatus, SIGCHLD to parent, wait4 collects, kstack
  reaped). The abandoned exception frame lives on the task's own
  kstack and dies with it. Kernel faults still halt.
- Vector -> signal: #DB/#BP->TRAP(5), #UD->ILL(4),
  #DE/#OF/#NM/#MF/#XM->FPE(8), #BR/#AC->BUS(7),
  #TS/#NP/#SS/#GP/#PF/#VE->SEGV(11). Kernel-integrity exceptions
  (#DF, #MC, NMI, #CP, #VC) halt even from CPL3 — task teardown is
  not a trustworthy answer to a double fault.
- **Self-review found a real gap**: only the error-code exceptions
  had stubs — #DE/#DB/#NM/#MF/#XM hit `stub_default`'s unknown
  sentinel and halted anyway. All plausible user vectors are now
  stubbed and gated.
- The #UD-skip and #BP-resume proofs are gated to kernel cs — a
  user int3/ud2 now dies (SIGTRAP/SIGILL) instead of resuming or
  looping.
- CVE-2018-8897 (deferred #DB after MOV/POP SS): the user path can
  no longer reach kernel-halt — #DB->SIGTRAP, `mov ss`->#GP->SIGSEGV.
- Boot proof: `faulttest` — children die to null-write(11),
  ud2(4), div0(8); parent verifies all three statuses, prints,
  exit(0); 11 tasks, zero leak, boot PASS.
- Audit run-59 (standard): 0 confirmed, 6 rejected, NV-59-1..4
  (fault death doesn't deliver a catchable SIGSEGV to a handler
  yet — needs fault-driven signal frames; reserved vectors still
  sentinel-halt, can't fire in practice; si_addr/cr2 not reported
  to userspace — UART line only; kernel faults halt unconditionally).


## per-task FPU/SSE state (commit pending, audit run-60)

- The scheduler's UCtx covered GPRs only: enabling SSE without
  per-task fx state would leak xmm registers across tasks every
  timeslice, and not enabling it made any SSE userspace die #NM.
  Task now carries a 512-byte `FxState`; INIT_FX is captured once
  after `fninit` at boot and copied into every spawn.
- cpu::init sets CR0.MP+EM.clear/TS.clear and CR4.OSFXSR+OSXMMEXCPT
  -- explicit enable rather than inheriting firmware defaults;
  OSXSAVE/AVX left off (no XSAVE, plain FXSAVE only).
- Eager switching everywhere: tick fxsave's the preempted task,
  switch_to fxsave's the outgoing + fxrstor's the incoming,
  launch/resume_ctx fxrstor the target. fork inherits the parent's
  live image; exec resets to INIT_FX (matches exec-zeroes-FPU).
- fputest proves isolation: parent/child hold different 16-byte
  patterns in xmm0 across ~60k verify iterations each under
  10ms preemption -- a missing save/restore would fail immediately.
  parent exit(0), child exit(0), 12 tasks, zero leak.
- cve.now check: CVE-2018-3665 LazyFP n/a by design (eager is the
  mitigation); CVE-2006-1056 AMD FOP/FIP/FDP unrestored-after-
  fxrstor residual -> NV (QEMU/Intel don't exhibit; real AMD would
  need field scrubbing like Linux's eager-FPU hardening).
- Audit run-60 (standard): 0 confirmed, 5 rejected, NV-60-1..3
  (AVX/XSAVE unsupported so a CPUID-advertising guest could #UD on
  xsave -- matches "no AVX" intent; FxState bytes are kernel-static
  so hostile user data can never shape an fxrstor pointer;
  CR4.OSXMMEXCPT enables #XM which fault_die already maps to
  SIGFPE).


## fault-driven signal delivery (commit pending, audit run-61)

- User exceptions used to die unconditionally via fault_die -- a
  task with a SIGSEGV handler never got control, which any serious
  userspace needs (stack-growth handlers, GCs, JITs).
- The generic exception `dispatch` tail now saves ALL 15 GPRs (was
  9 caller-saved) and passes a `SavedRegs*` to report_frame; the
  interrupted rcx/rbp stay in their push slots above the frame.
  report_frame rebuilds the complete interrupted UCtx and hands it
  to `user::fault_signal`.
- fault_signal pends the signo and runs the SAME maybe_deliver
  frame-push/redirect a kill() gets -- [signo][UCtx] on the task's
  own stack, all existing sigreturn hardening applies verbatim --
  then cpu.rs splices (handler rip, frame rsp, signo rdi) into the
  trap frame so iretq lands in the handler. sigreturn restores the
  fault-time ctx and re-faults if unfixed, exactly like Linux.
  DFL/IGN-on-synchronous dies via task_exit_inner (force_sig).
- sigfault.S proves the whole loop: caught handler runs with
  rdi=SIGSEGV, patches saved rip past the faulting movb in its own
  sigframe, sigreturn RESUMES the task; a SIG_DFL-reset fork child
  still dies bare-11. exit(0), zero leak.
- Fixed along the way: MAX_TASKS 16->32 (13 queued + accumulated
  test children intermittently ENOMEM'd sigfault's fork) and a
  hardcoded live[16] in pick_next that panicked at index 16 --
  caught by the expanded table, not by tests.
- Exits now print the pid (`user: pid N exit(c)`) -- anonymous
  exits made this whole debug cycle blind.
- Audit run-61 (standard): 0 confirmed, 6 rejected, NV-61-1..3
  (no si_addr/si_code/siginfo to the handler; a pending lower
  signal delivers ahead of the fault signal, fault stays pending --
  acceptable ordering; nested fault frames bounded only by the
  user stack, as Linux).


## newfstatat (commit pending, audit run-62)

- Syscall 262: fills a 144-byte Linux x86_64 struct stat at a user
  VA. dirfd/flags are ABI-shape only -- the flat cpio namespace has
  no symlinks or per-dirfd views to honor.
- ino = the entry's archive index; mode synthesized
  (S_IFREG|0644, S_IFDIR|0755 for "."); st_size/st_blocks from the
  member header. Path goes through copy_user_path's getname
  discipline like open/execve.
- The stat struct is [0u64; 18] fully zeroed before fields are
  set -- the partially-initialized-kernel-struct copy_to_user
  info-leak class (CVE-2022-50531 family) is closed by
  construction. Write happens only after range_ok_w on all 144
  bytes.
- fstest covers: real file (mode/ino/size), ENOENT, "." -> S_IFDIR,
  EFAULT on an unmapped statbuf. exit(0), zero leak.
- Audit run-62 (quick): 0 confirmed, 3 rejected, NV-62-1
  (dirfd is ignored rather than ENOTDIR'd -- no real fd-relative
  resolution exists yet; timestamps are all-zero, no fs clock).

## poll(2) (commit pending, audit run-63)

- Syscall 7: Linux pollfd {i32 fd, u16 events, u16 revents} = 8B,
  nfds <= 32, timeout_ms (<0 infinite, 0 scan-only, >0 slept on a
  100Hz tick deadline). nfds=0+timeout is a plain interruptible
  sleep like Linux.
- Readiness is honest kernel state: pipe read ends report POLLIN
  on data plus POLLHUP when writers==0 (both may co-report);
  write ends report POLLOUT on space plus POLLERR when readers==0;
  file/dir/stdin reads never block -> POLLIN, console -> POLLOUT;
  unmapped/bad fd -> POLLNVAL. ERR/HUP/NVAL report regardless of
  the events mask, as Linux.
- The sleeper stores the user pfds VA + count in wait_ptr/wait_len
  and a tick deadline in wait_deadline; every pipe-state change
  (data, space, EOF/EPIPE teardown) re-scans all Poll waiters via
  per-byte translate through THEIR page tables -- same cross-space
  mechanism as pipe io wakes -- and a ready count>0 lands in
  ctx.rax. poll_expire in tick() zeroes revents and returns 0 on
  timeout.
- CVE-2023-54019 (poller/waitqueue lifetime UAF) is structurally
  absent: we hold no pointer from poller to polled object -- the
  fd->OFD->pipe chain is re-resolved each scan and the sleeper's
  own fds pin the objects.
- wait4 collects the zombie NOW (was: mark ppid=0, reap at next
  pick): Linux releases the task at wait; the deferral kept a
  dead child counted as a pipe writer, so post-wait4 POLLHUP
  arrived late -- polltest exposed it (exit 24 -> the deferred-
  reap window).
- polltest: empty-pipe poll timeout -> 0, POLLNVAL, poll on a
  plain file -> POLLIN, cross-fork write -> infinite poll wakes
  POLLIN, byte read, wait4, parent close -> POLLHUP, 5ms sleep.
  exit(0), zero leak.
- Audit run-63 (quick): 0 confirmed, 6 rejected, NV-63-1..2
  (reentrant &mut TASKS traversal pattern gains one more instance
  -- pre-existing class, single-CPU safe, unprovable without Miri;
  no select/epoll and nfds cap 32 vs Linux's RLIMIT-sized sets).
- Flake resolved: the run-63 "rare fputest exit(1)" recurred on the
  VM as child exit(9) -- root-caused to resume_ctx (the tick/IRQ
  resume path) never fxrstor'ing the incoming task's fx image.
  switch_to/launch had it; resume_ctx only set CUR_I/cr3/ctx, so a
  timer switch left the previous task's live xmm registers in the
  FPU. Invisible almost always (kernel emits zero xmm instructions,
  so stale live regs usually still hold the resuming task's own
  values); it needs a tick inside fputest's ~0.3ms verify loop AND
  round-robin to the other pattern-bearing task. A deterministic
  eager variant of the CVE-2018-3665 (LazyFP) cross-process FPU
  leak class. Fixed: resume_ctx now fxrstor(&t.fx); five clean WSL
  boots + native VM verify.

## UDP sockets (commit pending, audit run-64)

- Syscalls: socket(41) AF_INET/SOCK_DGRAM, bind(49) sockaddr_in,
  sendto(44), recvfrom(45). Args 4-6 now ride r10/r8/r9 out of the
  saved UCtx (arg4 is r10, never rcx -- the CPU-clobbered ret addr).
- A socket is an OFD kind (FdKind::Udp -> UDPSOCKS[8]): it dups and
  fork-shares like every fd; the endpoint dies with its last fd.
  bind claims a local port (0 -> ephemeral from 49152), re-bind is
  EINVAL, conflicts EADDRINUSE. First sendto auto-binds like Linux.
- The NIC got a live path: net_live() programs a persistent RX ring
  after the selftests (last rx_init wins RDBAL); rx_drain() runs in
  tick() plus once inside recvfrom before it sleeps. drain_desc
  answers ARP who-has for our IP, hands ARP replies to arp_resolve,
  and demuxes verified IPv4/UDP (for_us dst, checksum honored) into
  user::udp_rx -> socket queue or straight into a blocked recvfrom
  through the sleeper's tables -- the pipe-wake trick again.
- sendto resolves the link target: broadcast ff:ff, on-subnet ARPs
  the host (arp_resolve spins the live ring, other traffic keeps
  demuxing), off-subnet or unresolved -> the cached gateway MAC.
  Payload stages through a bounded kernel buffer; len>1400 EMSGSIZE.
- recvfrom sockaddr_out is a fully-zeroed 16-byte sockaddr_in
  (CVE-2021-47597 class closed by construction). Socket lifetime is
  synchronous -- no deferred-cleanup UAF class (CVE-2024-56642).
- Bug found + fixed by this rung: tx_once kmalloc'd a fresh 4KiB TX
  ring per frame and never freed it -- invisible while only selftests
  transmitted (leak inside the boot baseline), exposed the moment
  socket traffic ran inside the measured window: 8 frames = 8 tx
  calls. TX_PAGE is now persistent; zero-leak restored.
- translate split: translate_r drops the WRITE leaf gate for read
  paths (read_task_u/parse_sockaddr) -- reads of a read-only page
  must succeed; write paths keep the WRITE requirement.
- udptest: bind/EADDRINUSE/EAFNOSUPPORT, two real DNS round-trips to
  QEMU slirp's resolver (10.0.2.3:53) -- one via poll(8s)->POLLIN
  ->recvfrom, one via blocked recvfrom woken by the demux; txid echo,
  QR bit, sockaddr family/port all verified. exit(0), zero leak.
- Audit run-64 (quick): 0 confirmed after self-review fixes
  (bind re-bind, translate_r, tx page), 6 rejected, NV-64-1..4
  (one-dgram queue depth, no connect/send/recv aliases or
  getsockname, no O_NONBLOCK, sequential ephemeral ports).

## TCP sockets (commit pending, audit run-65)

- Syscalls: connect(42), accept(43), listen(50), shutdown(48) join
  socket(41)/bind(49); read/write and sendto/recvfrom route streams.
- A TCP endpoint is FdKind::Tcp -> TCPSOCKS[8] (bounded), an OFD kind
  that dups/fork-shares/closes like every fd. States: Init, Listen,
  SynSent, SynRecv, Estab, FinWait, CloseWait, LastAck, Closed.
- listen() turns a bound Init socket passive (backlog capped at 4;
  unbound gets an ephemeral port, separate namespace from UDP).
- connect() ISN = siphash(4-tuple, rdtsc, per-boot isn_key), SYN out,
  then blocks on WaitOn::TcpConn with a ~10s TICKS deadline
  (ETIMEDOUT). Loopback peers (127/8) canonicalize to our IP so the
  4-tuple stays exact on the injected path.
- Loopback is the hermetic test path AND a real OS feature: tcp_tx
  detects dst==our_ip/127.x and pushes the built frame onto LO_Q[4]
  instead of tx_once, then lo_drain() walks the SAME ip_demux as the
  NIC. The drain is iterative (LO_DRAIN guard) precisely so
  tx->demux->rx->tx can't nest and overflow the task kstack.
- accept() pops the completed backlog child into a fresh fd (sa_out
  is a zeroed sockaddr_in -- 47597 discipline); empty backlog blocks
  on WaitOn::TcpAccept and wake_accept mints the fd inside the
  sleeper's table through the cross-space wake machinery.
- RX demux: conn 4-tuple match first, then listener SYN, else RST.
  SynRecv children are bounded per-listener; the final ACK moves
  them to the backlog. RST -> dead + ECONNREFUSED/ECONNRESET wakes;
  ESTab consumes in-order seq only, ACKs, fin_rx -> CloseWait ->
  LastAck -> free. Orphaned (last-fd-gone) conns finish async.
- send copies the user range directly into the segment (no staging
  buffer -- range_ok'd, single-CPU, uninterruptible); recv copies
  out of a bounded 1400B conn ring or blocks on WaitOn::TcpRecv and
  wake_tcp_recv fills the sleeper's buffer through its tables.
- BUG FOUND + FIXED by this rung (the 4-frame leak): the loopback
  chain tcp_send pay[1400] + tcp_tx f[1600] + lo_drain fr[1600] +
  inner tcp_rx->tcp_seg->tcp_tx f[1600] + syscall frames summed to
  ~8.2KiB -- over the 8KiB kstack. The overflow wrote zeros over the
  kmalloc block header below kstack_base, so kfree read kind=0 and
  took the slab-link/corrupt arm, leaking the 4-frame block. Root-
  caused via af/km allocator counters + a corrupt-header probe.
  Fixes: (a) pay now reads the user slice directly, (b) tcp_tx's
  build buffer and lo_drain's pop buffer are non-reentrant statics
  (TX_F/DRAIN_F), (c) KSTACK_SIZE 8KiB -> 16KiB (x86_64 Linux's
  THREAD_SIZE), (d) kfree screams on a corrupt header instead of
  leaking silently (CVE-2022-4378 class: kernel-stack overflow
  corrupting allocator metadata).
- tcptest: socket/bind/listen/connect/accept over loopback, echo
  both directions, dead-port connect -> ECONNREFUSED, accept
  sockaddr_out family+port, teardown. exit(0), zero leak, 4x WSL.
- Audit run-65 (quick): the overflow was the confirmed finding and
  is fixed; NV-65-1 = pre-existing reentrant &mut statics pattern
  extended to TCPSOCKS (NV-63-1 family); known bounded limitations:
  no retransmit/timeout for orphans (slot pin), accept backlog
  tail-insert under EMFILE, no OOB/out-of-order queues (drop).

## Memory-management ABI: brk + anon mmap + munmap + mprotect (audit run-66)
- VMAs ARE the ranges[] table -- every mapped interval has an entry
  (R/W flag bits), so the syscall pointer gate, first-fit allocator,
  and teardown all walk the same truth. MAX_RANGES 8 -> 32 (the
  vm.max_map_count analog); load_inner now FAILS on overflow instead
  of silently dropping an entry (a dropped VMA would have been an
  ungated mapped page).
- brk(addr): page-granular break at the image-end-aligned brk_base,
  256MiB cap, returns current break on any failure (never errno --
  the Linux contract). Grow is collision-checked against other VMAs
  and rollback-unmaps on alloc failure; shrink unmaps + flushes.
- mmap: MAP_PRIVATE|MAP_ANONYMOUS only (fd/shared -> ENODEV until
  file VMAs exist). First-fit in a dedicated 4TiB arena
  (0x6000_0000_0000..0x7000_0000_0000); nonzero addr is a hint --
  collision falls back to first-fit like Linux; MAP_FIXED unmaps the
  overlap AND clips VMA entries then flushes the TLB before user
  code can run (freed frames must not stay cached -- that was the
  real stale-translation aliasing fix this rung caught in review).
- munmap: alignment-only EINVALs; wild VA silently no-ops; len
  rounds UP to whole pages; pages freed + VMAs split atomically --
  clip_entry_count proves the result fits the table BEFORE a single
  PTE is touched, so no half-applied unmap exists.
- mprotect: ENOMEM over unmapped VA, VMA splits (3 pieces max),
  leaf flags rewritten to match the gate flags; PROT_NONE maps as
  present-supervisor leaves -- VMA-reserved, faulting, recoverable.
- mmtest: 37 distinct failure exits covering grow/shrink/cap, both
  gates via pipe read/write, first-fit hole reuse after munmap,
  MAP_FIXED replace, kernel-window EINVAL, 3-page VMA split with
  surviving neighbor data, bad-arg table, 8-page single-call grow,
  and fork heap inheritance. exit(0), zero leak, 4x WSL.
- Audit run-66 (scoped, standard-grade on the diff): 0 confirmed
  after fixes; rejected: 29369/99463 race classes (n/a -- no
  concurrency), MAP_FIXED kernel-slot write, addr+len wraps, gate/
  PTE desync on sub-page unmap; NV-66-1 = NV-63-1 reentrant-statics
  pattern extended to the VM syscalls (functionally safe
  single-CPU, stacked-borrows UB in principle -- the same debt
  already tracked).

## Real-binary ABI: FS base + exec stack + the glibc startup cluster (audit run-67)
- Task.fs_base + arch_prctl(158): SET_FS validates 0-or-user-window
  (kernel-space TLS is impossible), GET_FS writes through a gated
  pointer. fs_base is restored on EVERY resume path -- launch,
  switch_to, and resume_ctx (the tick path, same slot the fx image
  needed in run-64a). Fork inherits it (Linux semantics), exec
  resets it to 0 -- TLS dies with the image. It lives in Task, not
  UCtx, so the 160B signal-frame layout is untouched (Linux doesn't
  save fs in sigframes either).
- exec/spawn build the REAL initial stack: strings top-down, 16B
  AT_RANDOM (ChaCha20), then [argc][argv*][NULL][envp*][NULL][auxv
  pairs: AT_PHDR/PHENT/PHNUM/PAGESZ/BASE/FLAGS/ENTRY/UIDs/HWCAP/
  CLKTCK/SECURE/RANDOM][AT_NULL] -- rsp 16-aligned at entry.
  sys_execve collects argv/envp into bounded kernel buffers (16/8/
  256B caps, E2BIG) while the OLD address space is still mapped;
  argv==NULL gets the binary name as argv0 (the CVE-2022-49264
  discipline -- never argc<1).
- ELF gains ET_DYN (static-PIE): a fixed LOAD_BIAS applied at parse
  (entry + phdr va biased, saturating_add against hostile wrap);
  glibc self-relocates from its own dynamic section, the kernel just
  maps + jumps. LOAD_BIAS reuses the 0x5555... test base.
- VMA truth fix the binary forced: ranges[] stored raw segment
  bounds (p.va..mend) but pages span the page-aligned va0..va1 --
  glibc's RELRO mprotect ENOMEM'd on the sub-page slack and aborted
  ("cannot apply additional memory protection"). VMAs now record
  the actually-mapped page range, matching Linux's page-aligned VMAs.
  First real-binary bug caught -- exactly why this rung exists.
- Syscall cluster: writev/readv (each iovec re-validated inside
  sys_write/fd_read, cnt<=32), exit_group (= exit, no threads),
  uname (zeroed 390B utsname), gettid/getpid + uid/gid family (0),
  set_tid_address, set_robust_list (len==24 check), getrandom
  (ChaCha20, <=4096B), ioctl -> ENOTTY, prlimit64 (RLIM_INFINITY),
  clock_gettime/gettimeofday (apic::TICKS 100Hz), nanosleep +
  clock_nanosleep via WaitOn::Timer + wait_deadline -- EINTR wakes
  fill rem; clock_nanosleep's positive-errno ABI rides wait_ptr2,
  TIMER_ABSTIME supported. Dispatch logs ENOSYS numbers (bring-up
  aid: it surfaced glibc's rseq 334 + readlinkat 267 probes, both
  tolerated).
- realbin.c (gcc -static-pie hello): glibc _start consumed our auxv
  stack, installed TLS via SET_FS, grew the heap via brk+malloc,
  uname'd us, slept 20ms through nr 230, survived the RELRO
  mprotect, and exited 42 via exit_group. 18 tasks, zero leak,
  WSL x3 green.
- Audit run-67 (scoped on the diff): 0 confirmed after the VMA fix;
  rejected: 49264 argc0 (handled), 1070-class unchecked reads
  (bounded collect + extent checks), SET_FS outside user window,
  ET_DYN va wrap (saturating), UCtx/sigframe growth (not needed),
  iovec under-validation (per-buffer gates), uname infoleak (zeroed);
  NV-63-1 reentrant-statics debt extends to the new paths.
## Process-lifecycle ABI: clone fork-subset, sigmask, identity/metadata (audit run-68)
- clone(56): the fork-shaped subset -- exit-signal 0 or SIGCHLD plus
  the child-TID writes glibc asks for (0x1200011 = SIGCHLD |
  CHILD_SETTID | CHILD_CLEARTID). PARENT_SETTID writes the child pid
  to *ptid in our space (range-gated); CHILD_SETTID writes it to
  *ctid in the CHILD's space via its own pml4; CHILD_CLEARTID is a
  futex-registration no-op -- no clear_child_tid state is ever
  stored, so the CVE-2009-2848 execve-forgot-to-clear class is
  structurally absent. stack!=0 or any other flag -> ENOSYS.
  clone3 stays ENOSYS; glibc falls back.
- rt_sigprocmask(14): a real per-task u32 sigmask. SIG_BLOCK/
  UNBLOCK/SETMASK, how validated only when set!=NULL, glibc's 8-byte
  set truncated to our 31 signals. deliverable() = pending & !mask
  gates BOTH delivery and every EINTR wake check, so a masked signal
  stays pending without interrupting sleeps; SIGKILL's bit is
  ignored on delivery (Linux: sig_kernel_only signals can't be
  blocked -- the self-review caught a masked-SIGKILL-survives bug
  here before commit).
- REVIEW-CAUGHT SECURITY FIX: translate()/translate_r() walked ANY
  va through the task's pml4, which shares kernel upper-half slots.
  A user-controlled VA therefore reached kernel memory: clone's ctid
  (4-byte kernel write of a pid), the sigframe rsp (user rsp=kernel
  va -> signal delivery writes [signo][UCtx] into kernel space --
  pre-existing!), and the argv/envp walkers (kernel infoleak into
  user stack). Both walkers now bound va to [USER_VA_LO,USER_VA_HI),
  covering every task-memory path at once.
- Task.name: cpio name stored at spawn, inherited at fork, replaced
  at exec. readlinkat(/proc/self/exe) returns / + name -- the
  absolute path glibc's _dl_get_origin asserts (dl-origin.c:41
  linkval[0]=='/'). The relative name made BOTH C binaries abort
  silently at glibc init via tgkill(SIGABRT) -- the bug this rung's
  real binaries caught.
- Metadata cluster: getcwd (/), stat/lstat/faccessat over the flat
  cpio fs, fstat by OFD kind (chr console, fifo pipe, sock socket),
  clock_getres (100Hz = 10ms), getrlimit aliased onto prlimit64.
  tgkill(234) -> kill (tgid==tid, no threads) -- glibc abort() lands
  there. sched_yield(24): ctx-save + pick_ready handoff.
- parent.c (gcc -static-pie): metadata checks all ok, then
  clone fork -> execve(realbin, argv, envp) -> waitpid: the child
  prints argc=2 argv1=from-parent env=child and exits 42; parent
  verifies WIFEXITED + status==42 -> "0 failures, done" exit(0).
  realbin still exits 42 standalone. MAX_INITRD bumped 1->8MiB (two
  ~830KB static-PIE binaries). 19 tasks, zero leak, WSL x4.
- Audit run-68 (scoped on the diff): 1 confirmed (unbounded task-
  space translate = kernel write/infoleak primitive) -- fixed
  pre-commit; copy_process race family n/a (single CPU); NV-63-1
  reentrant-statics debt extends.

## File-I/O ABI: openat, pread, fcntl FD flags, dup3, accept4, O_CLOEXEC (audit run-69)

- What landed: openat(257) with real dirfd semantics, pread64(17)
  that never moves the shared OFD position, fcntl(72) F_GETFD/
  F_SETFD/F_GETFL/F_SETFL/F_DUPFD/F_DUPFD_CLOEXEC, dup(32)/
  dup2(33)/dup3(292), accept4(288) with SOCK_CLOEXEC on both the
  immediate and blocked-wake paths, and a per-fd O_CLOEXEC bitmask
  (Task.fd_cloexec) that fork inherits and exec sweeps before the
  image swap. socket(41)/pipe2(293) flags mask now rejects
  NONBLOCK honestly (EINVAL) instead of silently ignoring.
- The bug only a compiled binary could catch: glibc passes dirfd
  as a 32-bit int -- mov edi,-100 zero-extends to 0xffffff9c, so a
  u64 compare against sign-extended AT_FDCWD never matched and
  EVERY openat returned EBADF. dirfd is now read as i32, matching
  Linux's 'int dfd' parameter. Hand-written asm tests always
  sign-extended; this is the second ABI-skew class (after
  _dl_get_origin's absolute-path assert) only real code surfaces.
- Honest-error discipline: pread answers EINVAL(neg pos) ->
  EBADF(bad fd) -> ESPIPE(non-file) -> EFAULT(bad buf) in Linux's
  order; openat EINVALs unknown flags, EROFSs write opens (the
  initrd is read-only, that is the truth), ENOTDIRs a non-Dir
  dirfd; dup3 EINVALs oldfd==newfd and non-CLOEXEC flags; fcntl
  F_SETFL accepts only 0 (no toggles exist to fake).
- O_CLOEXEC lifetime: the bit lives on the fd, not the OFD -- dup
  family clears it on the copy (Linux semantics), F_DUPFD_CLOEXEC
  sets it, the exec sweep drops every marked slot via ofd_release
  so a pipe/socket cannot leak into a binary that never opened it.
  MAX_FDS<=16 is a compile-time assert so a future fd-table bump
  cannot silently truncate the u16 mask.
- Proof: kernel/user/iotest.c (static-pie) -- fopen/fgets/fclose
  through glibc's openat, pread offset + no-pos-move, lseek all
  three whences + read-back, fcntl get/set/clear + GETFL, dup3
  cloexec vs plain-dup clearing, openat through a real O_DIRECTORY
  dirfd, and the ENOENT/EROFS/EINVAL honesty table: 0 failures,
  exit(0). 20 tasks, zero leak, WSL x3.
- Audit run-69 (scoped on the diff): 0 confirmed -- the dirfd-int
  and pread-ordering bugs were ABI-correctness, not boundary;
  cloexec-sweep leak class checked against cve.now
  (CVE-2025-68814 family, structurally absent: validation precedes
  minting, sweep has no early return). NV-63-1 reentrant-statics
  debt extends.

## Shell-pipeline proof + exit_files ordering fix (audit run-70)

- kernel/user/shelltest.c (static-pie): pipe() -> fork() -> child
  dup2(w,1) + close + execve(realbin) -> parent drains the pipe to
  EOF and finds realbins argv/env in the stream -> waitpid status 42;
  plus dup2(fd,0) stdin-redirect read-back. 0 failures, exit(0).
- The bug the shape caught: task fds released only in reap(), never
  at exit. A dead pipe-writer OFD kept writers>0 forever and the
  parents blocked reader starved for EOF -- observed live as pid 21
  still blocked at suite end while pipe_end_closed only fired during
  the final reap. Linux runs exit_files(2) inside do_exit; release_fds
  now runs in task_exit_inner (die_signal covered too), idempotent
  via take() so reap stays a no-op.
- Audit run-70 (scoped): 0 new confirmed -- release ordering was a
  liveness bug, not a boundary; cve.now fd-lifetime classes (39966
  async fput, 38722 install race) structurally absent. NV-63-1
  reentrant-statics extends (release under TASKS borrow, same shape
  as reap).
- 21 tasks, zero leak, WSL x2.

## Writable file layer + wiotest proof (audit run-71)

- A scratch namespace now shadows the flat archive: VFile slots
  (16 files, 1MiB each, kmalloc'd buffers) behind FdKind::Ram OFDs.
  fd_open resolves VFILES first then cpio -- mount-shadow order;
  archive writes answer EROFS at open, EBADF on an O_RDONLY fd at
  write (the fmode check, which the suite enforced via fstest).
- OpenFile carries accmode (f_mode analogue) and append; dup/fork
  share it through the OFD like Linux. New syscalls: unlink(87)/
  unlinkat(263), rename(82)/renameat(264)/renameat2(276),
  truncate(76)/ftruncate(77), creat(85), fsync(74)/fdatasync(75).
  getdents enumerates archive+VFILES as one virtual directory;
  newfstatat and access see both namespaces.
- Open-unlink semantics are real: unlink drops the name while an
  open OFD keeps the storage readable; last close frees it. Rename
  over an open target keeps the replaced file alive the same way.
- Self-review catches fixed pre-commit: zero-length write at pos>len
  allocated+extended (now early-0); empty-VFile pread UB (n==0 early
  return); access("") -> ENOENT. Known gaps recorded: renameat
  skips dirfd validation; no rmdir (AT_REMOVEDIR -> EISDIR);
  open("") -> EISDIR vs ENOENT.
- Proof: kernel/user/wiotest.c (static-pie) -- 33 checks: creat,
  write/read-back, EBADF on both wrong accmodes, fsync, fstat,
  O_TRUNC, O_APPEND-at-EOF, O_EXCL->EEXIST, ftruncate shrink +
  grow zero-fill, path truncate, rename + stat-both-sides,
  open-unlink-still-reads, ENOENT after unlink, EROFS table on
  archive unlink/rename, access + getdents listing a fresh file:
  0 failures, exit(0). 22 tasks, zero leak, WSL x3.
- Audit run-71 (scoped on the diff): the three catches above were
  correctness/UB-adjacent, not boundary violations; rename/unlink
  UAF classes (CVE-2022-49349, CVE-2025-21887) structurally absent
  under the OFD-pins-storage invariant. NV-63-1 reentrant-statics
  extends (VFILES under OFDS borrow in vfile_remove).

## Terminal ABI — real ioctl dispatch (audit run-72)

- ioctl(16) finally dispatches instead of blanket-ENOTTY: the
  Stdin|Console pair is our one tty and answers the termios family —
  TCGETS/TCSETS/TCSETSW/TCSETSF on a shared 36-byte kernel-ABI
  termios (cooked defaults: ICRNL|IXON, OPOST|ONLCR, B38400|CS8,
  ISIG|ICANON|ECHO). glibc's isatty() is just "does TCGETS succeed",
  so the kind gate is the entire isatty answer — files ENOTTY.
- TIOCGWINSZ reports the REAL grid: fbcon records cols/rows (GOP
  width/8 x height/16, currently 160x50) into TTY_DIMS at init,
  80x25 fallback when no framebuffer exists. TIOCGPGRP returns the
  task's own pid; TIOCSPGRP/TIOCSWINSZ validate the arg then accept
  (the geometry and the single pgrp can't change).
- FIONREAD is per-kind honest: pipe ring fill, File/Ram bytes
  remaining, TCP rxl, UDP next-datagram size, write-end pipe and
  dir EINVAL, stdin/console 0 (no input queue exists). FIONBIO
  EINVALs — no nonblocking mode exists to fake.
- Proof: kernel/user/termtest.c (static-pie) -- 18 checks: isatty
  0/1 + file ENOTTY, tcgetattr flag values, tcsetattr round-trip,
  winsize nonzero, pgrp==pid, FIONREAD empty/queued/file, EBADF +
  EINVAL refusals: 0 failures, exit(0). 23 tasks, zero leak, WSL x3.
- Audit run-72 (scoped): 0 confirmed -- every arg extent is bounded
  with the exact struct size before copy; TIOCSTI absent by
  omission (no input queue to inject); ldisc CVE family n/a.
  NV-63-1 reentrant-statics extends (TERMIOS cell).

## TTY stdin — IRQ1 to read(0) via a real line discipline (audit run-73)

- The keyboard path now ends at a real input queue, not the
  framebuffer: kbd IRQ -> 64B scancode ring -> kbd::poll decoder ->
  stdin_key line discipline (256B canonical edit buffer -> 4KiB
  ready queue) -> WaitOn::Stdin block/wake. The pump runs in the
  timer tick (live echo + bounded) and lazily at fd_read entry.
- Canonical mode edits the line in-place (VERASE erases + echoes
  backspace-space-backspace under ECHOE, VKILL drops the line) and
  submits on '\n' or VEOF; VEOF on an empty line is Linux's one-shot
  EOF (read returns 0 once, the next read blocks again). ICANON off
  pushes bytes straight to the ready queue. ISIG turns VINTR/VQUIT
  into SIGINT/SIGQUIT for the blocked reader through kill() — which
  already owns the EINTR-wake/ignored-check machinery. ECHO goes
  through printk like every other user-visible byte.
- poll(0) is honest now — POLLIN only when bytes or the EOF flag
  wait (the old arm hardcoded POLLIN because stdin meant EOF).
  FIONREAD reports the ready-queue depth; read(0) on an empty queue
  blocks with the pipe discipline (wait_ptr/len, waker copies
  through the sleeper's pml4, EFAULT on a dead mapping, EINTR on a
  pending signal).
- The boot-time ~3s echo window in main.rs is gone — it consumed
  decoded keys that now belong to the queue.
- Proof: kernel/user/kbdtest.c (static-pie) — isatty, empty-queue
  FIONREAD/poll-not-ready, then a bounded input window: headless
  runs hit the poll deadline and exit 0; a LIVE QEMU run injected
  "hi<ret>" via QMP human-monitor sendkey inside the window and
  read(0) returned the canonical 3-byte line. 0 failures, 24 tasks,
  zero leak, boot PASS x2.
- Fixed mid-rung: a termios tcsetattr roundtrip in kbdtest raced
  termtest on the shared tty cell (correct Linux semantics — the
  test was wrong to mutate it during a concurrent suite); removed.
- Audit run-73 (scoped): 0 confirmed — bounded queues, drop-on-full,
  no allocation in the feed path, IRQ-safe calls only, translate-
  gated wake copies, take/consume split means EFAULT loses no input.
  cve.now: n_tty buffer-swap/ldisc-attach families n/a (no replaceable
  buffers, no attach path, single CPU). NV-63-1 extends.

## Real shell binary + the oversized-read EINVAL divergence (audit run-74)

- rsh (kernel/user/rsh.c, static-pie glibc) is the smallest real
  shell: prompt, byte-wise line read (works on the canonical tty
  AND pipes), whitespace split, exit builtin, otherwise
  fork -> execve("/name") -> waitpid -> "rsh: exit N" report.
  It is packaged as a boot task (a live shell blocked on read(0)
  for a guest keyboard) and as rshtest's exec target.
- rshtest proves the interactive shape headlessly: pipe(in),
  pipe(out), fork, child dup2(in[0],0)+dup2(out[1],1), close all
  four, execve /rsh; parent writes a script (realbin arg1,
  notacommand, exit), reads the whole session back, asserts the
  prompt, realbin output, argv propagation, "rsh: exit 42", and
  "rsh: exit 127".
- The rung caught a kernel-side divergence, not the suspected OFD
  refcount bug: read(fd, buf, 8191) hit `a3 > MAX_COPY -> EINVAL`
  in the NR_READ gate (MAX_COPY=4096). The parent's read loop
  broke on -EINVAL, closed out[0], and the output pipe's reader
  count died honestly — rsh's subsequent writes correctly saw
  EPIPE. Full fd/OFD instrumentation (fork bump, dup2 release +
  install, exit_files release, endpoint counts) showed the
  refcounting was right all along.
- Fix: NR_READ clamps count to a3.min(MAX_COPY) instead of
  EINVALing — Linux's MAX_RW_COUNT semantics (never EINVAL on a
  big buffer; a 128KiB stdio read must not fail). Every fd_read
  arm already min()s len against available data and validates the
  actual copy extent, so the clamp removes a divergence with no
  new boundary surface.
- Verified: rshtest 0 failures (parent's reads stream
  1+18+5+30+226+18+10+9 bytes then EOF), termtest/kbdtest/
  wiotest/shelltest all 0 failures, 26 tasks, frames equal,
  boot PASS x2, native VM verified.
- Scoped audit: 0 confirmed — kernel delta is a one-line count
  clamp; cve.now's pipe-read race hits (ftrace iterator, USB
  iMON disconnect, ksmbd RPC) are unrelated subsystems. Known
  divergences recorded: rsh has no job control/globbing/redirection
  builtins yet, PATH is hardcoded as "/name" for bare commands,
  exit only reports numeric status.

## CLONE_VM — shared address space, real thread memory model (audit run-75)

- clone(flags&CLONE_VM, stack, ...) now builds a task on the SAME
  pml4 instead of a deep copy: MM_REFS (pml4,users) ledger marks
  first share at refs=2, each reap decrements, and only the last
  user frees the user mappings + pml4 frame. The child gets its own
  kernel stack, its own user rsp on the caller-supplied stack,
  rax=0, and fs_base=tls when CLONE_SETTLS.
- exec() on a shared-mm task detaches like exec_mmap: a fresh
  zeroed pml4 replaces the shared one ONLY after the alloc
  succeeds; mm_release then decides — siblings alive -> swap in the
  new pml4, sole survivor -> free mappings and reuse the old one.
  (Self-review caught the alloc-after-release ordering that would
  have corrupted the refcount on ENOMEM.)
- Still per-task: fd tables (OFD refs bumped — Linux would need
  CLONE_FILES to share), the ranges ledger (sibling mmaps land in
  the shared page tables — real sharing for user access — but not
  in other tasks' range_ok view: fails closed, documented),
  sigmask/pending, and distinct pids — a CLONE_VM child is a
  normal wait4 child (no CLONE_THREAD group semantics yet).
- sys_clone flag gate now accepts {SIGCHLD-exit, PARENT_SETTID,
  CHILD_SETTID, CHILD_CLEARTID, CLONE_VM, CLONE_SETTLS};
  CLONE_VM requires a nonzero stack (EINVAL) — running a thread
  on its parent's rsp is unbootable — and plain-fork SETTLS
  writes the child's fs_base post-fork like Linux.
- MAX_INITRD bumped 8->16MiB: the archive crossed 8MiB with
  vmtest.elf inside (read-loop cap returned None — "none found").
- Proof: kernel/user/vmtest.c (static-pie) — glibc clone(CLONE_VM)
  child sees the parent's pre-clone shared_val, writes it + an
  arg pointer through shared memory, exits 7; a
  CLONE_VM|CLONE_SETTLS child reads fs_base back via
  arch_prctl(ARCH_GET_FS) equal to the fake-TCB arg; honesty
  table (FILES/THREAD ENOSYS, no-stack EINVAL). Note: raw
  syscall(SYS_clone,...,newstack) cannot be used from C — the
  wrapper's return address sits on the PARENT stack — the glibc
  clone() wrapper exists precisely to avoid that.
- Verified: vmtest 0 failures + full suite green, 27 tasks,
  frames equal, boot PASS x2, native VM verified.

## Run-76 — futex + CHILD_CLEARTID (pthread_join's mechanism)

- futex(202) WAIT/WAKE: waiter sleeps as WaitOn::Futex(va) on its Task slot, keyed with the mm's pml4 so shared-mm siblings match and foreign processes cannot. Compare-then-block is atomic (syscalls run IF-masked on one CPU). EAGAIN on value mismatch, ETIMEDOUT via the generic deadline scanner, EINTR via the existing kill wake path, EFAULT on unmapped uaddr/timespec, ENOSYS on everything beyond WAIT/WAKE (REQUEUE, CMP_REQUEUE, PI ops, robust lists).
- CHILD_CLEARTID is now real: sys_clone registers ctid on the child (fork-shaped and VM clones); task_exit_inner zeroes *ctid through the dying task's page tables (write_task_bytes → still-referenced mm) then futex_wake(pml4, ctva, 1) — glibc's pthread_join wait verbatim.
- fxtest proves: a CLONE_VM child blocked in futex_wait is woken by the parent's store+FUTEX_WAKE; a ctid-registered child is joined by futex-waiting on its tid word; EAGAIN/ETIMEDOUT/EFAULT/ENOSYS honesty table.
- Divergences recorded: FUTEX_PRIVATE/CLOCK flags collapse into one key space; the key is (pml4, va) rather than physical page (exact while no cross-mm shared pages exist); wake returns the count woken but waiters are not strictly FIFO.

## Run-77 — CLONE_FILES: a real shared files_struct

- FDTABS: 40-entry fd-table ledger {users, cloexec, fds[16]} — the files_struct analogue. Task.fdi indexes it; every former t.fds/t.fd_cloexec site goes through fdt(t). OFD.refs count per TABLE (the table is the owner), users counts tasks — fork duplicates slots and bumps each OFD, CLONE_FILES bumps users only, exit drops users and the last user releases each slot (put_files_struct shape). FDI_NONE sentinel: exit release then reap is a no-op, not a double-decrement.
- sys_clone accepts CLONE_FILES in both modes: FILES|VM threads share mm+table (the pthread shape), FILES alone keeps the copied mm and shares only the table (raw fork-shaped clone — the glibc wrapper's mandatory stack arg stays VM-gated).
- ftest proves: FILES|VM child opens /motd.txt — parent reads the same fd number and sees the child's dup slot; FILES-only child reports its fd over an inherited pipe (copied memory can't share variables) and the fd stays alive in the parent after the child dies — the table outlives either user.
- vmtest's honesty row updated: FILES left the ENOSYS set, SIGHAND/THREAD keep it honest.
- Divergences: exec's cloexec sweep edits the shared table directly (Linux unshares files on de_thread); MAX_FDTABS exhaustion is ENOMEM; no fdtable resize (fixed 16 slots like before).

## Run-78 — CLONE_SIGHAND + CLONE_THREAD: thread groups

- SIGTABS mirrors FDTABS: {users, handlers[31]} sighand_struct analogue, Task.sigh indexes it; sigaction on any sharer is visible to all. release_sighand pairs with release_fds at exit+reap (SIGH_NONE sentinel, idempotent).
- tgid: group id = leader pid; getpid() reports tgid, gettid() pid. CLONE_THREAD child inherits parent tgid and takes the parent's ppid (leader's parent — Linux lineage); non-THREAD clones lead their own group (tgid = own pid, fork unchanged).
- Thread exit: invisible to wait4 and raises no SIGCHLD — join is the ctid futex (run-76). The exit path still releases fds/sighand/ctid/orphans, then marks DEAD_THREADS; reap_dead_threads() in pick_ready frees the slot — the sweep runs from a live context because a task can never free its own running kstack or the pml4 under its own cr3 (last-mm-user case included).
- Gate honesty: SIGHAND without VM -> EINVAL, THREAD without SIGHAND -> EINVAL (Linux's pairing); tgkill(tgid,tid) now targets the tid task.
- thrtest proves: shared disposition readback both directions, getpid==leader tgid / gettid==clone tid, ctid futex join, waitpid(thread)->ECHILD, EINVAL pairings.
- Divergences: exec sighand-reset edits the shared table (Linux unshares on de_thread); leader reap isn't delayed to group exit; no CLONE_FS/SYSVSEM yet.

## run-79 — Debian stub batch (umask/sysinfo/times/getrusage/statfs/getgroups/affinity/prctl/vfork/reboot)

The miscellaneous-ABI rung for the Debian path: ten small syscalls that minimal userspace needs, all real implementations not panics. umask is a per-task field (default 022, masked 0777, inherited through fork and clone_vm — the fs_struct's umask until CLONE_FS shares it). sysinfo reports real uptime and freeram; times/getrusage report honest tick-derived counters; statfs/fstatfs answer RAMFS_MAGIC + 4KiB blocks; getgroups is empty; sched_getaffinity reports CPU0; prctl implements PR_SET_NAME into comm[16]; vfork is plain fork (parent-pause contract is a no-op on the single-CPU model); reboot gates on Linux's magic pair then CAD_ON/OFF no-ops while real RB_* commands drive a 0xCF9 chipset reset.

Self-review caught four honesty bugs before commit: times silently succeeded on bad buf, getrusage zeroed invalid who, statfs left tail fields as caller garbage, reboot accepted any cmd. wiotest's getdents check needed a streaming loop — the dir outgrew its 1KiB buffer when aptest pushed the initrd to 32 records. glibc lesson: times() EFAULT is unobservable through libc because __times re-faults via a deliberate buf probe; raw syscall preserves it. aptest: 17 checks, 0 failures; 31 tasks, zero leak; WSL + native VM.

## run-80 — CLONE_FS + CLONE_SYSVSEM: the full pthread_create flag set now parses

FSTABS is the fs_struct analogue — a users-refcounted ledger carrying umask today (the Task field moved in), shaped to hold cwd/root when the fs grows them. CLONE_FS shares the index so a sibling's umask write lands in the parent's table (clftest proves it through the shared mm); fork duplicates it. CLONE_SYSVSEM is accepted as a true no-op — there is no SysV semundo state to share. The milestone: clone() now accepts glibc pthread_create's entire flag set in one call — VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID — verified end-to-end with a futex join. Also fixed a pre-existing csigh leak on fork's post-literal failure paths. clftest: 17 checks, 0 failures; 32 tasks, zero leak; WSL + native VM.

## run-81 — hierarchical VFS: real directories, per-task cwd, canonical path resolution

The flat-name filesystem becomes a real path layer. canon_path is the single resolution primitive: joins the caller base (task cwd, or a dirfd's stored DirPath) with the raw path, splits on '/', skips empty and '.' components, pops on '..' and CLAMPS at root (the Linux rule — /.. is /). Root is the empty canonical name; every path syscall now canonicalizes at its boundary (openat, stat/newfstatat, access, unlinkat, renameat2 both-args-own-dirfd, truncate, chdir, mkdir/mkdirat, rmdir, getcwd).

Directories are real objects: VDIRS (16 slots) hold explicit mkdir'd dirs; parents of archive/VFile entries are implicit dirs — dir_exists checks vdir match, the /proc pseudo-dirs, then any child under 'p/' across archive, VFILES, and VDIRS. FdKind::Dir became Dir(DirPath) so a directory fd RETAINS which dir it opened — dirfd resolution, fchdir, and per-dir getdents all key off it.

cwd lives in FsTab (run-80's fs_struct) — CLONE_FS siblings share it like Linux; chdir/fchdir write it; getcwd renders '/'+components. mkdir/mkdirat/rmdir are real: EEXIST on existing names, ENOENT on missing parents, ENOTEMPTY when any child (vfile, archive member, or vdir) still lives beneath; open(O_CREAT) requires a real parent dir; O_DIRECTORY|EISDIR/ENOTDIR honesty throughout. getdents64 streams '.', '..', then deduped first-components under the dir with DT_DIR/DT_REG types — a subdir listing shows only its own children.

Two fixes the process caught: dtest found dir_exists/fs_rmdir missed VDIRS children — rmdir could silently drop a NON-EMPTY vdir and orphan its subtree (data-loss class, fixed by covering vdirs in both scans). Audit found chdir/fchdir relied on an implicit 'dir_exists implies <=128' invariant to bound the cwd copy — now explicit ENAMETOOLONG guards. Also bumped MAX_TASKS 32->40 and MAX_OFDS 128->160 (33rd task couldn't spawn) and removed a stale >32 rename gate (name arrays are 128).

Divergences recorded: mkdir mode ignored (no file modes), no permission checks, Dir OFDs hold names not inodes (getdents after the dir is removed relists by name — Linux shows the stale inode listing), cwd cap 128B vs Linux PATH_MAX 4096, no mount/share boundaries so '..' only ever clamps at root.

dtest.c (static-pie, 40+ checks): mkdir/mkdirat, stat S_IFDIR, chdir/getcwd/'..'/relative, openat+fchdir+unlinkat dirfd, per-dir getdents with DT_DIR on dot entries, full EEXIST/ENOENT/ENOTEMPTY/ENOTDIR/EISDIR honesty table — 0 failures, 33 tasks, frames 14455->14455, WSL + native VM.

## run-82 — file-backed mmap: MAP_PRIVATE file mappings (the ld.so primitive)

sys_mmap's ENODEV wall falls for private file mappings: the fd's OFD supplies (ptr,len) — a cpio slice or VFile buffer — and after the pages map, write_task_bytes_force eager-fills them from off..off+len. MAP_PRIVATE is trivially-correct COW: pages are private copies, writes never reach the file (fmaptest proves a write lands in the map while pread still sees the original byte). off must be page-aligned (EINVAL), the fd must be open for reading (O_WRONLY -> EACCES) and regular (dirs/pipes/sockets -> ENODEV).

MAP_SHARED is honest ENODEV — ordered BEFORE the MAP_PRIVATE-required gate so shared-only maps get the real answer (writable shared mappings need writeback; silently private-izing them would be dishonest). The fill needed a new primitive: write_task_bytes honors the PTE writable bit (it's for user-stack/ctid targets), so PROT_READ maps silently skipped the fill — write_task_bytes_force walks present-only via translate_r, which is exactly the kernel folio-fill privilege over fresh private frames.

Divergences recorded: eager fill, no demand paging or page cache; past-EOF bytes read as zeros (Linux SIGBUS on whole pages past EOF — test pins the zeros); MAP_DENYWRITE ignored (no exec-from-mapped-file path); no msync/madvise.

fmaptest.c (static-pie, 18 checks): mmap content == read() content, PROT_WRITE private-copy isolation, off=4096 offset mapping + sub-page tail zero, len>file zero tail, MAP_SHARED->ENODEV, unaligned-off EINVAL, O_WRONLY->EACCES, dir/pipe fd->ENODEV, bad fd->EBADF, MAP_FIXED replace+refill — 0 failures, 34 tasks, frames 14442->14442, WSL + native VM.

## run-83 — real busybox in the initrd: signal-restorer sigframe + /proc/self/exe + the open-flag honest set

The first real third-party userspace binary runs under rustux: a static-PIE busybox (ET_DYN, self-relocating at LOAD_BIAS like every test ELF) baked into initrd.cpio, driven by bbtest.c. It exposed three real ABI gaps synthetic tests never did.

The big one: the sigframe was [signo][UCtx] with rsp=frame — a normal C handler's ret pops signo (17 = SIGCHLD) as its return address -> rip=0x11 crash in every busybox pipeline child. Our .S tests survived because their handlers manually invoked rt_sigreturn; real handlers RET. Fix is the Linux convention: a dedicated SIGTRAMP page (USTACK_VA-PAGE, exec-mapped user-RX, holding mov $15,rax; syscall) and the frame becomes [restorer][signo][UCtx] — ret pops the restorer address, lands in the stub, rt_sigreturn restores ctx at rsp+8. sigtest.S/sigfault.S updated to ret-style handlers (sigfault's UCtx.rip offset 128->136).

/proc/self/exe now resolves at fs_lookup time (not just readlink) — busybox's standalone applet mode re-execs /proc/self/exe for non-NOFORK applets like cat in a pipeline. The exe path is a real Task field (set at exec from the canonical path), separate from comm, so forked/sh-renamed children keep their binary identity.

Open-flag acceptances: O_LARGEFILE (0o100000, glibc busybox adds it unconditionally — LP64 no-op), O_NONBLOCK on dir opens (glibc opendir), O_NOCTTY. getdents64 cap raised to 1MiB (busybox passes big buffers). time(201) added. MAX_INITRD 16->32MiB for the 2.8MB binary; busybox added to the initrd prerequisites (stale-archive bug fixed).

Audit run-83: 0 confirmed — sigreturn privilege pins intact (cs/ss/rflags/rip/rsp), tramp page user-RX kernel-written-once, /proc/self/exe resolves only the caller's exe. vfork remains fork-shaped (documented divergence). bbtest: 0 failures, 36 tasks, zero leak, boot PASS x4.

## run-84 — real vfork: shared-mm child + suspended parent, and the exec-on-shared-mm fix

vfork(58) is no longer fork-shaped: the child is a clone_vm task on the parent's own user rsp (private fd/sighand/fs copies, matching clone(CLONE_VM|CLONE_VFORK|SIGCHLD,0)), and the parent sleeps in WaitOn::Vfork(child pid) — uninterruptible like Linux's vfork_done completion (kill() exempts the variant; pending signals deliver on resume via deliver_for). The wait completes at the child's exec mm-swap (wake_vfork_parent_of inside exec, the exec_mmap point) or its exit (task_exit_inner's parent-wake covers Vfork).

vtest.c caught two real bugs. First, a zombie-collection subtlety: the exit wake marks the zombie "collected" (ppid=0) once a wait4 status is delivered — but a Vfork wake delivers no status, so the child vanished from the parent's own waitpid (ECHILD). collected now only fires for real wait4 wakes.

Second, the bigger one — exec from a shared mm was a never-exercised path with three defects: np got no kernel slots (a cr3 switch would fault instantly), cr3 was never switched to np at all (the syscall path doesn't reload it, so the child returned to user on the torn shared table and exec-fetch-faulted at entry), and load_inner's read_cr3 slot-copy would have imported the shared user page tables by reference — mapping the new image into the still-shared mm. The #GP was real kernel memory corruption; now np gets kernel slots 0..127 and cr3 switches before load_inner (self-copy becomes a no-op). Any CLONE_VM task exec'ing — not just vfork — benefits.

Divergences recorded: clone(CLONE_VFORK) flag form unparsed (glibc uses nr 58); a vfork child's mm mutations don't reach siblings' range ledgers (same CLONE_VM limitation).

vtest: shared-write visible + suspended-ordering + stack integrity + waitpid(7); exec path + waitpid(0); fork-no-suspend contrast. 0 failures, 37 tasks, zero leak, boot PASS; audit run-84: 0 confirmed.
## run-85 — PT_INTERP: dynamic ELF binaries via the real ld.so + glibc

execve can now run dynamically linked binaries — the single biggest ABI gap
toward real Debian userspace. When the image carries PT_INTERP, `Elf::interp()`
extracts a bounded (filesz 2..=4096), absolute, NUL-terminated interpreter path
(first PT_INTERP wins, exactly like binfmt_elf — the CVE-2026-68151 fix shape)
and `interp_load()` performs Linux's load_elf_interp dance: resolve the name in
the initrd, measure the PT_LOAD span under a probe bias (bias-0 would fail the
entry-in-window check), first-fit a gap in the mmap arena via `mmap_find` — the
same VMA allocator user mmap uses, so the interp can never collide with a later
mapping — re-parse at the real bias, and map it. Userspace starts at the
interpreter's entry with AT_BASE = its load base and AT_ENTRY = the main image's
entry. The segment mapper split out of load_inner (`map_loads`) takes
`track_brk` so the interp's span never moves the main binary's break.

`ld.so` and `libc.so.6` are staged into the initrd from the build host at
mkinitrd time (always matching the gcc that built the test — nothing binary
committed), under `lib64/` and `lib/x86_64-linux-gnu/` — the run-81 implicit-dir
machinery resolves them by path. main.rs's auto-spawn now skips '/'-named
archive members so the support libs aren't queued as tasks.

The debugging was the interesting part: ld.so opened libc, read its headers,
fstat'd — and never mapped it, printing "no version information available" then
"undefined symbol: __libc_start_main, version GLIBC_2.34". The cause was
sys_fstat reporting st_ino=0 for every cpio member: glibc dedupes shared
objects by (st_dev,st_ino), so libc aliased ld.so's own already-loaded object.
sys_fstat now reports member-idx+1, the same scheme newfstatat uses. With real
inodes, ld.so's call shape is byte-for-byte the Linux strace one — MAP_PRIVATE|
DENYWRITE span map, MAP_FIXED RX/RO/RW segments, anon BSS extension — and glibc
startup runs clean.

Also fixed: lstest.S had been silently failing since the dir stream gained
'.','..' — the .S exit status isn't checked by anything, so its stale 'init
first record' + fixed-37 assertions rotted. Honestly re-asserted: 4KiB buffer,
>=44-record floor (other tasks can only add), '.' DT_DIR first record.

dyntest.c is a real DYNAMIC glibc binary (gcc -O2, rpath /lib/x86_64-linux-gnu):
gnu_get_libc_version(), fopen/fgets through real libc, fork+execl("/dyntest")
with waitpid status 7 — dyntest: 0 failures, done; the exec'd child also loads
through ld.so. 38 tasks, frames 10337->10337 zero leak, boot PASS.

Audit run-85 (run-58): 0 confirmed — interp bounds absolute+NUL+4KiB, first-
PT_INTERP-only, archive-member resolution only, mmap-arena collision-free by
construction, mid-exec failure tears down at reap. CVE ledger: 88.

## run-86 — real Debian dash: dynamic userspace end-to-end + wait4 pid_t ABI fix

A real `dash` 0.5.12 binary (Debian amd64 .deb via apt download) now
boots inside Rustux: staged as `bin/dash` (support file, not
auto-spawned), it loads through the run-85 PT_INTERP path — real
ld.so, real libc.so.6. `dashtest.elf` drives it through pipes:
vfork+exec `dash -c` scripts covering builtins, expansion,
substitution, pipelines, globs, redirects, and external exec of
`/init`.

Real-binary-caught ABI bug: glibc wait wrappers zero-extend
`mov edi,-1` to 0xffffffff — dispatching wait4s

## run-86 — real Debian dash: dynamic userspace end-to-end + wait4 pid_t ABI fix

A real `dash` 0.5.12 binary (Debian amd64 .deb via apt download) now
boots inside Rustux: staged as `bin/dash` (support file, not
auto-spawned), it loads through the run-85 PT_INTERP path — real
ld.so, real libc.so.6. `dashtest.elf` drives it through pipes:
vfork+exec `dash -c` scripts covering builtins, expansion,
substitution, pipelines, globs, redirects, and external exec of
`/init`.

Real-binary-caught ABI bug: glibc wait wrappers zero-extend
`mov edi,-1` to 0xffffffff — dispatching wait4's pid arg raw made
wait4(-1) search pid 4294967295 -> ECHILD -> dash exited 255 on a
bare external command. syscall.rs now passes `a1 as i32 as i64`
(truncate+sign-extend, matching Linux's pid_t ABI). Verified
boundary: wait4 gates on ppid==caller before any pid filter, so no
pid value can reap across principals.

dashtest: 15 checks, 0 failures — 39 tasks, frames 10335->10335
zero leak, boot PASS. Audit run-59: 0 confirmed (dash binary is a
test fixture; provenance = Debian-signed .deb). CVE ledger: 89.

## run-86b — VM flake triage: task/pipe table exhaustion

Two scheduling-dependent flakes found on the native VM and fixed:
`fork() -> EAGAIN` when all 48 task slots were live (39 suite tasks
+ concurrent children — the first dashtest sh_run hit it and the
harness's stale-buffer fallthrough hid it on later calls), and
`ls /` racing wiotest's `listed.tmp` unlink (legitimate name
TOCTOU -> busybox ls exits 1). Fixes: MAX_TASKS 64, MAX_PIPES 32
(ENFILE reachable at 8 with pipelining tasks + dash substitution
pipes), bbtest/sh_run harnesses report and zero-out on pipe/fork
failure so a kernel-resource error can never read as a pass, and
the ls check targets `/lib64` (fixed contents). 6/6 clean VM runs,
WSL clean, zero leak. Audit run-60: 0 confirmed.

## run-87 — rseq + sendfile; a latent shared-stack test bug

Two ENOSYS probes from real binaries retired: `rseq` (334 — glibc
registers an area at every startup) and `sendfile` (40 — busybox
applet copies). `sys_rseq` keeps per-task registration state
(`rseq_va`, not fork-inherited, cleared at exec), writes the
cpu_id pair once, and answers EBUSY/EINVAL honestly. `sys_sendfile`
copies regular-file/VFile input into a writable pipe ring with
correct pos vs *offset semantics; non-regular input EINVALs like
Linux, a zero-room ring EAGAINs (documented divergence vs block).

Testing surfaced a **pre-existing latent bug** (present since
run-79, not a kernel bug): aptest's `syscall(SYS_vfork)` child
called libc `_exit` — the `call` pushes onto the shared stack,
overwriting the parent's `syscall()`-frame return slot, so the
parent's resume `ret` landed wherever the child's last push left
(the layout moved the landing pad next to `_start`, turning a
silent corruption into a #PF kill). The ABI hazard is real on
Linux too — it's the man page's "no function calls before
exec/_exit" rule. The child now exits via a bare inline-asm
syscall (zero stack use). Also bumped MAX_FDTABS/MAX_SIGTABS/
MAX_FSTABS 48->64 and MAX_OFDS 192->256 — still sized for the
pre-86b 48-task bound, transient fork() ENOMEM under the
64-task suite.

`rtest.S` (raw asm — glibc tasks can't exercise registration):
register, cpu_id fields, EBUSY, all EINVAL paths, unregister,
re-register. `dyntest` verifies EBUSY on re-register (proof
glibc's real startup registration succeeded). `aptest` sendfile
block: whole-file move, byte equality, *offset semantics, EINVAL
honesty. enosys 334/40 gone entirely (nr 9999 is the intentional
probe). 40 tasks, zero leak, boot PASS x4 WSL. Audit run-61:
0 confirmed (Dirty Pipe CVE-2022-0847 reviewed — architecturally
absent: private kernel ring, no page-cache merge surface).
CVE ledger: 89.

## run-88 — real GNU bash; getsockname/getpeername; memory bump

The flagship gets heavier: Ubuntu's real **GNU bash 5.2** runs under
Rustux. It's a strict superset of the dash rung — dynamic PT_INTERP
consumer PLUS a second DT_NEEDED (`libtinfo.so.6`), so ld.so does
its first multi-library resolution through the default search path
(`lib/x86_64-linux-gnu/`, same dir libc already lives in). bashtest
drives 21 checks through `bash -c` pipes: brace expansion, indexed
arrays, [[ ]] pattern tests, functions+local, the rich parameter
expansion set (substr/len/default/replace), case, printf formats,
here-strings, trap EXIT, background jobs + `wait`, and `>>` append
through the VFile layer — all green.

Two kernel-side adds from the run: **getsockname(51) +
getpeername(52)** — bash probes every startup fd for socket-ness,
expecting ENOTSOCK; ENOSYS worked but was dishonest. `sock_name`
implements both: TCP reports peer/local sockaddr_in by state
(ENOTCONN unconnected), UDP reports local port (peer always
ENOTCONN — our datagrams never connect), everything else ENOTSOCK.
*addrlen is in/out with truncate-copy/report-full, and sockaddr_in()
already zero-fills all 16 bytes — the CVE-52937/7558/47597
uninit-copy class stays structurally absent.

Also: **QEMU -m 512M**. The e820 pool was ~40MiB (10.4k frames);
each bash child deep-copies ~5MB of address space on fork, and the
41-task suite transiently ENOMEM'd a parent's fork. The frame pool
is now ~532MB — honest ENOMEM semantics unchanged, the bound just
isn't suite-tight anymore. parent's fork failure now reports errno
(the run-86b honest-harness rule applied to the last silent check).

Audit run-62 scoped to the diff: 0 confirmed. CVE ledger: 91.
41 tasks, zero leak, boot PASS x3 WSL.

## run-89 — process groups, sessions, job control; scheduler idle semantics

The last big stub family becomes real: `Task.pgid`/`sid`/`did_exec`,
`TaskState::Stopped`, `WaitOn::Group`. Real setsid/setpgid (self-or-child,
same-session, no-leader, pre-exec-child, group-exists rules), getpgid/
getsid/getpgrp. `kill` fans out: pid, 0 = own group, -1 = everyone,
-pgid = group, sig 0 = probe. SIGKILL/SIGSTOP force through masks;
SIGCONT wakes stopped tasks + reports WCONTINUED once; stop signals
19-22 stop, once per WUNTRACED. wait4 takes pid<0/-1/0 group selectors
+ WNOHANG/WUNTRACED/WCONTINUED (+__WALL/__WNOTHREAD no-ops). Console gets
a real fg-pgrp: TIOC*PGRP read/write it, ^C/^Z route to the fg group,
bg tty reads SIGTTIN, orphaned groups get EIO.

bash -m works end-to-end: `jobs` lists `[1] Running`, `kill -0 -pgid`
probes groups, kill/wait reap cleanly. pgtest adds 18 checks across
identity/setsid/setpgid/group-signal/stop-cont/group-wait/tcsetpgrp/
TTIN/orphan-EIO.

Audit run-63 scoped to the diff caught 4 real bugs, all fixed:
(1) "no runnable" was treated as end-of-run — the suite would either
reap live Stopped/Blocked tasks or hlt-wedge with no serviced wake
sources; tick now runs poll_expire/rx_drain/stdin_pump on every frame
and idle is honest. Its completion: rsh is *correctly* parked on
WaitOn::Stdin forever — new `run_over()` predicate ends the run only
when survivors are all Exited or Stdin-blocked (CVE-2006-6921 class:
stranded-process DoS, prevented by construction). (2) stop/cont wait
reports duplicated — flags now consumed on wake. (3) setpgid didn't
re-wake group waiters — fixed (Linux ECHILD parity). (4) SIGCHLD was
pended raw, bypassing handler-EINTR — routed through pend_one.

Debugging note for future runs: printk only reaches serial via drain
(syscall/main contexts); an hlt-idle machine never drains — post-hang
ring reads silently pile up. Raw-UART breadcrumbs (single-byte outb
markers) were the working instrument.

42 tasks, frames zero leak, boot PASS x3 WSL. CVE ledger: 95.

## run-90 — interactive bash: UART RX input, /dev/tty, pselect6(270)

Interactive bash now works end-to-end on the serial console.
`make run-bash` boots a solo initrd whose only task is `-bash`
(argv0 dash = login shell) — prompt, readline, command execution,
job control through the real ctty. Verified by driving QEMU's
`-chardev socket` serial with scripted keystrokes: bytes landed in
the 16550 RX FIFO, the tick-side stdin pump fed them through the
ldisc (ICRNL CR->NL), bash's pselect woke, `echo` ran, a fresh
prompt printed.

What landed:
- `uart::get_byte()` polled RX (LSR data-ready) — the serial
  console's input half, drained in stdin_pump (64-byte cap/tick).
- `/dev/tty` in fd_open: sid==CONSOLE_SID opens the console as an
  Stdin-kind OFD (read + ioctls); ENXIO outside that session,
  ENOTDIR under O_DIRECTORY. bash's job-control setup uses it.
- pselect6(270): the missing piece — bash/readline waits on input
  via pselect and was treating ENOSYS as EOF (logout at prompt).
  Real implementation on the poll substrate: three fd_sets scanned
  through the caller's pml4 via poll_revents, timespec deadline,
  atomic sigmask swap ({ptr,len} pair, ss_len==8) restored on every
  wake path (ready/timeout/signal) via psel_restore.
- run_over() counts Poll/Pselect waits as console-input-blocked —
  an interactive shell parked on input no longer wedges the suite.
- iotest: 4 pselect checks (idle pipe, ready pipe, nfds EINVAL).

Suite-run lesson: -bash does NOT belong in the standard initrd —
it legitimately TIOCSPGRP'd the console foreground, failing a test
that asserts fg==own pgrp. Real job control working as designed;
interactive shells get their own image instead.

Audit run-64 scoped to the diff: 0 confirmed. CVE ledger: 95.
42 tasks, zero leak, boot PASS WSL + interactive socket-driven proof.

## run-91 — TOSTOP + SIGTTOU: the tty write-side job-control gate

The write-side mirror of run-89's SIGTTIN read gate — Linux's
tty_check_change(SIGTTOU) under O_TOSTOP. With TOSTOP armed on the
console termios (c_lflag 0x100), a task of the console's session
writing the tty from a non-foreground pgrp gets its whole group
SIGTTOU'd; the write returns EINTR before a byte moves when the stop
is deliverable. SIGTTOU blocked or SIG_IGN writes through; an
orphaned group gets EIO — the same pgrp_orphaned POSIX test the
read gate uses. Gate ordering matches Linux: the access check runs
before len/range validation, so a bad-buffer background write still
stops on the signal. Cleared TOSTOP (the default), a dead
foreground pgrp, a foreign session, or being fg all bypass.

New ttoutest binary + `make run-ttout` solo image: the test MUST
own the machine — every spawned task shares CONSOLE_SID 1, so with
TOSTOP armed any other suite task's console write stops it
permanently (nobody fg's it back; run_over counts Stopped as
revivable -> hang). Linux semantics are correct; the shared suite
is the hostile environment. 18 checks: TOSTOP default-clear +
set/round-trip, fg write passes, bg write SIGTTOU stop, SIG_IGN
write-through, orphaned-group EIO, cleared-TOSTOP ungated.

Audit run-65 scoped to the diff: 0 confirmed (TOCTOU rejected —
single-threaded irq_save critical section; SIGTTOU-storm DoS
bounded; writev per-iovec gating noted as acceptable divergence).
Follow-up noted: Linux also SIGTTOU's a background tcsetpgrp
(TIOCSPGRP) — the ioctl arm is not wired yet. cve.now tty class:
CVE-2014-0196 (n_tty_write LECHO race, KEV) n/a by construction —
synchronous single-threaded console write, no shared ldisc buffer.
42 tasks, frames zero leak, boot PASS x3 WSL. CVE ledger: 98.
## run-92 — SIGTTOU on background TIOCSPGRP: the ioctl-side job-control gate

Completes the job-control gate set: Linux's tiocspgrp runs
tty_check_change(SIGTTOU) unconditionally — a background pgrp may not
move the tty's foreground without a job-control signal landing first.
The run-91 gate's core is factored into shared ttou_gate();
tty_tostop_gate() keeps its TOSTOP precondition and the new
tty_spgrp_gate() runs the check unconditionally. Placement matches
Linux: after the fd-is-console and caller-session checks (ENOTTY),
before range_ok(arg) — the signal check precedes argument validation.

ttoutest gains six checks: background tcsetpgrp -> SIGTTOU stop
(WUNTRACED/WSTOPSIG), SIG_IGN tcsetpgrp succeeds and provably moves
FG_PGID (verified via tcgetpgrp), orphaned-group tcsetpgrp -> EIO.
The gate is exercised with TOSTOP clear, proving it is unconditional
on the ioctl path unlike the write path.

Audit run-66 scoped to the diff: 0 confirmed (no TOCTOU — gate and
FG_PGID store live in the same single-threaded critical section;
gate-before-arg ordering leaks nothing beyond what tcgetpgrp already
reveals). cve.now: CVE-2020-29661 — the canonical TIOCSPGRP CVE,
tty_jobctrl.c locking/UAF with a public exploit — n/a by
construction: no refcounted tty object exists; the console is static
and pgrp/sid/FG_PGID are plain integers moved inside one critical
section, so there is no lifetime to race.
run-ttout: 0 failures; full suite all 21 suite lines green, 42 tasks,
frames zero leak, boot PASS WSL. CVE ledger: 99.
## run-93 — signal waits: pause(34), sigpending(127), sigsuspend(130), ppoll(271)

The sleeping-signal family on top of run-90's mask-swap machinery.
pause blocks on the new signal-only WaitOn::SigWait and always
returns -EINTR; sigsuspend atomically swaps the sigmask for the
wait's duration (saved mask rides psel_mask, restored on every
exit); sigpending copies the pending bitmask; ppoll is poll +
timespec deadline + atomic mask swap sharing the same poll_scan
substrate — its {sigmask,size} pair is two separate args, unlike
pselect6's struct-wrapped one, and glibc passes size=8.

The subtle part is delivery ORDER inside sigsuspend: Linux runs
the handler while the temporary mask is installed, then restores
the mask on the -EINTR return. The shared signal-wake path now
calls maybe_deliver for SigWait waits BEFORE psel_restore —
restoring first would re-mask the just-arrived signal and the
handler would never run (caught by the pgtest check on first run).
The same inline delivery covers a signal that was already pending
at syscall entry. maybe_deliver can exit or stop the task via a
default disposition, so the post-deliver resume is conditional on
the task still being Blocked.

Tests: iotest +5 (ppoll ready pipe, idle timeout with revents
zeroed, mask restored after wait, bad-nsec EINVAL, pselect-byte
drain harness fix); pgtest +7 (handler arm, block, self-kill,
sigpending sees blocked SIGUSR1, sigsuspend EINTR + mask restore,
pause interrupted by child SIGUSR1). Full suite green, 42 tasks,
frames zero leak, boot PASS WSL.

Audit run-67 scoped to the diff: 0 confirmed (SigWait wake can't
resurrect a killed task — resume guarded on state==Blocked; ppoll
mask restore covered on all four exits; the check-then-sleep race
these calls exist to close is one uninterrupted stretch in a
single-threaded kernel — structurally atomic). cve.now: no
sigsuspend/ppoll/sigpending CVEs on record — the class is the
signal-check-then-sleep race itself, which the atomic
swap-check-block section eliminates. CVE ledger: 99.


run-94 — epoll: create(213)/create1(291)/ctl(233)/wait(232)/pwait(281)
---------------------------------------------------------------------

The readiness-multiplexing family real daemons prefer. A new
FdKind::Epoll OFD kind: the interest set lives in a fixed EPOLLS
table (MAX_EPOLLS=8, MAX_EPOLL_FDS=16 — ENFILE/ENOMEM are the
honest answers past the bounds, never a silent drop). Interest
entries key on the caller's fd number for ctl lookup but pin the
OFD index — Linux's epitem -> file mapping — so a closed-then-
reused fd number can't redirect an interest, and dup'd fds share
the set. ofd_release purges interests whose OFD dies (Linux drops
the epitem at file teardown) and frees the instance slot when the
epoll fd's refs reach 0.

poll_revents split: the task-free core is now ofd_revents(oi,
mask) — epoll evaluates OFDs directly; poll resolves fd -> ofd
first. The Epoll poll arm reports POLLIN when any interest is
ready; ctl rejects epoll-kind members with ELOOP so that arm can
never recurse (nested epoll is a documented divergence, as are
EPOLLET/EPOLLONESHOT — accepted but level-triggered).

epoll_wait/pwait block on WaitOn::Epoll(ei): wake_pollers rescans
via epoll_scan (12-byte packed epoll_event records written through
the sleeper's tables), poll_expire returns 0, the signal path gets
the shared -EINTR, and pwait's temporary mask rides psel_mask on
every exit — the same discipline as ppoll. run_over parks Epoll
waiters like Poll/Pselect.

errno fidelity: ctl non-epoll fd -> EINVAL, bad op -> EINVAL,
self-watch -> EINVAL, dir fd -> EPERM, dup ADD -> EEXIST, missing
MOD/DEL -> ENOENT; wait on non-epoll fd -> EINVAL, bad epfd ->
EBADF, maxevents 0 -> EINVAL; read() on an epoll fd -> EINVAL
(stream-less fd, not EBADF); fstat reports S_IFCHR|0600 like
Linux's anon_inodefs.

Tests: iotest +22 (create1, ADD, ready+cookie, idle, timeout,
EEXIST/ENOENT/EINVAL ctl errors, MOD mask semantics both ways,
pwait mask restore, blocked-wait wake via a forking writer, fstat
chrdev, read EINVAL). Full suite green, 42 tasks, frames zero
leak, boot PASS WSL.

Audit run-68 scoped to the diff: 0 confirmed (stale-OFD interests
purged at teardown and never trusted; instance can't be freed
under a waiter — its fd pins the OFD; ELOOP rejection makes the
poll arm's recursion depth structurally 1; fixed-slot tables mean
no user-sized kernel allocation). cve.now: CVE-2025-38349
(eventpoll refcount-under-mutex UAF — n/a, single-threaded, no
refcount-under-lock), CVE-2025-39881 (epitem outliving released
file — n/a, OFD-index pins purged at teardown), CVE-2013-7446
(epoll_ctl UAF — n/a, no heap epitem), CVE-2023-54019 (per-file
waitqueue UAF — n/a, none exist). CVE ledger: 102.


run-95 — anon-inode semaphores: eventfd(284)/eventfd2(290),
timerfd_create(283)/settime(286)/gettime(287)
---------------------------------------------------------------------

The rest of glibc's event-loop toolkit. eventfd is a u64 kernel
semaphore behind a new FdKind::Eventfd: write adds (u64::MAX is
EINVAL, overflow past 2^64-2 blocks or EAGAINs), read drains —
or decrements by 1 under EFD_SEMAPHORE. Both sides block:
WaitOn::EventfdR readers are deposited their value through the
sleeper's tables by eventfd_wake_readers; WaitOn::EventfdW
writers re-check fit at wake like PipeWrite. nonblock lives
per-instance like Linux file-status flags.

timerfd is one armed TICKS deadline plus a periodic interval in
TIMERFDS. timerfd_expire() runs from the timer tick and lazily at
every timerfd syscall: one-shots expire once and disarm,
periodics fold missed cycles into expirations (Linux's overruns)
and re-arm forward. WaitOn::Timerfd readers get the count
deposited by the same translate-write wake. settime reports the
prior {interval, remaining} through `old`, gettime the current
one; ABSTIME reads as absolute ticks — our single clock is the
documented divergence (CLOCK_REALTIME aliases MONOTONIC).

poll/epoll integrate via ofd_revents arms: eventfd is POLLIN on
nonzero count and POLLOUT under the ceiling; timerfd is POLLIN on
pending expirations OR a passed-but-unfolded deadline — computed
read-only so scans never mutate inside a TASKS iteration.
ofd_release frees both instance slots; a blocked waiter's own fd
pins its instance alive (same OFD-refcount argument as epoll).

Tests: iotest +22 (create, empty EAGAIN, write/drain round-trip,
poll ready, MAX/short-write EINVAL, fstat chrdev, semaphore
decrement, epoll-watches-eventfd composition, blocked read wake
via forking writer, timerfd arm/expire/periodic-overruns/disarm/
gettime/non-timerfd EINVAL). Full suite green, 42 tasks, frames
zero leak, boot PASS WSL.

Audit run-69 scoped to the diff: 0 confirmed (instances can't be
freed under a waiter — fd pins the OFD; expire never runs inside
a TASKS iteration — ofd_revents reads deadline state without
folding; the EFD_MAX check can't wrap since v<=EFD_MAX is proven
first; sub-tick requests round UP not early). cve.now: no
eventfd/timerfd CVEs on record — the class folds into run-68's
anon-inode lifetime findings (no refcount-under-lock, no per-
object waitqueues to dangle). CVE ledger: 102.

### run-96 — /proc breadth: generated procfs for real ps

/proc grows from the lone proc/self/exe link into a real (if
small) procfs. Global files: uptime (100Hz ticks -> sec.cent),
meminfo (MemTotal/MemFree/MemAvailable from the new
kalloc::total_frames + free_frames), loadavg (live-task counts +
last pid, honest 0.00 loads — no load accounting yet), version,
stat (cpu line with idle ticks + process counts). Per-task:
proc/<pid> exists for every TASKS slot — Exited zombies included,
matching Linux's pre-reap visibility — with stat (the full
52-field Linux layout), status, comm, cmdline, and the exe link.

The model is seq_file: open() renders the file into one kernel
frame the OFD owns, so a reader sees a consistent open-time
image even if the described task exits mid-read, and poll/read/
pread/lseek/FIONREAD/fstat all ride the regular-file arms.
stat's real fields: pid/comm/state(R,S,T,Z)/ppid/pgrp/session/
tpgid/num_threads(same-tgid count)/starttime (new Task.
start_ticks, set at spawn+clone)/vsize=brk_cur/rss — and rss is
the HONEST number, a bounded walk of the task's user-half page
leaves (the page table is the allocation ledger). signal(31)
and blocked(32) report the real pending/sigmask u64s. exe is not
generated: it resolves to the task's initrd image for open,
stat (target's real size), and readlink — proc/self/exe is now
just the pid=self case of the general proc/<pid>/exe rule, and
fs_lookup generalized to match so exec("proc/<pid>/exe") works.

Enumeration: getdents on "proc" emits the global files, "self",
and every live pid rendered into a stack buffer; getdents on
"proc/<pid>" and "proc/self" emits the five leaf names.
dir_exists knows live pid dirs; is_file knows the leaves;
newfstatat reports Linux's 0444/size-0 proc shape (exe stats its
target). O_CREAT under proc/ is EROFS even though pid dirs read
as directories — nothing synthetic may be created there.

One real bug the suite caught: the snapshot frame was allocated
inside proc_open BEFORE the EROFS/O_DIRECTORY/EMFILE checks — an
O_WRONLY open leaked one frame (108619 -> 108618). Fixed by
parse-check-render ordering plus explicit free_frame on every
post-render early return; frames now 108619 -> 108619 zero leak.

Tests: iotest +26 — self stat parse (pid/comm/R/ppid=0),
comm/cmdline content, readlink+stat exe, uptime/meminfo/version,
0444 fstat, lseek+pread, /proc and /proc/self listings (own pid
present, stat+exe leaves), a forked child's stat under its own
pid, post-reap ENOENT for dir and stat, O_WRONLY EROFS,
O_CREAT-under-proc EROFS. All green; 42 tasks, zero leak.

Audit run-70 scoped to the diff: 0 confirmed. Snapshot model
kills the task-lifetime class (frozen at open; dead-pid dir
ENOENTs while an open snapshot still reads). The pre-fix frame
leak was the only real finding — closed. cve.now: CVE-2026-64371
(procfs do_task_stat vs exec_update_lock race) recorded
n/a-by-construction — single-CPU syscall context means no
stat-vs-exec interleave, and reads sample a frozen image, not a
live task. CVE ledger: 103.

--- run-97 (procfs breadth 2: links, fd view, real accounting) ---

/proc/<pid> grows the full three-level shape real tools expect:
new leaves statm (vsize/RSS in pages), environ (empty — envp is
honest zero), wchan ("0"), io (zeroed counters), plus the link
leaves exe/cwd/root and the fd/ + fdinfo/ directories that
enumerate the target task's live fd table. proc_parse is now
three-level: proc/<pid>/{fd,fdinfo}/<n> resolves against the
FdTab — closed numbers and zombie tasks (fdi=FDI_NONE after
release_fds) are ENOENT, and getdents on fd/fdinfo emits decimal
fd names rendered like the pid enumeration.

fd links are real links: readlink names the OFD — "/dev/console",
"/"+archive/vfile path (File resolved by pointer-compare against
the cpio member list, Ram by VFILES name, Dir by its path),
"pipe:[id]", "socket:[id]", "anon_inode:[eventpoll|eventfd|
timerfd|proc]". open() of an fd link SHARES the open description —
cross-task dup, same OFD refs+1 — with Linux's gates: ENXIO for
sockets, EACCES when the requested accmode exceeds the OFD's,
EEXIST under O_CREAT|O_EXCL, O_DIRECTORY honored. execve through
the link runs archive-backed File OFDs. fdinfo renders
pos/flags/mnt_id (flags = accmode + O_APPEND + O_CLOEXEC, octal
like Linux). stat on an fd link follows to the OFD's own shape —
ofd_stat_shape() factored out of sys_fstat so both paths agree.

cmdline is now the REAL argv: exec() snapshots the NUL-joined
argv into Task.cmdline (256 B cap — an arg that won't fit drops
whole, Linux caps the page too); spawn seeds argv0; fork/clone
inherit. environ stays empty — envp is collected at exec but not
kept; an honest 0-byte file beats a fake one.

Accounting became real: Task.utime/stime bill the preempted frame
in tick() — kernel-CS means inside a syscall (stime), CPL3 means
user (utime). /proc/<pid>/stat fields 14/15 report them; the
/proc/stat cpu lines sum per-task counters (idle is the
remainder), ctxt counts resume_ctx switches, processes counts
task-table insertions, procs_running/procs_blocked count live
states. cpuinfo renders CPUID vendor/family/model/stepping plus
the 48-byte brand string when leaf 0x80000004 exists.
filesystems/mounts describe the actual flat rustux+proc VFS.
/proc/self readlink resolves to the caller's decimal pid.

Tests: iotest +24 — /proc/stat cpu+processes+ctxt, cpuinfo fields,
filesystems/mounts content, statm parse (rss>0), environ empty,
io counters, cmdline argv0, readlink self->pid + cwd/root->'/',
self/fd dir + getdents sees fds 0/2, fd/1->/dev/console link,
fdinfo pos+flags, and the key semantic: open("/proc/self/fd/<r>")
of a pipe read-end shares the OFD and reads the byte. Plus utime
actually ticked (stat field 14 > 0). All green; 42 tasks,
frames 108611 -> 108611 zero leak, exit 33.

Audit run-71 scoped to the diff: 0 confirmed. The share path's
ref bump/rollback verified against EMFILE; parse-then-share runs
in one critical section so no stale-fd interleave exists; EACCES
direction matches Linux (wronly on rdonly refused). cve.now:
CVE-2011-1020 (procfs tree access not restricted after setuid
exec, public exploit) recorded n/a-by-construction — Rustux has
no uids or privilege boundary for the missing check to cross.
CVE ledger: 104.

## run-98: real-tool verification — sysinfo + lstat/proc-link fixes

bbtest now drives the real static busybox through the new procfs:
ps, free, uptime, top, df, cat cpuinfo, and 'ls -l /proc/self/fd'.
ps/top/uptime/df/cpuinfo worked immediately against run-97 procfs
(ps lists every live task with real TIME; df prints the rustux mount
row). Two real kernel bugs surfaced and were fixed:
- sys_sysinfo wrote totalram=0 and left mem_unit uninitialized, so
  busybox free computed totalram*mem_unit on a garbage multiplier.
  Now zeroes the 112-byte struct then fills uptime, totalram
  (total_frames*4096), freeram, procs (live task count), mem_unit=1.
- lstat followed proc links, so 'ls -l fd/' printed target modes and
  no 'name -> target' arrows. newfstatat takes a nofollow flag; lstat
  and AT_SYMLINK_NOFOLLOW (0x100) now report S_IFLNK|0777 with the
  link-target length as st_size for self/exe/cwd/root/fd/<n>. stat
  (follow) is unchanged — still resolves to the target OFD shape.
iotest suite 0 failures; bbtest 0 failures; 42 tasks, frames
108611 -> 108611 (zero leak), exit 33 on WSL and native VM.
Audit run-72 (quick, scoped to the two functions + dispatch): 0
confirmed findings. cve.now: no directly-applicable sysinfo/stat
entries; the copyout-uninit infoleak class (CVE-2022-50531,
CVE-2024-35849, CVE-2023-53798 — unrelated drivers) is the
defensive pattern the new zero-fill already follows. Ledger: 104.

## run-99: synchronous signals — sigtimedwait + signalfd

Completes the signal family: rt_sigtimedwait(128) — which IS
glibc's sigwaitinfo (no separate nr on x86_64; NULL ts = infinite)
— plus signalfd(282)/signalfd4(289). New WaitOn::SigTimed waits on
a set: pend_one collects an in-set arrival (dequeues the bit,
writes the 128B siginfo_t/signalfd_siginfo record through the
sleeper's own tables, rax = signo or 128), lets an out-of-set
deliverable signal take the normal -EINTR+handler path, and leaves
the sleeper down for masked/ignored noise. poll_expire answers
EAGAIN on the timedwait deadline. signalfd is FdKind::Signalfd
over a bounded SIGNALFDS mask table — read dequeues the READER's
pending in-mask signals (single 128B record per read, Linux-valid
minimum), poll/epoll-ready when pending&mask, mask-update on an
existing fd, EINVAL on a non-signalfd fd.
Three ABI traps fixed en route: nr128 is rt_sigtimedwait(4-arg,
glibc sigwaitinfo calls it with ts=NULL), signalfd4 passes
sigsetsize in a3 (flags is a4), and fd is an int — user -1 arrives
as 0xFFFFFFFF not u64::MAX.
pgtest +11 checks: EAGAIN empty window, blocked-pending collect,
mid-wait arrival, nonblock empty read, poll POLLIN, 128B record
with ssi_signo, blocked-read wake via child kill, mask update,
EINVAL on foreign fd. 42 tasks, frames 108610 -> 108610 zero
leak, exit 33 WSL + VM. Audit run-73 (quick, scoped): 0 confirmed;
cve.now has no signalfd/sigtimedwait-class entries. Ledger: 104.

## run-100: inotify — the last anon-inode fd family

inotify_init/init1(253/294) + inotify_add_watch(254) +
inotify_rm_watch(255): FdKind::Inotify over a bounded INOTIFY table,
watches keyed on canonical path. ino_report routes self events
(nameless) vs parent-dir events (named by final component);
ino_report_self_loss queues DELETE_SELF/MOVE_SELF then IN_IGNORED
and frees the wd. Emitters at open/create/write/truncate/unlink/
rename/mkdir/rmdir/writable-close; bounded queue folds overflow
into one IN_Q_OVERFLOW record; poll reports POLLIN, FIONREAD sums
the whole queue, read returns one 16B-aligned record per call,
blocked readers wake via ino_deposit through the sleeper's own
tables; generic pend_one covers the signal -EINTR path.
Wired bugs found en route: the wake-scan in ino_report originally
walked TASKS unconditionally on every emit — a mid-syscall
iter_mut borrow hazard that raced iotest's reaped-pid proc checks
(now gated on an event actually landing); and a pre-existing /proc
race the shifted timing exposed — a wait4-collected zombie kept
its pid dir until the NEXT pick_next (the exiting task can't reap
its own slot mid-pick). proc_dead now mirrors pick_next's
reapability rule: a zombie nobody can still wait4 is invisible to
/proc lookup and enumeration while its slot lingers. Also fixed
in review: events consumed on undersized buffers (pop after the
fit check, EINVAL keeps them like Linux), mask==0 EINVAL after the
existence check (ENOENT wins like Linux), FIONREAD head-only.
iotest +24 checks: lifecycle, EAGAIN/EINVAL surfaces, POLLIN,
IN_OPEN->IN_MODIFY->IN_CLOSE_WRITE sequence, rm_watch IN_IGNORED,
dir-watch create/delete, blocked-read wake. 42 tasks, frames
108608 -> 108608 zero leak, exit 33 WSL + VM. Audit run-74 (quick,
scoped): 0 confirmed; inotify CVE class cross-checked. Ledger: 111.
Known divergences: path-keyed watches (a self-watch on a renamed
file dies with MOVE_SELF+IGNORED rather than following the inode);
one record per read; F_SETFL can't toggle instance nonblock.

run-101 — queued signals: rt_sigqueueinfo(129)/rt_tgsigqueueinfo(297)
plus real siginfo_t provenance end-to-end. Per-pending-bit SigSrc
records (pend_src) carry si_code/si_pid/si_uid + aux (si_value for
SI_QUEUE, si_status for SIGCHLD, si_addr for faults); standard
signals coalesce first-pend-wins exactly like Linux's merge. The
extended sigframe [restorer][signo][UCtx][siginfo_t][saved mask]
hands SA_SIGINFO handlers rsi=&siginfo_t + rdx=&ucontext, and
sigreturn now restores the saved mask. sigaction honors the kernel
32-byte {handler,flags,restorer,mask} layout — sa_mask + SA_NODEFER/
SA_RESETHAND applied at delivery. sigqueue_one enforces the Linux
provenance rule (si_code>=0 or SI_TKILL -> EPERM); negative pid/tgid
collapse to ESRCH. SIGCHLD reports CLD_EXITED/KILLED/DUMPED/STOPPED/
CONTINUED + child pid + si_status; fault delivery passes real
si_code (MAPERR vs ACCERR from #PF err bit0) + si_addr=cr2.
Three bugs found en route, all real: (1) signalfd_read and sig_wait
dequeued pending bits directly and saw no provenance — all record
writers now share sig_record/fill_sig_rec; (2) the sigsuspend mask
fix needed the frame_mask mechanism — a signal delivered inside the
suspend must carry the ORIGINAL mask in its frame because the
handler's sigreturn is the suspend's return point (both the blocked
wake arm and the immediate-deliverable path); (3) the fault-delivery
splice updated rdi but never rsi/rdx — a caught SEGV handler read
siginfo through a stale pointer. Audit also caught a REAL
evasion bug: signalfd masks weren't stripped of SIGKILL/SIGSTOP, so
a parked signalfd_read could swallow a fatal signal — an
unkillable task; stripped at mask write like dequeue_signal's
sig_kernel_only skip. pgtest +18 checks: SI_USER/SI_QUEUE codes,
si_value, EPERM paths, tgsigqueueinfo wrong/right tgid, CLD_EXITED
metadata, signalfd ssi_* fields, SIGSEGV ACCERR+si_addr on a
PROT_NONE page, non-inheritance of queued payloads. 42 tasks,
frames 108588 -> 108588 zero leak, exit 33. Audit run-75 (quick,
scoped): 0 confirmed unresolved (the evasion defect fixed
pre-commit). Ledger: 111.

run-102 — real statfs/fstatfs(137/138): the ramfs reports the
frame allocator's capacity (f_blocks/f_bfree/f_bavail =
total/free frames, 4KiB bsize+frsize, namelen 255) and the
vfile table's inode count (f_files=MAX_VFILES, f_ffree=free
slots); /proc reports its own superblock — PROC_SUPER_MAGIC,
ST_RDONLY|NOSUID|NODEV|NOEXEC flags, zeroed storage fields.
statfs canon'd its path (ENOENT on a miss, /proc* routes to the
proc fill); fstatfs resolves the fd — Proc OFDs and Dir OFDs
naming proc get procfs, everything else ramfs. Also fixed a
latent offset bug: the old fill wrote f_namelen/f_frsize at the
f_flags/f_spare offsets. busybox df now prints real numbers
(rustux 438676 22316 416360 5%). iotest +7 checks: struct field
assertions on both superblocks, ENOENT, fd-kind routing.
42 tasks, frames 108589 -> 108589 zero leak, exit 33.
Audit run-76 (quick, scoped): 0 confirmed. Ledger: 111.

run-103 — real VFS symlinks: a link is a VFile whose bytes are the
raw target text (is_link flag; no NUL). resolve_links() is a Linux
namei-style iterative rewriter — every component prefix naming a
link swaps for canon(link's-dir + target), absolute targets ignore
the dir, 40-hop cap -> ELOOP; `last` controls whether the final
component follows (lstat/readlink/unlink never, everything else
always). syscall(88)/symlinkat(266) mint links where a file could
be created — parent dir real, name free, proc EROFS, empty target
ENOENT. Hooks: fd_open (O_NOFOLLOW -> ELOOP, CREAT|EXCL -> EEXIST,
plain O_CREAT through a dangling link mints the TARGET), newfstatat
(lstat reports S_IFLNK|0777 + st_size=target length, vfile-space
st_ino), fs_unlink/fs_rename/fs_truncate/fs_mkdir/fs_rmdir/
sys_chdir/statfs_path/sys_access/sys_execve/interp_load/
inotify_add_watch, getdents DT_LNK(10). proc_readlink retired —
fs_readlink covers vfile + proc links and splits EINVAL(existing
non-link)/ENOENT properly. Audit caught a REAL overflow: fs_rename
length-checked the UNRESOLVED new name — a resolved name past the
128-byte name slot would panic the copy; now checked post-resolve.
iotest +39 checks: create/readlink/lstat/stat/open/O_NOFOLLOW/
EEXIST/EINVAL, dangling (lstat-visible, stat ENOENT, CREAT mints),
relative targets + link-to-dir 2-hop, chdir-through-link,
symlinkat/readlinkat FDCWD, self+mutual ELOOP, rename-the-link,
truncate-follows, unlink-leaves-target, bad-parent/empty-target
errnos, getdents d_type. 42 tasks, frames 108587 -> 108587 zero
leak, exit 33. Audit run-77 (quick, scoped): 1 confirmed fixed
pre-commit. Ledger: 110.

### run-104: real file metadata (chmod/chown/utimensat family)
VFiles and VDirs now carry real metadata — mode, uid, gid,
atime/mtime/ctime — stamped at create with the task umask
applied (vfile_stamp: mode & 0777 & ~umask, setuid bits pass
through). chmod(90)/fchmod(91)/fchmodat(268), chown(92)/fchown(93)/
lchown(94)/fchownat(260), utime(132)/utimensat(280)/futimesat(261)/
futimens(311) all wired; the previously-ignored open/creat/mkdir
mode args now land (umask(95) was already dispatched but inert).
stat/lstat/newfstatat/fstat return the stored fields — lstat
reports the LINK's own meta, stat resolves to the target's.
Symlink split is honest: chmod/chown/utimensat follow the final
link, lchown/fchownat(NOFOLLOW)/utimensat(NOFOLLOW) act on the
link itself via resolve_links(cpath, !nofollow). uid/gid
(u32)-1 = keep. UTIME_NOW/UTIME_OMIT + nsec>=1e9/usec>=1e6 ->
EINVAL, NULL times = now, AT_EMPTY_PATH on fchownat/utimensat
treats the dirfd as the target fd. Metadata mutations emit
IN_ATTRIB; writes bump mtime+ctime, reads bump atime (always-
update, stronger than relatime), metadata ops bump ctime, rename
bumps ctime. Archive members + proc entries EROFS on mutation;
stat_meta split covers writable-file/vdir/link/proc/archive.
Audit (run-78, quick, scoped): 2 ordering fixes pre-commit —
times-pointer read moved after pathname copy (ENOENT outranks
EFAULT like Linux getname), nsec validation moved after object
lookup (ENOENT outranks EINVAL like Linux inode-lookup-then-
validate). cve.now: CVE-2026-63833 ntfs3 xattr-forged i_uid/
S_ISUID assessed n/a by construction — metadata is stored but
never enforced (no credential model, no setuid-on-exec, no
permission checks on open) so planting root-owned setuid bits
grants nothing; divergence documented alongside run-96's /proc
access note. iotest +28 checks: create modes + umask, chmod/
fchmod/fchmodat stored + dir, chown/fchown/lchown through-link vs
on-link, -1 keeps, utime/utimensat explicit + NOW + OMIT keeps
atime, futimens AT_EMPTY_PATH, futimesat, bad nsec/usec EINVAL,
NOFOLLOW vs follow on link, archive/proc EROFS. 42 tasks, frames
108587 -> 108587 zero leak, exit 33. Ledger: 112.

## run-105 — char devices: real /dev namespace, mknod/mknodat

VFile gains fmt (S_IF* tag) + rdev; device nodes ride the same
machinery as regular files (name/meta/unlink/rename/inotify/
stat/getdents) with a new FdKind::Dev OFD carrying the vfile
index. mknod(133)/mknodat(259): canon + resolve_links(final=
false), EEXIST on existing name incl. links, EROFS under
/proc, fmt whitelist {0,S_IFREG,S_IFCHR,S_IFBLK,S_IFIFO,
S_IFSOCK} — S_IFDIR/S_IFLNK EINVAL like Linux. dev_init() at
boot mints dev/ + null(1:3)/zero(1:5)/full(1:7)/random(1:8)/
urandom(1:9)/tty(5:0)/console(5:1) plus the /dev/{fd,stdin,
stdout,stderr} links to /proc/self/fd — the old one-off
dev/tty path hack is gone. Open() dispatches on rdev: known
minors only (major1: 3/5/7/8/9, major5: 0 with the
t.sid==CONSOLE_SID ctty check, 1 console) else ENXIO, other
majors ENODEV, block/fifo/sock nodes ENODEV/ENXIO — a crafted
mknod can't reach a driver that isn't there. Read arms: null
EOF, zero+full zero-fill, random/urandom xorshift (nonzero-
seeded from rdtsc), tty/console share tty_input_read (job-
control gate and all). Writes: full ENOSPC, rest sink;
major-5 writes route through sys_write's fd_is_console path.
Dev fds integrate poll/FIONREAD/ioctl/fstat-meta/getdents
DT_CHR/proc fd-links/fchmod/fchown/futimens; lseek is
noop_llseek; O_TRUNC skips dev nodes; unlink-while-open
storage dies with last OFD like regular files.
Audit (run-79, quick, scoped): 1 confirmed defect fixed
pre-commit — the open() major whitelist was missing and
fd_read's catch-all routed ANY unhandled rdev to the tty
input queue, so a crafted mknod(1:99) read console input
without the ctty session check; now whitelisted open +
explicit rdev match + EINVAL floor. cve.now: CVE-2026-89560
(landlock mknod-whiteout guard) n/a — no overlayfs/LSM;
no-CAP_MKNOD recorded as the same standing no-credential-
model divergence as run-104. Also fixed: dev_init moved
before the frame baseline (boot objects aren't task leaks)
and the iotest mknod-type probe corrected to S_IFDIR (Linux
does allow S_IFSOCK nodes). iotest +25 checks: stat/fstat
S_IFCHR+rdev, open/read/write on null/zero/full/urandom,
/dev/tty open, poll readiness, lseek, mknod+mknodat types +
EEXIST + EINVAL + a working mknod'd node, getdents DT_CHR.
21/21 suites 0 failures, 42 tasks, frames 108572 -> 108572
zero leak, exit 33. Ledger: 111.

