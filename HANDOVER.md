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

run-106 — Windows-personality groundwork: a real PE32+ .exe
now spawns under a second syscall personality. Task gains
pers (PERS_LINUX/PERS_NT), gs_base, an 8-slot NT handle
table (nth), and nt_alloc (NT VA bump arena). load()/exec()
detect MZ and branch to pe_load_inner: headers page at
PE_LOAD_BIAS (= elf::USER_VA_LO), sections mapped per
IMAGE_SCN flags (W->WRITE, !X->NX), USTACK stack, then
teb_peb_init mints TEB (gs:[0x30]=Self, gs:[0x60]=PEB) and
PEB (ImageBaseAddress, ProcessParameters block with std
handles + a real UNICODE_STRING command line). gs_base is
restored on every context switch beside fs_base — Windows
reads TEB via GS, Linux keeps FS for TLS. syscall.rs routes
on pers before the Linux table unpacks rdi-args: NT calls
carry r10=arg1, rdx/r8/r9, stack args at rsp+0x28, and get
NTSTATUS back — the REAL ntdll stub convention (ntdll does
mov r10,rcx so syscall entry sees arg1 in r10). nt.rs is a
Win10-x64-numbered service table: NtReadFile(6)/NtWriteFile
(8)/NtClose(15)/NtAllocateVirtualMemory(24)/NtTerminate
Process(44)/NtDelayExecution(52); everything else answers
STATUS_NOT_IMPLEMENTED. Std handles 1/2/3 are PEB-published
and share the Linux ldisc/console paths — no parallel I/O
stack. exec-of-.exe swaps personalities mid-task (mm_release
prologue shared, PE branch after did_exec). tools/mkpe.py
wraps a flat blob into a minimal PE32+ (MZ, PE sig, COFF,
PE32+ opt header, one RWX .text); petest.S assembles to
that blob. Audit (run-80, quick, scoped): 2 fixes —
NtAllocateVirtualMemory's out-pointers were probe-checked
read-only (range_ok) but written through — now range_ok_w;
the PE loader's kernel fill used write_task_bytes which only
translates writable pages — now _force for headers+sections
(else read-only .text rejects the copy). nth table zeroed
per image so exec can't leak handles. cve.now: no PE-loader
class CVEs apply (single hit CVE-2025-22060 is a NIC TCAM
race, n/a). Divergences noted: imports/relocs rejected at
parse (import-less images only), image loads at PE_LOAD_BIAS
not ImageBase (reloc-aware rebasing deferred), NtReadFile
on an NT stdin handle still runs the POSIX pgrp gate inside
tty_input_read (kill_pgrp could signal an NT task — logged,
not reachable without a real NT console reader yet).
petest boots in QEMU: 'NT personality + TEB OK' (gs:[0x30]
read), NtAllocateVirtualMemory commit touched+verified,
NtDelayExecution 10ms sleep, NtTerminateProcess — real .exe,
no shim, no Wine. 21/21 suites 0 failures, 43 tasks, frames
108572 -> 108572 zero leak, exit 33. Ledger: 112.

run-107 — real PE imports + base relocations: pe.rs now carries
the IMPORT/BASERELOC directory extents (rva+size, both bounds-
checked against SizeOfImage) instead of rejecting them.
pe_apply_relocs walks .reloc blocks and adds (bias - image_base)
to each DIR64 slot — the image still links at 0x140000000 but
runs at PE_LOAD_BIAS; non-DIR64/ABSOLUTE types fail honestly.
pe_resolve_imports walks IMAGE_IMPORT_DESCRIPTORs: only
ntdll.dll resolves (other DLLs fail the load), ILT names map
through nt::service_for_name (Nt/Zw prefixes both accepted,
ordinals rejected), each import gets a 16-byte stub on STUB_VA
(mov r10,rcx; mov eax,nr; syscall; ret — the real ntdll shape)
written into the IAT, so compiled `call [rip+IAT]` code just
runs. The stub page is RWX during fill then dropped to R-X.
peitest.S is a real import-bearing PE: descriptor+ILT+IAT+name
strings all in .text (IMPDIR00/RELOC markers let mkpe.py fill
the data dirs), calls NtWriteFile/NtTerminateProcess via the
IAT using the standard Win64 ABI (rcx-arg1, stack args at
rsp+0x20), and checks a DIR64-relocated pointer by printing
the string it points at. Audit (run-81, quick, scoped): 2
fixes — reloc slot RVA was bounded only by page-off math
(could rewrite mapped-but-foreign task pages like the stub
page/TEB on malformed input), now every slot must land inside
SizeOfImage; descriptor/thunk RVAs likewise bounded (name_rva,
ilt_rva, iat_rva, IMAGE_IMPORT_BY_NAME rva all < p.size) so a
crafted image can't make the loader read/patch memory outside
its own span (self-corruption only anyway — translate_r stays
inside the task's own maps). Also fixed service_for_name's
Zw-strip dropping the Nt prefix match (imports literally
named NtWriteFile never resolved). cve.now: PE-loader class
has no applicable CVEs (only CVE-2025-22060 NIC TCAM race,
n/a). Verified: descriptor walk capped 64, thunks capped 256,
names bounded 32/48B unterminated-reject, stub page bounded
256 slots. peitest+petest both pass in QEMU: 'imports resolved
via IAT', 'DIR64 reloc patched'. 21/21 suites 0 failures, 44
tasks, frames 108567 -> 108567 zero leak, exit 33. Ledger: 112.

run-108 — real compiler-produced .exe + Win32 thunk layer:
pe_resolve_imports now accepts kernel32.dll / kernelbase.dll /
api-ms-win-* descriptors in addition to ntdll; each non-ntdll
import is resolved by k32_stub, which emits a hand-encoded
Win64 translation thunk into the STUB_VA page — a real
kernel32 export shape that re-marshals Win32 args into the NT
service convention (WriteFile/ReadFile/WriteConsoleA/
ReadConsoleA -> 9-arg Nt{Read,Write}File with a stack iosb
whose info word is copied back to &written; GetStdHandle
-10/-11/-12 -> NT std handles 1/2/3; ExitProcess ->
NtTerminateProcess(-1); VirtualAlloc ->
NtAllocateVirtualMemory(-1) returning the committed base or
NULL). Unknown names still fail the load honestly. Test is
hello_win.exe — a REAL MinGW-gcc-produced PE32+ (gcc
-nostdlib, committed as a binary fixture with hello_win.c
provenance, not hand-rolled): genuine .text/.rdata/.pdata/
.xdata/.idata sections, a real import descriptor, DIR64
relocs, compiler-emitted call [rip+IAT] against the IAT.
Boots in QEMU: 'hello_win: real MinGW-compiled .exe via
kernel32' written through WriteFile -> NtWriteFile -> the
shared console, exit via ExitProcess -> NtTerminateProcess.
Audit run-82 quick scoped: verified thunk byte counts <= the
96B stub-slot bound, jz/js/jmp displacement math by hand,
iosb lands inside each thunk's own stack frame (userspace
write, no kernel deref), dll[..12] api-ms prefix slice
guarded by len check, unknown k32 names honest-fail, stub
page still drops to R-X after fill. cve.now: no applicable
class hits. 21/21 suites 0 failures, 45 tasks, frames
108568 -> 108568 zero leak, exit 33. Ledger: 112.

run-112 — native Windows heap subsystem: PE tasks get a real
process heap instead of page-per-alloc VirtualAlloc backing.
The arena [HEAP_VA=STUB_DATA_VA+0x1000, HEAP_MAX=TEB_VA+0x40000,
~236KiB) sits between the PE support pages and NT_ALLOC_VA
(which moved to HEAP_MAX). Real Windows manages heaps in ntdll
userspace (RtlAllocateHeap); ours is kernel-side: a 128-slot
block table in Task ([addr,size,state] state 0/1/2), best-fit
with split+coalesce, bump allocation with lazy page commit
(USER|WRITE|NX), and only the committed prefix registered in
ranges[] so range_ok rejects uncommitted heap VA. Win32 thunks
marshal GetProcessHeap/HeapAlloc/HeapReAlloc/HeapFree/HeapSize
plus HeapCreate (fake handle), inert TRUE stubs (Destroy/
Validate/Lock/Unlock/Compact/Query/SetInformation), and
Local/GlobalAlloc/Free; malloc/calloc/realloc/free/_msize and
the ucrtbase _base spellings rewire onto the same private
RUX_HEAP_* services (0xF0-0xF3), replacing the old malloc=
VirtualAlloc-with-header path (VirtualAlloc/VirtualFree stay
real). Double/invalid free returns FALSE — kernel metadata
cannot be forged from userspace, so the classic heap
exploitation class is structurally absent. Audit run-86 quick
scoped: 3 confirmed + 1 semantic gap fixed pre-commit —
HeapReAlloc thunk REX byte emitted `mov rax,r10` for
`mov r8,rdx` (garbage zero-flag); nt_try_map honored a
VirtualAlloc hint into the uncommitted heap tail (VA
double-owner alias); heap_rng cached a ranges[] index that
nt_free_pages compaction could silently re-point (now the
committed range is found by arena base; field removed);
in-place grow now zeroes the tail for HEAP_ZERO_MEMORY.
winheap.exe is a real MinGW fixture exercising all of it
(GetProcessHeap, HeapAlloc ZERO_MEMORY, grow-preserves,
HeapSize, double-free rejection, block reuse, malloc/calloc/
realloc/free+free(NULL)); it exits via the full success path
(exit 23). Suite: 21/21 0 failures, 49 tasks, frames
108481 -> 108481 zero leak, qemu exit 33. NOTE: winheap.exe is
committed gzip-compressed (winheap.exe.gz, mkinitrd.py
decompresses .gz sources) because the host AV (Kaspersky)
quarantines the raw PE on sight — a storage workaround, not a
kernel change. Ledger: 113.

run-113 — Windows process parameters + TLS + VM honesty: a real
MinGW CRT binary now gets genuine startup state instead of
canned cells. pe.rs parses IMAGE_DIRECTORY_ENTRY_TLS (9) into
tls_rva/tls_size bounds-checked like the other directories. The
loader emits a TLS trampoline into the stub area before the R-X
lock-down: it validates the AddressOfCallBacks array is inside
the image, loops the array calling each entry with
(hinst, DLL_PROCESS_ATTACH, 0), then tail-jumps to the real
image entry. pe_tls_init zeroes *AddressOfIndex and points
gs:[0x58] slot 0 at the image template — enough for .CRT
callbacks and __thread variables in a single-threaded process.
The TEB now carries real ClientId (pid at +0x40, tid at +0x48)
written by pe_late_init after spawn/exec assigns the pid, and
the PEB command line is a real UNICODE_STRING built from the
actual exe name (same late call — t.exe is empty during
teb_peb_init, which was the winmisc bit-0x1 root cause). The
data page gains a 64-slot TLS array + allocation bitmap
(TlsAlloc/Free/Get/Set bound index<64), environment blocks in
both ANSI and UTF-16 (RUSTUX=1), a STARTUPINFO with cb=104, and
lconv/locale/charset cells for the MinGW CRT probes. Two real
NT services land: NtQueryVirtualMemory 0x23 (48-byte
MEMORY_BASIC_INFORMATION from the ranges ledger — committed
fields, or MEM_FREE to the next registered region) and
NtProtectVirtualMemory 0x50 (probe-validated pointer args,
overflow-safe alignment, bounded to user VA, heap arena
rejected since it self-manages, range_covered + entry-count
checked before PTE rewrites, TLB flushed). VirtualProtect and
VirtualQuery thunk-marshal to them; VirtualFree maps to the
existing NtFreeVirtualMemory. Fourteen new thunk arms fill the
bigger CRT surface winmisc imports: strstr, wcslen, a strlen
that returns rax (the run-111 arm left len in rcx for
puts/fputs — the regression that took windir to exit 5),
memset/memcpy/strcmp/strncmp fixes, fputc,
FreeEnvironmentStringsA/W, and locale/charset inert cells.
winmisc.c is a real MinGW fixture with a .CRT TLS callback
and a __thread variable; it exits 31 on full pass. Two
emitter bugs fixed pre-commit: strstr and memset had REX
direction bytes 0x4c where 0x49 was needed (emitting
mov rdx,r10 / mov rcx,r9 — reversed — so r10/r9 stayed stale;
the memset one could rep-stosb through a garbage destination
inside task space). Audit run-87 quick scoped: no confirmed
findings; cve.now PTE-protection hits are all Linux-mm
concurrent-walker UAF races (n/a — synchronous rewrite under
the global lock). Suite: 21/21 0 failures, 50 tasks, frames
108480 -> 108480 zero leak, qemu exit 33. Ledger: 114.

run-114 — NT virtual-memory reserve/commit split: VirtualAlloc
finally behaves like real Windows memory. MEM_RESERVE places an
RNG_RES ledger entry (bit 8) that holds VA with zero frames —
a 1 GiB reservation costs nothing — carrying the placeholder
protection in the access bits for honest AllocationProtect;
range_check now excludes RNG_RES explicitly so placeholder
bits can never pass a user-pointer probe into unmapped pages.
MEM_COMMIT walks the window piecewise through
nt_commit_window: inside a reservation it splits the entry
(remnants keep RNG_RES|placeholder) and maps pages with the
call-supplied protection — protect is finally honored, not
just bookkeeping — at unowned VA its

run-114 — NT virtual-memory reserve/commit split: VirtualAlloc
finally behaves like real Windows memory. MEM_RESERVE places an
RNG_RES ledger entry (bit 8) that holds VA with zero frames —
a 1 GiB reservation costs nothing — carrying the placeholder
protection in the access bits for honest AllocationProtect;
range_check now excludes RNG_RES explicitly so placeholder
bits can never pass a user-pointer probe into unmapped pages.
MEM_COMMIT walks the window piecewise through
nt_commit_window: inside a reservation it splits the entry
(remnants keep RNG_RES|placeholder) and maps pages with the
call-supplied protection — protect is finally honored, not
just bookkeeping — at unowned VA it's an implicit
reserve+commit, and over committed pages it's the no-op
re-commit Windows allows. MEM_DECOMMIT lands as its own path:
committed pieces unmap and flip to RNG_RES, reserved pieces
are no-ops, gaps fail; and MEM_RELEASE with size 0 resolves
the covering region extent like real callers expect.
VirtualQuery reports MEM_RESERVE with Protect 0; protect and
decommit require committed coverage (range_committed). All
window ops bound to user VA, page-align bases, reject the
self-managed heap arena (commit/decommit/protect/free now
consistent), pre-flight ledger capacity before any split,
and map-before-flag with per-piece unwind so a mapped-but-
reserved page can never exist. range_compact now sorts
before merging since splits append out of order — repeated
commit/decommit cycles can't exhaust the ledger. Audit
run-88 quick scoped: no confirmed findings; the audit caught
that decommit was missing the heap-arena exclusion the other
three ops had (would have left HeapAlloc handing out unmapped
pages). winmem.exe.gz (real MinGW) proves it end to end:
1 GiB reserve succeeds (eager would need ~262k frames),
in-reservation commit, Query RESERVE->COMMIT->RESERVE->FREE,
protect-on-reserved fails, decommit and both release forms
work — exits 29. Suite: 21/21 0 failures, 51 tasks, frames
108477 -> 108477 zero leak, qemu exit 33. Ledger: 115.

Run-115 (this session): real NT threads and per-thread TLS.
CreateThread now builds a genuine CLONE_VM-shaped task — shared
pml4 via mm_share, shared files/sighand/fs table refs, own kernel
stack, and one contiguous committed VA window per thread holding
[user stack | TEB | TLS copy] so the range ledger spends exactly
one entry per live thread (the first design spent three and the
32-slot ledger died after ~10 creates; dead threads
windows are reclaimed on the next create via owner bookkeeping).
The new task gets a unique pid under the shared tgid, rip=start,
rcx=param (Win64 first arg), rsp aimed at a synthetic return
address into the thread-exit stub, gs_base=its own TEB, and
state=Blocked+WaitOn::NtSuspend for CREATE_SUSPENDED.
Thread handles live in a global 16-entry NT_THREADS ledger
keyed by ledger idx (stored in nth_fd): handles stay valid
after the task slot reaps, refs bump at bind and drop on
CloseHandle, dead+unreferenced entries free themselves;
task_exit records the raw exit code there for
GetExitCodeThread/NtQueryInformationThread (ThreadBasicInformation:
ExitStatus or STILL_ACTIVE, TebBase, ClientId pid/tid).
The subtle one: this kernels

Run-115 (this session): real NT threads and per-thread TLS.
CreateThread now builds a genuine CLONE_VM-shaped task - shared
pml4 via mm_share, shared files/sighand/fs table refs, own kernel
stack, and one contiguous committed VA window per thread holding
[user stack | TEB | TLS copy] so the range ledger spends exactly
one entry per live thread (the first design spent three and the
32-slot ledger died after ~10 creates; dead threads windows are
reclaimed on the next create via owner bookkeeping). The new task
gets a unique pid under the shared tgid, rip=start, rcx=param
(Win64 first arg), rsp aimed at a synthetic return address into
the thread-exit stub, gs_base=its own TEB, and state=Blocked+
WaitOn::NtSuspend for CREATE_SUSPENDED. Thread handles live in a
global 16-entry NT_THREADS ledger keyed by ledger idx (stored in
nth_fd): handles stay valid after the task slot reaps, refs bump
at bind and drop on CloseHandle, dead+unreferenced entries free
themselves; task_exit records the raw exit code there for
GetExitCodeThread/NtQueryInformationThread
(ThreadBasicInformation: ExitStatus or STILL_ACTIVE, TebBase,
ClientId pid/tid). The subtle one: this kernel's blocking model
abandons the syscall kernel frame - a blocked task resumes in
userland at ctx.rip with a waker-written rax - so a poll-and-
sleep loop inside the handler was wrong twice over (it returned
rax=0 == WAIT_OBJECT_0 on the timer wake regardless of the
object). NtWaitForSingleObject now parks on WaitOn::NtWait(idx)
serviced per tick by nt_wait_expire: dead entry ->
ctx.rax=SUCCESS, expired wait_deadline -> STATUS_TIMEOUT, NULL
interval = infinite. WaitForSingleObject marshals a negative
relative LARGE_INTEGER in r8; INFINITE becomes NULL. ResumeThread
is the only wake for WaitOn::NtSuspend. TLS went genuinely
per-thread: each TEB carries its own 64-slot array at +0x200 and
bitmap at +0x1f8 (gs:[0x58] points at the array; the bitmap sits
at array-8), slot 0 is the compiled .tls template copied per
thread, and TlsAlloc/TlsFree/TlsGet/Set operate on the current
thread's bitmap - __thread copies are private per worker (fixture
verifies 100+idx does not leak into the leader). Audit run-89
quick scoped: one confirmed-class issue found and fixed in-run -
the copied ranges/heap ledger would go stale when a sibling
mutates the shared map (probe passes on freed VA -> kernel #PF);
mm_owner_i/mm_owner_mut now routes every NT non-leader ledger
access (probes, alloc/free/commit/decommit/query/protect, heap
ops) to the process leader. Also recorded: nth handles are
per-task (Windows handles are process-wide - honest
INVALID_HANDLE divergence), and the probe->raw-deref atomicity
invariant is now load-bearing (no syscall handler yields mid
user-VA access; verified). winthr.exe.gz (real MinGW) exits 37:
two workers run/join with exit codes 41/42, STILL_ACTIVE while
running, TlsAlloc slot isolation, __thread privacy, unique tids,
CREATE_SUSPENDED times out at 50ms then ResumeThread runs it to
exit 9, CloseHandle on all handles. Suite: 21/21 0 failures,
52 tasks, frames 108475 -> 108475 zero leak, qemu exit 33.
Ledger: 116.

Run-116 (this session): process-wide NT handle table.
Windows handles are process objects, but run-115 left them
per-task — a thread got INVALID_HANDLE for anything the leader
opened. All nine nth helpers (nt_handle_kind/close/alloc_file/
fd/free_slot/alloc_thread/thr_idx plus nt_dir_pattern{,_set})
now resolve through mm_owner_mut, so an NT non-leader defers
to the task slot whose pid == tgid — the same routing the
run-115 ledger fix established for ranges/heap. The child's
own nth is zeroed at create instead of snapshotting the
parent's: nothing can consult it, and a table that looked
alive but wasn't would be worse than an honest empty one.
NTH_FILE close works unchanged because fd_close resolves the
calling task's shared fdi — same OFD slot, ref drops once.
Verified by construction: leader-reaped resolves None ->
INVALID_HANDLE rather than a freed-slot touch; NtClose is
atomic on the single CPU so close-vs-close can't double
refdown; a waiter holds the ledger IDX so close-vs-wait
yields STATUS_INVALID_HANDLE, never a UAF. One honest
divergence recorded: leader reaped while threads still run
drops the whole handle table (real Windows keeps it in the
process object until the last thread dies). The joiner
thread in winthr now Waits on h0 — a handle the leader
opened — and reads its exit code; exit(37). Audit run-90
quick scoped: no confirmed findings. Suite: 21/21 0
failures, 52 tasks, frames 108477 -> 108477 zero leak,
qemu exit 33. Ledger: 117.

Run-117 (this session): NT section objects and file mapping
views — the kernel primitive behind CreateFileMapping/
MapViewOfFile and, later, SEC_IMAGE DLL loading. NT_SECTIONS
is a small ledger of (oi, size, prot, state, refs) entries;
each NTH_SECTION handle bumps refs and NtClose refdowns.
nt_handle_file_oi resolves an NTH_FILE handle to its OFD
index and pins it — the section (and every view) holds a ref
so the backing content cannot die mid-map. NtCreateSection
takes SEC_COMMIT sections only, file-backed or anonymous
(NULL/-1 file => MaximumSize required), rejects a READWRITE
section on a read-only OFD up front, and now caps the size at
the NT arena span (audit fix — an unbounded u64 made the view
page-round wrap). NtMapViewOfSection validates off/vsz inside
the section, never grants view prot beyond the section prot,
commits a fresh window via nt_alloc_pages, seeds file bytes
through write_task_bytes_force — the physical-frame fill the
PE loader uses for RO sections, because a PAGE_READONLY PTE
denies kernel VA writes too (CR0.WP kernel #PF, found and
fixed this run) — and records a view entry. The view ledger
splits va_size (committed span) from file_span (raw file
bytes), so write-back of a short offset view can never grow
the file to a page boundary. Only PAGE_READWRITE views on
Ram-backed OFDs write back on unmap/flush; WRITECOPY
discards; initrd slices are immutable by construction.
NtUnmapViewOfSection/NtFlushVirtualMemory resolve views by
owner pid + base and route free/ledger work through
mm_owner, so threads unmap cleanly. Two emitted-stub
encoding bugs found and fixed: MapViewOfFile or r8,r9 lacked
REX.B (section handle leaked into SectionOffset), and the
new memcmp/strncmp loads used REX.B where REX.R was needed
— mov cl,[r9] read supervisor page 0 (the cr2=0/err=0x5
mystery: page 0 is present+supervisor in the cloned pml4).
nt_sec_refdown now also releases the OFD pin on last close
(audit fix — bounded ref leak). winmap.exe (real MinGW)
exercises RW view + writeback, FlushViewOfFile, COW discard,
anon section, RO view of initrd content, offset view, and
denied cases — exit(39). Audit run-91 quick scoped: 2
confirmed findings fixed in-run, no remaining. Suite: 21/21
0 failures, 53 tasks, frames 108475 -> 108475 zero leak,
qemu exit 33. Ledger: 118.

## run-118 — PE DLL loading (LoadLibrary/GetProcAddress/FreeLibrary)

Real MinGW windll.dll loads inside a running NT process: pe_map_image
maps the image into an existing address space (arena placement, per-
section PTE+ledger, DISCARDABLE skip that keeps .reloc since MinGW
marks it discardable), relocs + IAT thunks via the persisted nt_stub
cursor, NT_MODS ledger for dedup/refs/unload. LoadLibraryA/W thunks
call DllMain(DLL_PROCESS_ATTACH) only on fresh maps — the kernel
returns base|1<<63 and the thunk js/btr-rax,63s on it. nt_get_proc
walks the export dir by name (owner-checked hmod, forwarders rejected,
frva span-checked). nt_free_dll refcount-unmaps. windlltest exits 33:
load, export call, DllMain state, dedup same-HMODULE, two FreeLibrary,
reload fresh map, missing export + missing dll rejection. Audit
run-92 quick scoped: no confirmed findings, 2 latent fixed in-diff
(frva span, raw-extent slice guard both loaders). Suite: 21/21
0 failures, 54 tasks, frames 108468 -> 108468 zero leak,
qemu exit 33. Ledger: 120.

## run-119: dependent-DLL loading (PE import graph + dep DllMain + unload cascade)

- Modules can now import other user modules: pe_resolve_imports routes
  any non-system descriptor name (not kernel32/kernelbase/msvcrt/
  ucrtbase/api-ms-*/ntdll) through nt_mod_resolve — dedup bumps refs on
  a live module; a miss maps the image recursively via pe_map_image
  (depth bound 4, cycles fail honestly with full unwind).
- The importer IAT gets the dep export VA directly (no thunk), bound
  through nt_export_lookup — the export-directory walk factored out of
  nt_get_proc and shared by both paths (forwarders rejected, frva
  span-checked, 8192-name cap).
- NT_MODS grew to 9 fields: + dep_mask (which slots this image bound),
  + entry_va, + pend_attach. nt_mod_refdown cascades: final release of
  a parent refdowns every recorded dep, like the real loader.
- Dep DllMains run: nt_mod_add flags fresh modules pend_attach; the
  LoadLibraryA/W thunk drains the queue via new RUX_DLL_ATTACH (0xF7)
  calling each DllMain(DLL_PROCESS_ATTACH) in userland — deps sit in
  lower slots so they initialize before their importer.
- Audit fixes in-diff: duplicate-descriptor dep refs now undo the
  surplus bump (mask releases once); failed loads release accumulated
  dep refs via nt_deps_release.
- MAX_RANGES 32->128 — sized to NT_MAX_MODS=8 images x ~11 mapped
  sections + exe + system VMAs (+2304B/task static).
- Fixture winchain.exe (exit 34): wchain.dll statically imports
  wbase.dll: recursive map, export-bound IAT, dedup to the dep
  mapping, chain_state/base_state set by drained DllMains, cascade
  unload + reload at a fresh base. windlltest regression clean.
- Audit run-93 quick scoped: 2 confirmed fixed in-diff, none remaining;
  cve.now hits all SMP-concurrent classes (n/a). Artifacts:
  ~/security-audit-skill/linux-rust/run-93/.
- Suite: 55 tasks, frames 108432 -> 108432 zero leak, qemu exit 33.
- Known gaps (recorded, not bugs): module-name dedup is byte-exact
  (case variants double-load); exe-static-import dep DllMains never
  drain (no LoadLibrary thunk in the spawn path); import cycles fail
  at depth 4 rather than binding the in-progress image.

## run-120 — exe-static dep attach drain + GetModuleHandle (this commit)

- emit_attach_drain: an exe that statically bound module imports starts
  on a stub trampoline that loops RUX_DLL_ATTACH calling each pending
  module's DllMain(DLL_PROCESS_ATTACH) — dep attaches run before the
  image's TLS callbacks and entry, closing run-119's recorded gap.
- nt_lock_stubs split: a dep's resolve no longer seals the shared stub
  pages mid-fill (it ran unconditionally at every resolve tail — the
  root cause of the winstatic spawn failure); the outermost caller
  (pe_load_inner / nt_load_dll) seals once the whole import graph is
  bound. Audit fix: the seal also runs on the failure path — a failed
  LoadLibrary no longer leaves stub pages RWX.
- Stub cursor publish/resync: the exe's local cursor went stale across
  a dep resolution, so post-dep descriptors emitted thunks over the
  dep's and dep IATs aliased wrong code — now t.nt_stub is published
  before recursing and resynced after.
- Spawn-time dep ownership: pid moves into load() (was assigned after
  image load, so spawn-time deps registered under owner=0 and never
  drained/deduped); nt_mod_add's dead-owner sweep exempts the caller's
  own slots — a spawning task is not in TASKS yet when its second dep
  registers, and the sweep would have reaped the first dep's slot.
- Fixed-region ranges[] registered BEFORE import resolution — dep
  placement via nt_place_ok provably avoids stack/PEB/TEB/stub spans;
  pe_map_image/nt_mod_resolve take &mut Task so spawn-time dep maps
  land in the new task's pml4, not the running task's.
- GetModuleHandleA/W: named-path lookup via RUX_MOD_HANDLE (0xF8) +
  nt_mod_handle — basename-reduced, owner-keyed, no ref bump; NULL
  keeps the PEB.ImageBaseAddress fast path. nt_mod_name shares the
  bounded name read with nt_load_dll.
- Fixture winstatic.exe (exit 36): statically imports wchain.dll (which
  itself imports wbase.dll) — verifies recursive map/bind/dedup, dep
  DllMain ordering via the startup drain (base_state=7, chain_state=20),
  export calls, and GetModuleHandle A/W/NULL/missing/path-basename.
- Audit run-94 quick scoped: 1 confirmed finding fixed in-diff (failed
  resolve left stub pages RWX — sealed on both outcomes now); cve.now
  clean. Artifacts: ~/security-audit-skill/linux-rust/run-94/.
- Suite: 56 tasks, frames 108432 -> 108432 zero leak, qemu exit 33.
- Known gaps (recorded, not bugs): module-name dedup byte-exact;
  spawn-drain covers only spawn-time pending attaches (later loads
  drain via the LoadLibrary path, as on Windows); borrowed-handle
  semantics (no GetModuleHandleEx ref bump).

## run-121 — DllMain(DLL_PROCESS_DETACH) + cascade unload (this commit)

- nt_free_dll final-ref path no longer unmaps inline: a worklist
  simulation over dep masks computes the zero-reaching set and marks
  every member pend_detach (pend_st is now tri-state: 1 pend_attach,
  2 pend_detach, 3 detached-awaiting-fin). Return is 1|1<<63 so the
  FreeLibrary thunk knows a drain is owed.
- FreeLibrary thunk: on the pend bit it loops RUX_DLL_DETACH (0xF9,
  descending slot order = importer-first), calls each returned base's
  PE entry with (hinst, DLL_PROCESS_DETACH, 0), then runs
  RUX_FREE_FIN (0xFA) until it reports no pending work — then returns
  TRUE explicitly.
- nt_detach_fin: per-importer dep refdown over each marked mask
  (a union mask undercounted refs for deps shared by two freed
  importers — permanent leak), slot clear + unmap of the marked set,
  then re-marks any live module driven to refs==0 mid-cascade so its
  detach still runs (the thunk re-drains on the again bit).
- Re-entrant FreeLibrary from inside a DllMain(DETACH) merges into the
  live pipeline instead of re-arming it: entries already pend_st >= 2
  are left alone and the nested call returns a plain success — only
  the outermost FREE_FIN ever unmaps, so a nested fin cannot pull an
  image out from under a running outer DllMain. FreeLibrary on an
  in-flight module is a TRUE no-op (Windows serializes this on the
  loader lock).
- pe_map_image now returns the actual mapped extent (mapped_hi), not
  SizeOfImage: MinGW's discardable .debug tail is never mapped, and a
  dep legitimately placed in that gap was being unmapped by the
  importer's FREE_FIN — the "partial unmap mid-DllMain" fault class.
- Fixture windetach.exe (exit 41): importer-first detach order via
  probes written into exe-owned memory, shared-dep retention while a
  second ref holds it, handle disappearance after unmap, non-final
  release does not detach, final release does, reload re-init works.
  wchain's detach performs a re-entrant self FreeLibrary (no-op) and
  probes count calls (+=), so a re-armed or doubled detach fails.
- Audit run-95 quick scoped: 2 confirmed findings fixed in-diff
  (re-entrant free pipeline corruption; shared-dep refdown undercount);
  cve.now clean. Artifacts: ~/security-audit-skill/linux-rust/run-95/.
- Suite: 57 tasks, frames 108430 -> 108430 zero leak, qemu exit 33.
- Known gaps (recorded, not bugs): no loader lock — multi-threaded
  same-owner FreeLibrary/LoadLibrary races are unsynchronized;
  process exit still does not run detaches for surviving modules;
  a dep zeroed by a re-entrant free gets its detach from the re-drain
  with approximate ordering.

## run-122 — exit-time DllMain(DLL_PROCESS_DETACH) (this commit)

- RUX_EXIT_DETACH (0xFB) -> nt_exit_detach: one service does both
  halves of the exit drain — mark every still-live module this owner
  holds pend_detach (state 2), except attach-pending state-1 entries
  which go straight to 3 (a DllMain whose ATTACH never ran gets no
  DETACH — same rule Windows applies), then pop the next pending entry
  descending slot order = reverse-load order. Idempotent and
  re-entrancy-safe: entries at state >= 2 are never re-armed, each pop
  flips 2 -> 3 before the call returns.
- emit_detach_drain: the detach-callback loop shared by FreeLibrary
  (0xF9) and ExitProcess (0xFB) — identical emit to the run-121
  drain (syscall -> test -> peoff/entryRVA read -> null-entry skip ->
  call r9 with (hinst, DETACH, 0)), parameterised on the service id;
  returns the loop head so FreeLibrary's fin-loop can re-enter.
- ExitProcess/exit/_amsg_exit thunk: sub rsp,0x28; park the exit code
  at [rsp+0x20] (above the callee's shadow space so DllMain cannot
  clobber it); drain; restore the code into rdx; NtTerminateProcess
  as before. TerminateProcess and abort keep the old straight path —
  no detach callbacks on forced termination, matching Windows.
- Fixture windexit.exe (exit 42): loads wchain+wbase, FreeLibrary on
  wchain proves the explicit-unload detach still fires exactly once,
  then exits with wbase still mapped — its detach is owed at exit and
  runs in the drain; probe counters would fail any double call.
  winstatic now also exercises exit-detach for a statically-loaded
  dep chain.
- Audit run-96 quick scoped: no confirmed findings. The one candidate
  (a nested FreeLibrary inside an exit-drain DllMain unmapping the
  running image through nt_detach_fin's all-owner sweep) is closed by
  the run-121 in-flight check — the executing module is at state >= 2
  during its own callback, so the nested free merges into the live
  pipeline and skips drain/fin entirely. Divergences recorded:
  LoadLibrary inside an exit-drain detach is skipped entirely (marked
  3, never attached); exit drain does not unmap images — task
  teardown owns the address space; ordering is descending-slot
  approximate, not the loader's real reverse-init list; multi-threaded
  owner races remain unsynchronized (no loader lock).
- Suite: 58 tasks, frames 108433 -> 108433 zero leak, qemu exit 33.

run-123 — thread-lifetime DllMain notifications (DllMain reason 2/3)

- New private service RUX_THR_ENUM (0xFC): nt_thr_enum(prev, dir) is
  a pure iterator over the owner's live module entries (pend_st == 0)
  — dir 0 walks forward in load order for DLL_THREAD_ATTACH, dir 1
  reverse for DLL_THREAD_DETACH. prev=0 starts the walk; a prev whose
  slot was freed mid-drain fails the lookup and ends the walk cleanly.
  Owner resolves via nt_owner_pid (tgid-aware), so a secondary thread
  enumerates the leader's module table.
- emit_thr_drain: shared emitter used by the thread-entry trampoline
  and the ExitThread thunk — loops RUX_THR_ENUM with rbx as cursor
  (callee-saved, survives user-mode DllMain), passes prev in r10 per
  the ntdll arg convention (rcx is clobbered by syscall itself), and
  calls each entry (hinst, reason, 0). Skips modules with no entry.
- emit_thr_entry + Task.thr_entry_va: every exe gets a thread-entry
  trampoline emitted at load; nt_thread_create sets rip to it with
  rcx=start_fn, rdx=param (the bare-start fallback remains for
  tasks without stubs). The trampoline normalises rsp, parks
  start/param above the callback shadow space, drains
  DLL_THREAD_ATTACH forward, calls the real start routine, drains
  DLL_THREAD_DETACH reverse, then NtTerminateThread(0, status) —
  covering the normal return path end-to-end.
- ExitThread thunk arm now drains DLL_THREAD_DETACH (reverse) before
  NtTerminateThread so the explicit-exit path matches.
- Alignment fix carried over: emit_attach_drain's sub rsp,0x28 left
  DllMain at rsp%16==0 after and rsp,-16; frames in all three sites
  are now multiples of 16 (0x30/0x40) so the callee lands at ==8.
- Fixture winthrnt.exe (exit 43): wbase/wchain gained thr_att/
  thr_det counters and a seq_reg order probe (writes 'b'/'c').
  Thread 1 (return path) must produce attach "bc", detach "cb",
  seq "bccb", counters 1 each; thread 2 (explicit ExitThread) repeats
  it for seq "bccbbccb" and counters 2 — exact-order and
  exactly-once assertions, not just presence.
- Audit run-97 quick scoped: no confirmed findings. Two development-
  caught defects noted: prev initially travelled in rcx which
  syscall clobbers (enum always saw garbage -> no callbacks — the
  fail-closed direction), and the first emit buffer (160B) silently
  truncated the trampoline causing total PE spawn failure (now 256B
  with a hard length check). Divergences: no loader lock — a
  concurrent FreeLibrary can unmap a module mid-drain and fault the
  draining thread in its own address space; a detach callback that
  frees the visited module ends the walk early; thread-vs-leader
  load ordering unsynchronized.
- Suite: 59 tasks, frames 108432 -> 108432 zero leak, qemu exit 33.
  windexit 42, windetach 41, winstatic 36, winchain 34,
  windlltest 33 all regression-clean.

## run-123b/123c — module-table hygiene (a99cf48, 5d7dba5)

- 123b: NT module slots are released at leader exit — without it the
  8-slot ledger filled with zombie-owned entries across fixtures.
- 123c: NT_MODS widened 8 -> 16 and dep_mask u8 -> u32; six concurrent
  DLL fixtures holding ~2 modules each exceeded 8 live slots even with
  the exit-time release.

## run-124 — PE TLS callbacks through process/thread lifecycle (this commit)

- MinGW's CRT keeps its __thread destructor list behind a TLS callback;
  without firing PIMAGE_TLS_CALLBACK arrays the loader diverged from
  real ntdll on every notification. New emitted helpers:
  emit_tls_walk (generic NULL-terminated PIMAGE_TLS_CALLBACK walk),
  emit_tls_cb_walk (per-module: reads the TLS directory at
  peoff+0xd0, relocates AddressOfCallBacks, bounds-checks the array
  inside the image — lower bound cbs>=base plus wrap-safe size compare),
  emit_exe_tls (exe array published at STUB_DATA_VA+0x108 by
  pe_tls_init, cleared when tls_rva==0).
- Callbacks run BEFORE the matching DllMain on every notification:
  process attach/detach and thread attach/detach, for statically
  imported deps and LoadLibrary modules alike. Verified against real
  Win11 ntdll with a purpose-built PE (exe + 2 DLLs logging order):
  per-module TLS-before-DllMain, forward attach / reverse detach, and
  exe callbacks LAST on both thread reasons (the loader skips the exe's
  ldr entry and handles it separately).
- TLS index allocation moved to a process-global bitmap at
  STUB_DATA_VA+0x1f8 (lock bts / lock btr). The old per-thread bitmap
  let a worker re-issue index 1 already owned by the CRT's dtor list —
  TlsSetValue then corrupted the list and the detach destructor
  dereferenced a raw integer (winthr crash, cr2=0xa0). TlsAlloc and
  TlsFree now also zero the freed/allocated slot in the calling thread
  (kills stale-value reuse); TlsFree honors btr's CF and fails on an
  unallocated index. Divergence: Windows clears the slot in EVERY
  thread; ours clears only the freeing thread's (needs a TEB walk —
  recorded as audit NV).
- nt_mod_add now inserts after the owner's last LIVE module instead of
  the first free slot — slot reuse from dead-owner sweeps could place a
  later LoadLibrary ahead of an earlier one, flipping drain order
  nondeterministically (winthrnt's seq probe caught "CcBbBbCc").
  Free test tightened refs==0 -> base==0.
- pe_tls_init / emit_tls_tramp bounds rewritten in subtract form
  (x>=bias && x-bias<=size-k) — the add form could wrap u64 for
  file-controlled VAs near 2^64.
- die_signal gained a sig-death printk — signal-killed tasks previously
  exited with no log line at all.
- Suite: qemu exit 33; all PE fixtures green incl winthrnt exit(43)
  and winthr exit(37) across repeated runs. The intermittent
  "wait failed"/vanished-fixture mysteries were resolved: ordering bug
  above + a serial ring-buffer replay artifact (duplicated lines share
  pid/timestamp), not task deaths.
- Audit run-80 standard scoped: clean, 7/7 coverage units, 0 confirmed.
  needs_validation: pre-existing nt_detach_fin unreachable-promotion
  slot leak (DllMain(DETACH) re-entrant FreeLibrary drops a dep to
  refs==0 mid-cascade; promoted entries are unreachable — unchanged
  adjacent code); TlsFree cross-thread slot clear divergence.

## run-125 — NT process objects, CreateProcessA, kstack underflow fix (this commit)

- The intermittent page-table corruption / stale-mapping / triple-fault
  mystery is resolved: Task is ~0x4d00 bytes but KSTACK_SIZE was 16384.
  Large stack-local Task construction plus load() -> Option<Task>
  by-value returns underflowed the stack into adjacent physical frames —
  sometimes live page-table frames. KSTACK_SIZE is now 49152 (order-4;
  a 128KiB order-6 attempt made spawn fail under fragmentation).
- NT process objects: NT_PROCS ledger (tgid/refs/state/exit), NTH_PROCESS
  handle kind, RUX_SPAWN_PROC 0xFD and RUX_PROC_QUERY 0xFE services.
  CreateProcessA works through the generated Win32 thunk layer and
  returns real process/thread handles + ids via PROCESS_INFORMATION;
  wait on the process handle (NtWaitForSingleObject) and
  GetExitCodeProcess are implemented.
- CREATE_SUSPENDED + ResumeThread: spawn_idx(..., hold) stages the child
  suspended while its ledgers and handles are installed — it cannot
  exit and reuse a slot mid-setup. Process object signals only when the
  last thread in the group exits; handle refs keep the object alive.
- Audit run-98 quick scoped: 2 confirmed findings fixed — sys_brk
  grow-rollback unmapped without flush_tlb (stale-TLB UAF,
  CVE-2018-18281 class; now flushes at user.rs:6722) and
  WaitOn::NtWaitProc raw-index ABA (a freed+reused ledger slot could
  satisfy a stale wait; now tgid-pinned, INVALID_HANDLE on identity
  mismatch). Verified by a fresh-eyes verifier: all 10 unmap_page
  sites flush, wake identity check precedes state check.
- Address-space fix kept from the debug hunt: new pml4s copy only
  (0..128).chain(256..512) — the caller's user PML4 slots were leaking
  into fresh address spaces.
- Fixtures: winchild.exe / winspawn.exe real MinGW PEs — spawn, wait,
  exit-code, suspend/resume, cmdline via both ANSI args and PEB
  parameters all verified.
- Suite: qemu exit 33, 61 tasks, frames 108425 -> 108425 zero leak,
  6/6 clean runs including post-diagnostic-strip.
- Diagnostics stripped before commit: DR0 watchpoint + register dumps
  (cpu.rs), allocator kind/ownership tags (kalloc.rs), FREEDANGL/PDUMP/
  MAPWALKBAD printks (user.rs).
- needs_validation: WaitOn::NtWait(thread) keeps the raw ledger index —
  same un-pinned ABA pattern, pre-existing; 48KiB stacks have no guard
  page (headroom margin only, CVE-2017-1000364 class).
- Next: run the README GIF regeneration (QMP screendump scripts), then
  the next ABI gap — see roadmap.

## run-125b — getdents enumeration cap (this commit)

- fd_getdents dedupes dir first-components into names[96]; '/' crossed
  ~100 components (initrd + sl_* + concurrent tasks), so entries past
  slot 96 were silently dropped — the iotest DT_LNK FAIL on VM-3.
  Same latent cap in the NT dir-listing path; /proc (64 pid dirs +
  globals) was approaching it too. Cap now 384.
- iotest's two getdents d_type checks did a single 2048B read of '/'
  with no continuation; both now loop until EOF (fd_getdents o.pos
  skip index supports it).
- Verified failing 2/2 on VM-3 pre-fix at both e3df0fd and e59445b
  (pre-existing flake, not a run-125 regression), passing after.

## run-126 — RTC wall clock + NT time/system services (this commit)

- rtc.rs: CMOS reader over ports 0x70/0x71 (NMI stays masked), BCD/
  binary per reg-B, bounded UIP spin, century reg 0x32, strict field
  validation (y 2000..2200 etc.), Hinnant days_from_civil +
  civil_from_days. EPOCH_BASE anchors unix time at boot so wall_now
  rides the 100Hz tick monotonically; tsc_hz() calibrates rdtsc over
  the PIT ch2 window (same trick apic::init uses).
- sys_time/sys_gettimeofday/sys_clock_gettime: REALTIME family (0/5/8)
  now returns the RTC wall clock; MONOTONIC/BOOTTIME stay tick-based —
  the clock-id split is deliberate, not a conflation. EFAULT +
  range_ok_w pointer rules unchanged.
- RUX_SYS_INFO 0xFF serves the Win32 side: SYSTEM_INFO (48B honest
  values), GetTickCount64 ms, FILETIME (1601-epoch), SYSTEMTIME via
  wall_datetime, rdtsc QPC + tsc_hz QPF, packed 10.0.19045 version,
  OSVERSIONINFOA/W. Thunk arms emit the rcx->rdx out-pointer /
  r10d=sub / eax=0xFF syscall sequence; NTSTATUS->BOOL via test+sete.
- WaitOn::NtWait is now (idx, tid) — the run-125 thread-wait ABA is
  closed: expire checks identity before signaled state, freed slots
  are zeroed, tids are monotonic, so a recycled slot can only yield
  STATUS_INVALID_HANDLE never a foreign SUCCESS.
- Audit run-99 (quick, scoped): 2 confirmed findings fixed in-diff —
  tsc_hz's OUT2 poll was unbounded and user-reachable (dead PIT ->
  kernel hang; now a ~0.16s TSC deadline), and NT handle-ledger refs
  were never released on task death (nt_handle_sweep at last-tgid-
  standing in both exit_bookkeeping paths + unconditional in
  Task::reap; idempotent). Verifier: no remaining stale-success path;
  blocked waiter implies handle ref >=1.
- winsys.exe (real MinGW, sprintf+puts only — printf/fflush pull
  imports we don't thunk): exit(45) after SYSTEM_INFO fields, tick
  monotonicity, QPC freq ~3.49GHz, FILETIME century check, SYSTEMTIME
  field ranges, GetVersion/ExA. Prints the RTC date on serial.
- 62 tasks, frames 108423 -> 108423 zero leak, qemu exit 33.
- Next: another ABI gap from the roadmap — the NT surface still lacks
  registry/env/console-input services; Linux side lacks fchmodat2/
  statx-class syscalls and settimeofday.


## run-127 — NT filesystem/path services (RUX_PATH 0x100)

- nt_pathop subs 0-10 over the shared VFS: Get/SetCurrentDirectory,
  GetFullPathName, Create/RemoveDirectory, GetFileAttributes,
  GetFileType, SetEndOfFile, FlushFileBuffers, GlobalMemoryStatusEx,
  GetComputerName — 20 thunk arms (A+W), fstab cwd shared with Linux.
- ANSI/UTF-16 path reader, DOS-path writer with Windows size
  semantics (returns needed-size-incl-NUL when short).
- Audit run-100: fixed UTF-16 page-straddle read (per-byte
  translate_r) + range_ok_w on GetComputerName *size; clamps on the
  DOS-path stack buffers.
- winfs2.exe exit(46): cwd round-trip, mkdir EEXIST, ".."
  canonicalisation, attrs/type/eof/flush, gms, name — 63 tasks,
  frames 108421 -> 108421 zero leak, qemu exit 33.
- Next: registry/env/console-input or Linux statx-class syscalls.


## run-128 — statx(2), NR 332

- sys_statx over the existing stat pipeline: newfstatat/sys_fstat
  refactored into fill_stat/fill_fstat returning Result<[u64;18]>;
  statx_emit builds the 256-byte struct (mask = request ∩
  STATX_BASIC_STATS, makedev decode); statx_dirfd_stat handles
  AT_EMPTY_PATH (FDCWD -> cwd, fd -> fstat shape).
- Unknown AT_* flag bits -> EINVAL; audit fix added
  AT_SYMLINK_FOLLOW (0x400) to the accepted mask.
- iotest: 15 statx checks — basic mask/mode/ino agreement, NOFOLLOW
  vs FOLLOW link split, EMPTY_PATH on dirfd/FDCWD/file-fd, and all
  four error edges. 63 tasks, frames equal, qemu exit 33.
- One flake observed mid-rung: fxtest spun in R past suite end on a
  single boot (reproduced 0/2 subsequent runs; unrelated to this
  diff — no futex/sched changes; watch it).
- Next: showcase ladder — htop needs full /proc/<pid>/stat fields +
  TIOCGWINSZ + termios output; then slirp net -> wget -> apt.


## run-129 — htop milestone: fbcon terminal emulator + extended kbd + 1MiB ustack

- fbcon.rs rewritten as VT100/xterm-subset emulator: cell grid + dirty
  repaint, CSI cursor/positioning/ED/EL/ICH/DCH, SGR colors, DEC
  line-draw -> CP437 glyphs, alt screen (saved_alt), DSR/DA replies
  injected via stdin_inject; scroll region clamped above boot splash.
- kbd.rs: E0-prefixed arrows/nav + F1-F10 -> ANSI sequences queued to
  the tty input path; Escape handled.
- log::user_out: raw console path for user writes — no printk record
  prefix; curses screens render clean while kernel log keeps [ts].
- USTACK_PAGES 16 -> 256 (1MiB) after htop overflowed the 64KiB stack
  into the signal-trampoline page (#PF, cr2 just under stack top).
- /proc/stat btime now RTC-derived boot epoch (was 0).
- initrd: real htop + libncursesw/libtinfo/libm/libnl + xterm
  terminfo; htoptest forks htop, pipe-feeds q, asserts exit 0.
- audit run-102: 6 confirmed findings fixed (alt-screen saved cursor,
  DECSTBM clamp order, UTF-8 abort byte-drop, cursor ghost, inject
  poller wake, ICANON semantics documented).
- 64 tasks, frames 108410 -> 108410 zero leak, qemu exit 33.
- Known polish: htop prints 'Can not save configuration to
  //.config/htop/htoprc: Invalid argument' — writable HOME/mkdir
  surface for a later rung.
- Next: QEMU slirp end-to-end (DHCP/DNS/TCP/wget http), then dpkg/apt
  prerequisites, then downloadable mini-ISO.

## run-130 — slirp end-to-end: DNS + TCP connect + HTTP through QEMU user net

- kernel/user/nettest.c (new, static-PIE): wire-format DNS query to
  slirp's resolver 10.0.2.3 (label encoder, compression-aware answer
  walk for the first A record), then a real TCP connect :80 +
  HTTP/1.0 GET asserting the status line. EHOSTUNREACH on sendto ->
  clean skip so a NIC-less boot stays green.
- Makefile: nettest.elf in USER_ELFS + mkinitrd; new `run-net` target
  attaching -netdev user + -device e1000e explicitly. Note: q35's
  QEMU default is already `-nic user,model=e1000e`, so `make run`
  exercises the same wire path — run-net makes it explicit, and the
  skip path only triggers under -nic none.
- user.rs: MAX_TASKS 64 -> 80 (65-task suite + fork slack); the
  FDTABS/SIGTABS/FSTABS caps now follow MAX_TASKS instead of a
  literal 64 so they can't silently under-provision again.
- main.rs: MAX_INITRD 32 -> 64 MiB — adding nettest pushed the
  archive to 30.9/32 MiB (96%); crossing the cap makes load_initrd
  return None -> the whole suite would silently collapse to the
  embedded hello while still exiting 33.
- lstest.S: record floor 44 -> 45 (nettest member; real count is 81
  incl concurrent adds). EOF check now drains bounded (256 calls)
  instead of requiring a single second call to return 0 — concurrent
  tasks add root records mid-suite (dashtest /sh_tmp, /proc churn is
  separate) so the old check raced; found via pid 4 lstest exit(1).
- audit run-103 (manual scoped — security-audit.md rubric and
  cve.now MCP not yet on this host): no kernel input/RX path touched;
  all caps remain compile-time bounded; nettest bounds-checks every
  parse. No confirmed findings. Verify with cve.now once configured.
- 65 tasks, frames 100174 -> 100174 zero leak (baseline -8192 frames
  = the extra 32MiB LOADER_DATA pre-alloc), qemu exit 33 on both
  `make run` and `make run-net`; nettest exit(0), HTTP/1.1 200 OK
  from deb.debian.org via 10.0.2.3.
- Env note (moved off Windows): repo at ~/linux-rust on this VM;
  toolchain native (no WSL). Missing vs old box: ~/linux-ref
  (v7.4.0-rc3 port base — needed only for NEW port extractions),
  ~/.devin/rules/security-audit.md, git push creds, cve.now MCP.
- Next: wget-style fetch through slirp, then dpkg/apt prerequisites
  (writable /var, tar/gz/SHA surface, fcntl locks), then mini-ISO.

## run-131 — real busybox wget over slirp: glibc-resolver socket ABI + TCP SYN retransmit

- kernel/user/wgettest.c (new, static-PIE): forks+execs /busybox
  `wget -T 15 -q -O /wget_out http://deb.debian.org/debian/` — real
  glibc stub resolver (reads /etc/resolv.conf -> 10.0.2.3), real TCP
  :80, O_CREAT output through the flat VFS. NIC-less skip like
  nettest; /wget_out unlinked after. kernel/user/resolv.conf staged
  as etc/resolv.conf; lstest floor 45 -> 47 (wgettest + etc dir).
- Root cause chain for `bad address 'deb.debian.org'`: busybox is
  STATIC GLIBC, and glibc's resolver (res_send.c reopen()) treats
  setsockopt(fd, SOL_IP, IP_RECVERR) failure as FATAL — aborts
  before connect(). It also needs SOCK_NONBLOCK accepted, UDP
  connect() peer-pinning, nonblocking recvfrom EAGAIN, and
  sendmmsg for the A+AAAA pair. Implemented:
  - OpenFile.nonblock (OFD-level like Linux file status flags —
    dup/fork share it); socket() accepts SOCK_NONBLOCK into it;
    fcntl F_GETFL reports accmode|O_APPEND|O_NONBLOCK, F_SETFL
    toggles APPEND+NONBLOCK (accmode bits ignored like Linux,
    stray status bits honest EINVAL).
  - UdpSock.peer + fd_connect UDP arm: instant peer pin, ephemeral
    bind like first-send, re-connect re-pins (no AF_UNSPEC
    disconnect — EAFNOSUPPORT on the unparsable family).
    udp_rx drops non-peer datagrams (covers queue + blocked-waiter).
    sendto(fd,buf,len,0,0,0)/write() on a connected socket targets
    the peer; sendto(addr) on connected -> EISCONN; send with no
    peer -> EDESTADDRREQ. getpeername reports the pin.
  - THE BUG: fd_socket compared RAW ty to 2 — SOCK_DGRAM|NONBLOCK
    (0o4002) minted a TCP socket, so every glibc resolver socket
    was TCP: sendto->EISCONN, connect->SYN to :53 ->ETIMEDOUT.
    Now `base = ty & 0x7` drives kind selection.
  - NR 46 sendmsg (iovec gather -> one datagram, bounded 1400;
    TCP arm streams segments; ancillary validated readable +
    dropped), NR 307 sendmmsg (per-entry sendmsg, msg_len written
    back at mmsghdr+56, stop-at-first-error), NR 54 setsockopt
    (ENOTSOCK non-socket, EFAULT unreadable optval, accept-and-drop
    otherwise — deliberate for IP_RECVERR & friends).
- TCP SYN retransmit: tcp_retx() rides the 100Hz tick — SynSent
  sockets re-fire SYN at Linux's initial-RTO 1s schedule doubling
  (RTO0 << syn_tries), cap 5. slirp DOES drop SYN/SYN-ACK under
  TCG load — single-shot connect() flaked wgettest to ETIMEDOUT
  twice in-suite; retransmission fixed it. TCP_CONN_TICKS (10s)
  still bounds the open.
- Frame-leak hunt (worth remembering): suite showed a hard 2-frame
  leak. Provenance instrumentation (per-frame caller table over the
  buddy, generation-tagged at the `before` snapshot) pinned it to
  vfile kmalloc — NOT a code bug: F_SETFL now working let htop
  actually WRITE ~/.config/htop/htoprc (previously "Invalid
  argument" at save), a persistent VFile holding 2 frames at reap.
  Fixed suite-side: htoptest unlinks the file post-wait like every
  other test cleans its scratch. Instrumentation removed; the
  kalloc FRAME_SRC pattern is documented here if needed again.
- audit run-104 (manual scoped — rubric + cve.now MCP still absent
  on this host): new user-pointer surfaces all funnel range_check
  (checked_add overflow-safe, VMA-bounded) — msghdr/iovec/mmsghdr/
  optval reads, gather bounded 1400, UIO_MAXIOV caps, msg_len
  writeback bounded. No confirmed findings. needs_validation:
  none new; re-verify with cve.now once configured.
- 66 tasks, frames 99886 -> 99886 zero leak, qemu exit 33 on BOTH
  `make run` and `make run-net`; wgettest 4/4 ok (wget exit 0,
  file, body, "Index of /debian" marker); nettest all ok;
  per-task exits diff-identical to run-130 baseline.
- Env note: firewall is OFF on this VM (ufw disabled, iptables/
  nftables empty ACCEPT) — was never blocking; git push still
  needs creds (credential.helper or SSH remote).
- Next: netlink route/addr surface (res_get_sort_addr path — glibc
  probes it post-resolve; currently ENOSYS nr 122/123 but non-fatal
  here), TCP data/FIN retransmission (SynSent covered; Estab
  retransmit still absent — matters for real WAN loss), then
  dpkg/apt prerequisites.

## run-132 — real .deb install: dpkg-deb extract + installed-binary exec

- `debtest` forks busybox `dpkg-deb -x /hello-traditional_2.10-6_amd64.deb
  /pkgout` — a genuine Debian package (ar container + xz data.tar) —
  then execs the freshly installed `/pkgout/usr/bin/hello` (DYNAMIC —
  loads through the staged /lib64 ld.so + libc), verifies the greeting
  over a capture pipe, and `rm -rf`s the tree. 9/9 checks, exit 0.
- Two kernel gaps stood between wget and this:
  1. pipe `fd_write` rejected `len > PIPE_SIZE` with EINVAL — the
     in-process unxz filter's 64KiB writes died instantly ("short read",
     nothing extracted). Now Linux semantics: <=PIPE_BUF atomic-or-block,
     larger writes take available room and return a short count; the
     waker copies only what fits and deposits the count in ctx.rax.
  2. `fs_lookup` only resolved initrd-archive names — installed
     (VFile-backed) binaries couldn't execve. New arm serves the vfile
     data buffer synchronously, same shadow order open() uses (vfile
     before archive).
- `MAX_VFILES` 32->128 and `VDIRS` literal 16->MAX_VDIRS 128 — the
  package's ~50 files + ~95 dirs (locale trees) overran both caps.
- 67 tasks, frames 100163 -> 100163 zero leak, qemu exit 33 on BOTH
  `make run` and `make run-net`; debtest/lstest all ok; per-task exits
  match the run-131 baseline profile.
- lstest floor 47->49 (debtest ELF + .deb record).
- Audit run-105 manual scoped (rubric + cve.now MCP absent — re-verify
  once configured): no confirmed findings; Dirty-Pipe class stays
  architecturally absent (private kernel ring). needs_validation: none.
  Inherited gap noted: pipe OFDs don't honor O_NONBLOCK yet.
- Env note: push still needs creds on this VM.
- Next: pipe O_NONBLOCK (EAGAIN), then dpkg proper (`dpkg-deb -x` is the
  payload path; `dpkg -i` adds maintainer scripts + /var/lib/dpkg status
  db — needs flock/fcntl locks, then `apt-get` needs method URIs + a
  real /var).

## run-133 — real `dpkg -i`: file locks + hardlinks + archive modes + futex bitsets

- `dpkgtest` forks real Debian `dpkg -i /hello-traditional_2.10-6_amd64.deb
  --force-depends` — genuine binary + libs staged in the initrd — then
  execs the installed `/usr/bin/hello`, checks `dpkg -l`/`status`, and
  removes tree + db. 0 failures; `linktest` adds 39 checks for the new
  ABI surface. Both green; 69 tasks, frames 100151 -> 100151 zero leak,
  qemu exit 33 on `make run` and `make run-net`.
- What real dpkg needed, in discovery order:
  1. **fcntl/flock file locks** — "unable to lock dpkg frontend lock":
     new bounded FLockReq table (64 slots, ENOLCK); POSIX vs OFD
     namespaces (owner = tgid vs ofd-index); byte ranges normalized
     (SEEK_SET/CUR/END, len==0 -> EOF); unlock splits ranges;
     F_SETLKW/F_OFD_SETLKW block via WaitOn::FLock, signal wake -> EINTR;
     locks swept on ANY fd close, CLOEXEC close, and task exit.
  2. **hardlinks** — dpkg links status -> status-old: VFile gained
     is_hard/hard alias slots sharing inode data+meta; link/linkat
     (NR86/265); nlink counts live names; EXDEV for archive members,
     EPERM dirs, EEXIST dest; unlinked-open inode survives to last
     close via alias+OFD pins in vfile_free_if_dead.
  3. **archive mode fidelity** — dpkg's file_is_exec rejected 0644:
     cpio c_mode parsed (entries_m), mkinitrd records source perms and
     forces 0111 on ELF payloads (incl .gz sources), stat reports real
     modes, access(W_OK) on archive members -> EROFS, execve enforces
     +x -> EACCES.
  4. **exec env cap** — dpkg exports >8 vars to children: ExecArgs moved
     to a 34KiB static .bss scratch (off the 8-16KiB kstack),
     MAX_EXEC_ENVS 8->64, E2BIG preserved.
  5. **futex bitsets** — libzstd's thread pool died on
     FUTEX_WAIT_BITSET ("futex facility returned an unexpected error
     code") truncating the data.tar stream: WAIT/WAKE_BITSET handled via
     op&0x7f, bitset collapsed to full-mask (wake-superset is
     Linux-legal).
  6. **utimensat NULL path** — GNU tar does utimensat(fd, NULL, ts, 0)
     = futimens; NULL at AT_FDCWD -> EFAULT, NOFOLLOW -> EINVAL.
  7. **vdir_rename** — dpkg's usr/share.dpkg-new -> usr/share move
     ENOENT'd; directory rename now rewrites the descendant prefix
     (ENOTEMPTY/ENOTDIR/EINVAL-into-self/self-noop like files).
  8. **sync_file_range** stub (flags masked, fd validated, returns 0 —
     pure writeback hint on a VFS with no writeback).
- Fixture pitfalls hit during probes: probe ESP must refresh BOTH kernel
  and initrd (stale kernel masked the lock path); solo cpios must stage
  /busybox at root or bb() helpers no-op; stale test binaries report
  test-side failures that vanish on rebuild.
- Audit run-106 manual scoped (cve.now MCP absent — re-verify once
  configured): lock identity/lifetime sound (live lock => live owner
  pin), alias pin prevents hard-index dangling, all new user buffers
  range-validated, mode checks fail-closed. needs_validation: none.
  Inherited gap still open: pipe OFDs ignore O_NONBLOCK.
- lstest floor 49->52 (linktest + dpkgtest + implicit sbin record).
- Env note: push still needs creds on this VM.
- Next: apt-get prerequisites (method URIs, /var layout, more coreutils
  surface — apt wants stty/dirname/head etc.) or alarm/setitimer to
  quiet busybox's enosys nr37; pipe O_NONBLOCK remains a small rung.

## run-134 — alarm/setitimer + the EXEC_BUF stale-argv0 regression fix

- `alarmtest` covers alarm(2)/setitimer/getitimer — 22/22 checks in
  suite: one-shot+pause EINTR, leftover reporting, disarm, periodic
  rearm, old/new itimerval round-trip, EINVAL/EFAULT matrix, VIRTUAL
  fires on user burn, fork non-inheritance. busybox's nr-37 enosys
  spam (wget progress watchdog) is gone.
- Per-task `itimers [[deadline,interval];3]` on three honest clocks:
  REAL=TICKS, VIRTUAL=utime, PROF=utime+stime (all already billed).
  `itimer_expire` in tick() pends the right signal through pend_one —
  wake/EINTR/sigwait semantics come free. Fork drops timers (fresh
  zeroed Task), exec preserves them, one-shot disarms, periodic rolls
  the deadline past-now without stacking expirations.
- REGRESSION FIX — run-133's shared `EXEC_BUF` broke every spawned
  glibc binary: `spawn_idx` copies argv[0] into argv[0][..n] but left
  byte n stale from the PREVIOUS spawn's longer name (faulttest ->
  fputest pushes "fputests" unterminated); glibc startup strrchr walks
  off stack_top -> #PF at 0x555600100000 for ~30 tasks. `exec_args_
  scratch()` now returns a cleared buffer — same semantics as the old
  stack-local empty(). Found by two-variable bisect (HEAD kernel +
  alarmtest initrd reproduced the storm — the bug predates run-134
  and had been masked by tail-only log greps + single-task probes).
- Suite-side source modes normalized: motd/resolv/winseed/.deb/
  terminfo -> 644, binaries -> 755 so run-133's recorded-mode stat
  matches intent (iotest "statx mode reg 0644" green again).
- 70 tasks, frames 100149 -> 100149 zero leak, qemu exit 33 on BOTH
  make run and make run-net; per-task exits match baseline profile.
- Audit run-107 manual scoped (cve.now MCP absent — re-verify once
  configured): no confirmed findings in the itimer surface; the
  EXEC_BUF poisoning is documented as a fixed regression (stale-state
  -> OOB-read-into-unmapped class). needs_validation: none.
- lstest floor 52->53 (alarmtest).
- Env note: push still needs creds on this VM. Verification lesson:
  grep FULL suite logs for "user fault"/"FAIL" — tails hide storms.
- Next: apt-get prerequisites (method URIs, /var layout, more
  coreutils surface) or pipe O_NONBLOCK (still the open small gap).

## run-135 — pipe O_NONBLOCK (the inherited gap, closed)

- `nbtest` covers the surface — 21/21 checks: pipe2(O_NONBLOCK),
  empty-read EAGAIN, atomic <=PIPE_BUF write EAGAIN, >PIPE_BUF short
  write with partial room, F_GETFL/F_SETFL flag round-trips, and a
  fork-proven blocking wake once nonblock is cleared.
- Implementation was small because the OFD already carries
  `nonblock` (UDP uses it): fd_pipe accepts the flag and mints both
  ends set; the read arm EAGAINs after the writers-EOF/len==0 checks
  and before the EFAULT/EINTR/block path; the write arm EAGAINs in
  the no-progress branch (atomicity rules unchanged).
- alarmtest's `getitimer remaining` check was racy under 71-task
  round-robin — armed 1s then slept >1s descheduled. Now arms 5s and
  asserts 0<r<=5s.
- 71 tasks, frames 100151 -> 100151 zero leak, qemu exit 33 on BOTH
  make run and make run-net; per-task exits match baseline.
- Audit run-108 manual scoped (cve.now MCP absent — re-verify once
  configured): no confirmed findings; errno ordering verified
  against Linux (EOF/EPIPE/EFAULT/EINTR precede the EAGAIN branch).
  needs_validation: none.
- lstest floor 53->54 (nbtest).
- Env note: push still needs creds on this VM.
- Next: apt-get prerequisites (method URIs, /var layout, more
  coreutils surface — apt wants stty/dirname/head etc.).
## run-136 — real Debian `apt-get update` end-to-end over slirp

- `aptprobe` (solo initrd via `make run-apt`) stages /etc/apt +
  /var/lib/apt, writes `[trusted=yes]` sources.list + resolv.conf,
  then execs the real dynamically linked `apt-get update`. Result:
  bookworm InRelease + 8.9MB compressed Packages index fetched over
  real DNS/TCP/HTTP, "Reading package lists... Done", exit(0).
- Kernel enablement, in the order apt exposed it:
  - e1000 per-frame TX printk removed (each line cost ~100ms of
    fbcon scroll — the whole stack ran at ~15kB/s); N_RX 8->64.
  - Window-update ACKs after the app drains rxb — without them the
    peer only relearned window space via its ~5s persist probe
    (~10kB/s); dup-ACKs now answer out-of-order and full-queue
    segments instead of silently dropping to RTO.
  - `TCP_RX_CAP` 2048->65536 with the buffer moved out of `TcpSock`
    into a `.bss` `RXBUF` — the 64KiB literal overflowed KSTACK.
  - `O_NONBLOCK`/`MSG_DONTWAIT` dropped for TCP recv (passed to UDP
    only): apt's method parked in recv forever on a completed
    stream. `dw` now threads into `tcp_recv_or_block` -> EAGAIN.
  - Armed-recheck lost-wakeup fixes: pipe read/write, TCP recv,
    poll, pselect, epoll all re-test after `wait_on`+`Blocked` are
    visible — a state change in the check-then-arm gap ran the
    waker with nobody home. pselect split into read-only
    `pselect_eval` + `pselect_write` so rescans can't corrupt the
    caller's input fd_sets.
  - getsockopt NR55 (SO_TYPE/SO_ERROR, optlen round-trip).
  - `VFILE_MAX` 1MiB->32MiB, buddy `MAX_ORDER` 11->14 for the index
    files; vfile_grow's ncap is kmalloc-header-aware
    (pow2(need+16)-16) only above the 4KiB slab cutoff.
- REGRESSION FIXED IN-RUNG — the first header-aware formula
  `pow2(need)-16` under-allocated `cap` below `need` on exact-pow2
  sizes: a 16B overwrite wrote Release-file text into a freed
  block's freelist link -> kmalloc dereferenced "/binary-" -> #GP.
  Corrected formula keeps cap>=need; over-cap requests degrade to
  honest ENOSPC via the order>=MAX_ORDER guard.
- apt config carries `Acquire::GzipIndexes` (index stays ~8.9MB
  compressed, uncompressed ~60MB exceeds VFILE_MAX),
  `APT::Cache-Start 100MB` (mmap pool), and empty
  pkgcache/srcpkgcache (36MB persistent cache would not fit).
- Expected non-zero exits: gpgv 111 (no apt-key/keyring staged —
  trusted=yes carries through), http method 100 after completed
  transfers (apt-tolerated).
- `kernel/user/aptroot/` stages the real Debian apt binaries +
  methods + lib closure + dpkg tables (copied from host
  /usr/share/dpkg for reproducibility).
- 71 tasks, frames 99745 -> 99745 zero leak, qemu exit 33 on make
  run, make run-net AND make run-apt; per-task exits match baseline.
- Audit run-109 manual scoped + cve.now reached over HTTP JSON-RPC
  this rung (MCP unconfigured locally): the size-miscalculation
  heap-overflow class (CVE-2022-0185, CVE-2021-43267 analogs) is
  exactly what the ncap fix closed; UAF/freelist-corruption class
  CVE-2024-39510; race-window class CVE-2016-8655 (lost-wakeups are
  availability-only here, no UAF). Verified: cap>=need invariant,
  getsockopt bounded <=4B write after optlen read+write checks,
  every recheck disarm clears wait_on/deadline and restores sigmask,
  RXBUF slots zeroed on reuse, wnd patch stays inside the TCP hdr
  with re-sealed checksum. needs_validation: none.
- lstest floor unchanged (aptprobe is a solo initrd, not a suite
  task). Env note: push still needs creds on this VM.
- Next: apt-get install/download path (gpgv proper + keyring for
  real signature checks, https method, more coreutils surface).

## run-137 — real Debian `apt-get install hello-traditional` end-to-end

- The same solo `aptprobe` initrd now continues past `update`:
  `apt-get install -y hello-traditional` downloads the real
  56.8 kB .deb, real `dpkg` unpacks + configures it ("Unpacking
  hello-traditional (2.10-6) ...", "Setting up ..."), and the
  freshly installed `/usr/bin/hello` execs and prints
  "Hello, world!". aptprobe: 0 failures, qemu exit 33.
- Three gaps surfaced and closed, in order:
  - apt's input-feeder child (forked apt-get, never execs) parked
    on `WaitOn::Stdin` forever — `Dpkg::Use-Pty "false"` alone does
    not suppress it. Fix is real-world headless-install semantics:
    the probe dup2s `/dev/null` onto stdin for spawned commands, so
    the feeder and any conffile read see immediate EOF. No kernel
    change needed — a scripted apt with tty stdin would block on
    Linux too.
  - dpkg's startup PATH check wants rm, tar, diff, dpkg-deb,
    ldconfig, start-stop-daemon, dpkg-split (and dpkg-query for
    later stages). Probe children now execve with
    PATH=/sbin:/usr/sbin:/bin:/usr/bin and the apt initrd mirrors
    the main initrd's proven toolchain: real dpkg-deb/dpkg-split/
    dpkg-query/tar/ldconfig, busybox as rm/diff/ssd, plus libacl
    and libz for tar/dpkg-deb.
  - wait4 lost-wakeup: same check-then-arm window as the run-136
    batch — a child exiting between the relevance scan and the
    Blocked arming ran the wake loop with nobody home. The scan is
    now `wait4_collect`, called on entry and again after arming;
    the recheck either collects (disarm + return) or observes the
    delivered wake (Runnable, pid in rax).
- Frame retention on the solo probe (~8.4k frames at shutdown) is
  the ramfs-resident apt state (lists + .deb + installed files) —
  live fs objects, not a task leak; `make run`/`run-net` stay
  zero-leak.
- Validation: make run exit 33 99747->99747; make run-net exit 33
  99750->99750 real DNS/TCP/HTTP/wget; make run-apt exit 33,
  aptprobe 0 failures; clippy 57 warnings before and after the
  diff (none on touched lines).
- Next: PTY layer (apt's PtyFeed/term.log still wants /dev/ptmx —
  masked by stdin redirect for now), gpgv+keyring for real sig
  checks, https method, maintainer-script .debs (postinst/prerm
  via bin/sh), and a fuller coreutils/dpkg surface.

## run-138 — Unix98 PTY layer (`/dev/ptmx` + `dev/pts/N`) + apt's real pty path

- `/dev/ptmx` (rdev 5,2) mints a pair per open: a private master
  node `dev/ptm/N` (rdev 128,N — the Unix98 ptm major) and a
  `dev/pts/N` slave node (rdev 136,N); the index rides the rdev
  minor exactly like Linux. Pairs are two pipe rings + lock flag +
  open counts (MAX_PTYS 4).
- Slave opens EIO while locked; unlockpt flips the flag. Ioctl
  surface: TIOCGPTN, TIOCSPTLCK, TIOCGPTPEER (mints a second slave
  fd — 0x5441 plain _IO, not the direction-encoded variant),
  TIOCSCTTY, TIOCGWINSZ, termios round-trip; FIONREAD reports ring
  depth. Reads/writes ride the pipe arms with tty-hangup EIO when
  the peer count hits zero; the last close retires the pair — rings
  freed, node names unlinked, index reusable.
- `fd_is_console` narrowed so ptmx fds stop routing through the
  system console. `ptytest` 23 checks: allocation, tty identity,
  ptsname match, locked-slave EIO, TIOCGPTPEER, bidirectional
  transfer, poll readiness, termios, hangup EIO both directions,
  index reuse.
- apt's real pty path now runs: `Dpkg::Use-Pty "true"` +
  posix_openpt succeeds, dpkg's output pty feeds term.log, install
  completes with zero soft errors (the TIOCSCTTY message from the
  first run is implemented, not suppressed). The /dev/null stdin
  redirect stays — it feeds apt's PtyFeed child EOF, orthogonal to
  the dpkg-side pty.
- Known open item: an intermittent suite flake (~1-in-4 runs) —
  slave-side write returns EIO before the explicit master close,
  i.e. the pair's mopen counted to zero early. Reproduced with the
  checke errno instrumentation; mechanism narrowed to open-count
  or OFD-lifecycle accounting, not the ring path. Clean runs pass
  all 24 checks with zero leak; the affected run leaked 2 frames
  (the two rings). Under investigation for the next rung.

## run-139 — ATA PIO block driver + `/dev/sda` + bootable live/install ISO

- `kernel/src/ata.rs`: polled ATA PIO on the primary channel
  (0x1F0/0x3F6) — IDENTIFY probe, LBA28 READ/WRITE SECTORS, one
  FLUSH CACHE per multi-sector command (the first cut flushed per
  sector — ~7ms each, install took minutes), capacity clamped to
  the 28-bit LBA space so a large disk can't alias. Up to 256
  sectors per command.
- `/dev/sda` is a real S_IFBLK node (rdev 8<<8) minted only when
  the probe found a disk; a crafted node on major 8 without
  hardware opens ENXIO. fd_read/fd_write do byte-range I/O at the
  OFD position — aligned runs write straight from the user buffer
  (one command per 256 sectors), unaligned edges read-modify-write
  through a kernel bounce; reads clip at capacity, writes short
  or ENOSPC. lseek works on the node (SEEK_END = capacity).
- `demomenu` is the demo pid1: banner + `[1] live session`
  (fork/exec /bin/sh, back to menu on exit) + `[2] install` —
  streams `/hd.img` to /dev/sda, verifies the first sector back,
  `reboot(RB_AUTOBOOT)` resets through 0xCF9. On the installed
  boot /hd.img is absent so the option hides itself.
- Build chain: initrd-live.cpio (demomenu + busybox sh/reboot/
  poweroff + bash + libc/ld + motd) -> hd.img 24MiB FAT16
  (kernel + live initrd; mformat auto-FAT16 — OVMF's hard-disk
  path rejects the undersized FAT32 a `-F` forces at 24MiB) ->
  initrd-iso.cpio (live + hd.img) -> esp-iso.img 48MiB ->
  rustux-demo.iso via genisoimage `-efi-boot -no-emul-boot`.
  `make run-iso` proves it headlessly: phase 1 boots the ISO,
  monitor-sendkey presses 2 (piped stdio never reaches the guest
  UART — the PS/2 path is the honest one anyway), installer
  writes + verifies + reboots; phase 2 boots target.img, sendkey
  1 lands in busybox ash — both greps PASS.
- The ATA driver wants the i440fx IDE channel, so the ISO targets
  `-machine pc`; q35 puts IDE drives behind AHCI.
- Validation: make run-iso both phases PASS; written image
  byte-identical to hd.img (first 24MiB), mtools lists
  EFI/+initrd on target.img; make run exit 33 — but see run-138's
  flake note (this run hit it: ptytest EIO + 2-frame leak; the
  ata path was inert — 'ata: no disk' on q35).

## run-140 — install prompt/eject flow + MAX_READ + ATA recovery

- `demomenu` no longer reboots instantly: install verifies the
  first sector, issues CDROMEJECT on `/dev/sr0` (ATAPI START STOP
  UNIT, LoEj — the real installer's "remove the media" step on
  QEMU's secondary-channel -cdrom), prints the success banner and
  blocks on ENTER before `reboot(RB_AUTOBOOT)`. The window can't
  vanish mid-flow anymore.
- `/dev/sr0` (S_IFBLK rdev 11<<8) is minted unconditionally —
  a node without hardware is normal; open() whitelists major 11,
  read/write answer ENXIO, ioctl CDROMEJECT (0x5309) is gated to
  the exact rdev (ENOTTY elsewhere) and returns EIO with no drive.
- The apparent "install stall" was never a wedge — it was TCG time
  dilation (~20x) plus a 4KiB-per-syscall read cap: `MAX_COPY`
  clamped NR_READ so each 64KiB chunk took 16 read+write cycles
  with a FLUSH each (~6k flushes per install). `MAX_READ` = 1MiB
  now bounds NR_READ separately (every fd_read arm already min()s
  against available data; MAX_COPY stays for path/copy buffers),
  and copy_image loops short reads to fill 64KiB before writing —
  ~190 flushes total, install finishes in seconds of guest time.
- `ata.rs` hardening from the stall hunt (kept — all real spec
  work): post-command 400ns settle (4x ALT reads) since status is
  undefined before it; bounded polls bail with a printk diagnostic;
  SRST device-reset recovery plus one retry in ata::write so a
  transient desync can't fail a write; eject() does ATAPI PACKET
  with a fixed START STOP UNIT CDB and bounded DRQ wait.
- run-iso is now one QEMU session: `once=d,order=c`, wait for the
  prompt, monitor `eject -f ide1-cd0`, sendkey ret, then verify the
  installed boot shows the live-only menu + busybox `/ #`. The
  monitor eject is required in-session — QEMU reattaches the ISO
  medium on device reset and OVMF's boot selection persists, so
  the guest-side ATAPI eject alone can't survive the reboot
  (correct on real hardware). Sendkey windows widened to match
  TCG dilation (16x15s install / 12x15s installed-boot phases).
- Temporary tick-heartbeat RIP diagnostics removed (the hunt that
  found the capped-read root cause); clippy 57 = baseline.
- Validation: make run-iso both phases PASS — log shows one
  DVD-ROM boot (initial ISO), install writes 24MiB + verify ok +
  medium ejected + ENTER prompt, then the installed disk boots
  to `[1] live session` only and a busybox `/ #` shell. make run
  exit 33, 72 tasks, frames 99744 -> 99744 zero leak, ptytest
  all 24 checks (the run-138 flake did not reproduce this run).

## run-141 — live payload: bash/htop/apt + cpio symlinks + /proc task + fbcon REP

- The demo ISO's live session is now a real Debian-flavored system:
  bash login shell (TERM/TERMINFO/HOME/PATH env), htop with its
  ncursesw/tinfo/libm/libnl deps + xterm terminfo, 50+ busybox
  applets as mkinitrd `link:` symlink records (one 2.8MB busybox
  copy instead of N), and the full apt/dpkg toolchain (apt-get,
  apt-helper, gpgv, http/store/copy/file methods, dpkg + dpkg-deb/
  query/split, real GNU tar, ldconfig, dpkg arch tables, ~30 libs,
  /etc/apt sources.list + 99rustux config, resolv.conf). ISO QEMU
  invocations gain slirp + e1000e so the NIC exists on demo media.
- `resolve_links` now follows initrd cpio S_IFLNK entries, not just
  VFile links — a `link:` record's data is the raw target text,
  resolved through the same 40-hop ELOOP/256-byte-name discipline
  as VFS links. This is what was missing for every applet link:
  `/bin/ls` exec'd the literal text "/bin/busybox" before (ls, df,
  top, ps — all dead); now multicall resolves argv[0] correctly.
  The lstat/readlink `fl` flag reports cpio links too.
- `/proc/<pid>/task` — htop's per-pid thread-group enumeration:
  PROC_TFILES gains task/, ProcEnt parses task/<tid>/<leaf>,
  dir_exists + getdents enumerate the group's TIDs and the leaf
  set per TID. htop showed an empty process list without it
  (busybox top's simpler proc walk masked the gap).
- fbcon gains REP (CSI Ps b — repeat last graphic char, bounded to
  cols*rows via a tracked last_glyph) — htop's meter bars paint
  their full width now instead of a single cell.
- MAX_INITRD 64->128 MiB: the ISO initrd carries the 48MiB hd.img
  install payload on top of the live rootfs (~81MiB) — the guard
  tripped and the kernel fell back to the embedded ELF.
- MAX_VFILES 128->1024 / MAX_VDIRS 128->512: a real `apt install`
  dep-set extracts several hundred names; 128 slots ENOSPC'd
  mid-libc6. Still bounded — an honest ENOSPC, ~300KB static.
- demomenu seeds /var/lib/dpkg/status marking every staged .so as
  installed (libc6 + dep set + ncurses/libnl for htop leaves) —
  without it apt tries to install libc6 for real and dpkg's
  backup-link step fails EXDEV on the cpio-backed staged file.
  Same pattern aptprobe already proved. Known divergence noted:
  hardlinking an initrd file is EXDEV — a real copy-up is roadmap.
- Boot selection pinned with device bootindex (CD 0, disk 1) +
  order=dc — OVMF's NVRAM-cached BootOrder ignores once= across
  sessions, which made the installed disk win over the media.
- QEMU -m 512M -> 1G everywhere: 81MiB initrd + ramfs extract
  headroom; the 512M guest vfile-ENOSPC'd mid-libc6.
- Verified live: `ls /` colored applet output, `df -h` real statfs,
  `apt-get --version` (apt 2.8.4), `apt update` (bookworm InRelease
  + 8.8MB Packages, dep tree built), `apt install hello-traditional`
  (leaf-only fetch, dpkg unpack+configure under the pty), and
  `/usr/bin/hello` prints "Hello, world!". htop paints Tasks/bars
  with SGR colors on the fb console.
- Validation: make run exit 33, 72 tasks; first run hit the known
  run-138 pty flake (2 frames), clean rerun 214361 -> 214361 zero
  leak. clippy 58 = baseline, none in touched regions.
- Scoped audit (quick): resolve_links cpio-link hop reuses the
  bounded tgt/cur buffers + ELOOP cap; cve.now entities.search —
  CVE-2024-53142 (initramfs name overrun, re-validated: same strict
  parser feeds entries_m) and CVE-2023-3161 (fbcon font-size OOB —
  structurally absent, fixed 8x16 font, REP bounded). needs_validation:
  run-138 pty flake stands.

## run-142 — fbcon CSI param fix + real login chain

- fbcon CSI parser: multi-digit params were split one digit per
  slot (nparams used as the index), so \e[50;1H -> row 4,
  \e[36m -> params [3,6] = no color, \e[1;50r -> scroll region
  rows 0-4 = whole-screen scramble. Digits now accumulate into
  the current param; ';' counts empty leading params. One bug,
  every symptom (no colors, floating F-bar, mangled layout).
- SGR bold is now persistent (self.bold) — ncurses emits
  \e[0;1m\e[30m for bright black; the old one-shot bump was lost
  on the following 30..37, rendering bar values/`kthr` invisible.
- Tick accounting: kernel-CS frames billed stime to cur
  unconditionally — the hlt-idle loop is kernel CS, so every
  idle tick landed on the last task (htop showed 100%). Now only
  billed when cur is Runnable (real preempted syscall frame).
- stdin_echo printk -> log::user_out: echo was rendering one
  timestamped log record per char; now verbatim console bytes.
- setfsuid(122)/setfsgid(123) -> 0: bash's startup probes
  stopped spamming enosys records.
- demomenu -> livemenu (rename everywhere). pid1 flow split:
  media boot (hd.img in initrd) shows the menu; an installed
  disk has no payload -> straight to login, no menu. Menu is
  media-only per request.
- Authentication: run_login does real /etc/passwd + /etc/shadow
  lookup with crypt() verification (libcrypt.a, $6$ SHA-512),
  termios ECHO-off password read, constant-shape "Login
  incorrect"; success sets HOME/USER/SHELL/PATH env and execs
  the account shell. root/rustux seeded via openssl passwd -6.
  whoami/id/logname/groups links; /etc/passwd existing gives
  htop USER=root. busybox login applet was tried first — it
  fails auth then #GP-crashes on retry (kernel ABI gap, tracked).
- Suite: 72 tasks, exit 33, zero leak; ISO boot -> menu ->
  login -> bash verified; installed disk -> login -> bash.

## run-143/144 — boot-media compatibility + console fault visibility
- initrd task scan no longer prints "skipped (data file)" per
  archive entry — hundreds of printk lines flooded the console and
  serial for several minutes of real time on the 81MiB live payload.
- load_initrd tries four name variants (initrd.cpio/INITRD.CPIO/
  initrd.cpi/INITRD.CPI): a FAT ESP keeps the long name, a bare
  ISO9660 view truncates to 8.3. Whichever filesystem firmware
  mounts, the archive resolves.
- ISO is now distro-structure via xorriso: El Torito BIOS default
  entry (512B boot stub, info-table) + UEFI alt entry (esp.img),
  isohybrid MBR (gptmbr.bin) + GPT marking /esp.img, plus
  /EFI/BOOT/BOOTX64.EFI and /initrd.cpio as plain ISO9660 files —
  covers El Torito-only, partition-scanning, and file-scanning
  firmware. 175MiB (initrd carried twice, once in esp.img once as
  ISO9660 data — required for both paths).
- cpu.rs: user faults AND kernel EXCEPTION reports now mirror to the
  framebuffer console (printk+drain_task), not serial-only — a
  faulting task or kernel oops is visible on serial-less machines
  (VMware, bare metal). IDT gates are 0x8e (IF cleared), same
  masking discipline drain_task already documents.
- VMware finding recorded: kernel boots fine under Workstation UEFI;
  userspace previously stalled after `task livemenu: queued` with
  zero console evidence (the fault line was serial-only). Console
  mirroring is the diagnostic that splits scheduling-stall vs
  fault-on-entry; awaiting field data.
- Committed locally; source push held pending user ISO test.

## run-145 — /dev/fb0 fbdev + DOOM proof-of-concept
- GOP framebuffer exposed as /dev/fb0 (Linux fb major 29): char node
  minted in dev_init, open ENXIO when no fb, positional read/write
  clamped to min(GOP map size, stride*height) — the upstream fbdev
  smem_len hardening class; SEEK_END = fb byte length; ioctls
  FBIOGET_VSCREENINFO (160B var, honest BGR-vs-RGB channel offsets)
  and FBIOGET_FSCREENINFO (smem_len, line_length, TRUECOLOR visual),
  rdev-exact ENOTTY gate.
- Accessors: FbConsole.fb_{info,byte_len,write_at,read_at} +
  log::fb_* through PANIC_CON (same sole-drainer argument as
  user_out — syscall context has IF masked).
- doom_rustux.c shim for doomgeneric (GPL'd original id source,
  vendored under third_party/): FBIOGET probes, integer scale
  (640x400 -> 1280x800 @2x), one lseek+write per composed frame;
  keys stubbed (attract mode needs none); -iwad /doom.wad.
- DOOM.WAD is copyrighted — NOT committed; .gitignore covers
  doom.wad/initrd-doom.cpio/esp-doom.img; `make run-doom` builds and
  boots a solo-task ESP. Verified on-screen under OVMF: registered
  DOOM banner, WAD load, E1M1 attract demo rendering at full speed.
- cve.now MCP + security-audit skill unavailable this session;
  scoped review done manually and recorded in the matrix row.
- Committed locally; push held pending user test.

## run-146 — /dev/input/event0 evdev + playable DOOM
- kbd.rs: parallel evdev tap — poll() pushes (Linux keycode, press/release)
  into a bounded 64-entry ring for every decoded scancode: plain makes,
  plain breaks (releases preserved — the tty path ignores them, evdev
  needs them), and E0 extended codes via ev_e0() (arrows, nav, right
  ctrl/alt, meta, KP enter/slash). Set-1 scancode == Linux keycode for
  unextended keys.
- /dev/input + /dev/input/event0 (major 13, rdev 0xd40) in dev_init;
  open whitelist arm `13 => i`; read: len<24 -> EINVAL like Linux,
  O_NONBLOCK -> EAGAIN, else WaitOn::Evdev + evdev_wake() marshals
  24-byte struct input_event {sec,usec,type=EV_KEY,code,value}
  records through the sleeper's own tables (stdin_wake discipline,
  EFAULT on vanished pages); direct path caps validation to the actual
  write span (queued*24 min len) — partial-buffer tail never probed.
- stdin_pump calls evdev_wake() every tick and counts pending events
  as input-change for wake_pollers; poll() reports POLLIN on queued
  records; EVIOCGNAME returns "Rustux PS/2 keyboard"; lseek = noop.
- doom_rustux.c: event0 O_RDONLY|O_NONBLOCK, full LKEY_* table ->
  doomkeys (ctrl->KEY_FIRE since doomgeneric binds key_fire to the
  abstract 0xa3, space->KEY_USE, alt->strafe, shift->run, arrows,
  F1-F10, keypad/nav, printable ascii) into a 64-entry pending ring —
  DG_GetKey returns one (pressed,doomKey) per call.
- Verified under OVMF on rustux-doom.iso: ESC opens the menu, Enter
  navigates New Game -> episode -> skill into real E1M1, arrows move/
  turn, ctrl fires (ammo 50->46 across held presses), ESC reopens the
  menu in-game. Tap-length caveat: a sub-tic press+release coalesces
  like real DOOM — use hold_ms with sendkey.
- cve.now MCP now configured: evdev classes checked (CVE-2026-74673
  infoleak — records fully initialized; CVE-2026-74683/98205 — ioctls
  absent/ENOTTY). security-audit skill still not installed; manual
  scoped review recorded. One audit fix landed this rung (write-span
  validation). Committed locally; push held pending user test.

## run-147 — scheduler diagnostics for the VMware stall
- `rustux: sched: launch <exe> (pid N) rip=` at first task entry + `no runnable task` fallback; per-slot `first syscall nr=X` bitmap; `rustux: beat t= cur= pit= kbd= net=` every 500 ticks — all screen-visible
- VMware repro attempt with `-cpu max` showed no stall (menu reached); diagnostics deployed so a VMware boot photo now names the dead stage instead of `livemenu: queued` + silence
- audit: safe-anything CLI scoped (security-audit skill still absent); cve.now no mapped class; no findings; run-138 pty flake still open
- `make run` PASS exit 33, 72 tasks, frames 214361 -> 214361 zero leak; rustux-demo.iso rebuilt with the instrumented kernel for the next VMware boot test
- next: VMware boot with the diagnostic ISO -> whichever stage the markers stop at is the fix target; then BIOS loader (16-bit + E820 + VBE + bios_entry); DOS personality (v86 + DPMI + int 21h + VGA 13h) for the real DOOM.EXE; pty ofd_release EIO flake

## pending user tests
- rustux-demo.iso (diagnostic build, commit a0c8b57 kernel) in VMware: boot it, photograph the screen — the sched: launch / first-syscall / beat markers name the dead stage. Pending as of run-147.

## run-148 — legacy BIOS boot via GRUB Multiboot2
- kernel/src/bios.rs + bios.ld: kernel builds for x86_64-unknown-none as
  a static 1 MiB ELF with an MB2 header; GRUB i386-pc (grub-mkrescue)
  handles real mode/A20/E820/VBE/disk; a .code32 trampoline switches to
  long mode on a 6-page boot pml4 (4 GiB identity), bios_entry parses
  MB2 tags (mmap->MapEnt, fb->FbDesc, module->initrd, RSDP 14/15 or
  0xE0000 scan) into the same normalized inputs UEFI builds —
  rustux_main is now front-end-agnostic (BOOT_ENTS/FbDesc/extra_reserved).
- Root-cause fixes this rung:
  - asm<->Rust ABI: x86_64-unknown-none is SysV while every stub passes
    args in rcx/rdx (win64). report_frame/sched_tick_frame/handle_syscall
    + the syscall.rs extern block are now extern "win64". Before this,
    sched_tick_frame returned garbage -> `mov rsp,rax` into .bss statics
    -> PRB ring destroyed + ASCII-filled fault dumps + vec 0x16.
  - resv alignment: the MB2 module end is unaligned; add_range seeded
    buddy blocks from that unaligned base -> corrupt free lists ->
    garbage frame -> noncanonical memcpy in map_loads (#GP). extra_
    reserved now rounds start-down/end-up before subtraction.
  - page-table carve: was at the START of the largest region (0x100000 =
    the kernel image itself under BIOS); now carved from the region END
    and capped <4 GiB (trampoline only identity-maps 4 GiB).
  - Cargo.toml gates uefi dep to target_os=uefi; acpi provide_rsdp;
    fbcon from_desc splits construction from GOP discovery.
- `make run-bios`: SeaBIOS -> GRUB -> multiboot2 -> full 72-task suite,
  exit 33, frames 246152 -> 246152 zero leak. UEFI `make run` still PASS
  (frames 214356 -> 214356). Note: GRUB's int13 read of the 55MB initrd
  takes ~70-90s under QEMU TCG — real BIOS/VMware hardware loads it
  fast; not a hang.
- Audit: safe-anything MCP scoped scan clean; one real fix in review
  (mmap entry_size floor 16->20 — CVE-2026-31613 pattern). cve.now
  checked firmware-parsing classes; GRUB2's own CVEs are build-time
  tooling, out of scope. security-audit skill still absent — recorded.
- Serial markers: tramp prints A/B/C/D on COM1 per stage (kept — only
  visibility into pre-console BIOS bring-up); the F/V/I/T/R dbg_mark
  probes and buddy canaries were debug scaffolding, all removed.
- next: VMware boot with the diagnostic ISO (still the open user test);
  DOS personality (v86 + DPMI + int 21h + VGA 13h) for real DOOM.EXE;
  pty ofd_release EIO flake.

## run-149 — DOS16M kernel deep-dive in tools/dosemu (untracked research harness)
- Goal: boot DOOM.EXE's *authentic* DOS16M stub (not the direct-LE path).
  The stub loads its own resident kernel (file 0x400-0xa290 -> 0x400,
  0xa290-0x10000 -> 0xa090), self-relocates to para 0x2238, lgdt/lidt
  itself (standalone, no DPMI host), runs 16-bit PM.
- Emulator bugs fixed this session:
  - guest-IDT: kernel executes `lidt base=0` in PM deliberately (overlays
    its IDT on the IVT). soft_int now bypasses the guest IDT for software
    ints >=0x20 -> native svc; only exceptions/<0x20 consult it with
    strict gate-type validation. int21 file I/O works.
  - int31 0x0300/0x0301/0x0302: register clobber (struct eax/ebx read
    before dispatch) fixed; real PM->RM->PM round-trip implemented
    (rmcall_pending/frame/sentinel + step() return hook; 0x301 copies cx
    param words below the iret frame). Kernel RM-call struct layout
    confirmed: dwords edi..eax @+0..0x1c, then fl@+0x20, es@+0x22,
    ds@+0x24, ip@+0x28, cs@+0x2a, sp@+0x2c, ss@+0x2e.
  - PM far-transfer RM reflect (load_seg rm_seg): the operand's "segment"
    is resolved via the descriptor — present sel -> desc_base, else
    paragraph sel<<4, null -> 0. Fixes the DOS16M stack-trampoline idiom
    (call far {bp-0xa, ss=0x20} -> RM 0:off). PM->RM->PM round trip now
    completes cleanly (verified: int15 trampoline -> retf -> PM resume).
  - svc vector seed: call far [ds:0x1e] gets off=0x7344 (proven kernel
    dispatcher; builds task frame, int31/302 to IVT[svc#]).
  - DOS16M service-vector template: file 0x1c-0x47 = {off,seg} entries
    (offs 0x2800/0x8c09/0x9409/...) copied to IVT at load; kernel reloc
    loop patches seg halves to the relocated para. int15 AH=0x31 stubbed
    CF=0 (kernel probe service).
- Current blocker: after the int15 svc returns, the caller function's
  epilogue `leave; ret` pops a corrupt return off (0x20 -> executes IDT
  bytes -> hlt). The frame was already wrong entering the unwind —
  consistent with the never-run DOS16M task/DPMI-variant init (service
  tables at ds:0xf6a empty, task switcher scratch cs:0x1f90 zero, no
  int21/25 vector hooks installed). Next: find the standalone-mode init
  that populates task state, or synthesize the current-task record.
- Vector table decode (Rosetta): entries @0x1e,0x22,0x26..4-byte {off,seg};
  callf[ds:0x22]->2238:7344 = generic svc dispatcher ([bp+6]=svc#,
  IVT[svc*4] via ds:0xc2c flat = the IVT itself). int15 AH=0x31 in the
  stack trampoline = "invoke RM int15 svc" via the kernel's reg-frame
  wrapper at kernrm 0x41fc (int#=[bp+4] al).
- audit: safe-anything scoped on tools/dosemu/dosemu.c — clean, no
  findings (untracked scratch tooling); cve.now entities.search "DOS
  emulator DPMI extender" — no mapped class. security-audit skill still
  absent; safe-anything MCP used per run-148 precedent.

## run-150 — DOS16M sel-0x88 resolved: kernel runs end-to-end to app entry
- Root cause of the "corrupt unwind" from run-149: NOT a task-init bug.
  The PM kernel hardcodes `call far 0x88:0x30f9` (its RM-code dispatch);
  sel 0x88's GDT slot is empty in the template — DOS16M expects it
  populated at runtime with a code16 descriptor for the RELOCATED RM
  kernel image. With it empty, para-synth gave base 0x880 -> executed the
  LOW kernrm copy whose `leave;ret` popped pushed-ds (0x20) -> IDT -> hlt.
- Relocated image discovery: kernrm exists twice in guest — low copy at
  0x400 (file image) and a 1:1 relocated copy at image base 0x20bb0
  (para 0x20bb). ds:0x20=0x2238 = image offset 0x17d0 (the RM/PM twin
  delta). Signature-match: routine `26 8b 77 06` at 0x3979 and 0x24129;
  delta 0x207b0 -> image base 0x20bb0.
- Fix: SELMAP=sel:base env writes a present code16 descriptor {lim ffff}
  into the guest GDT at lgdt time (dosemu.c ~line 1746). SELMAP=88:20bb0
  -> pmcs resolves 88:->20bb0, RM->PM restore keeps the base.
- Result — kernel runs END TO END: svc call -> pathscan routine
  (0x23ca9, filename canonicalization) -> ret->0x20 -> relocated 0x20bd0
  (0x27-entry vector seg-patch loop — real code) -> more svc calls ->
  int15 ax=0x8700 block-move (app -> XMS copy) -> DPMI-client init block
  RUNS (int31/0x204 get-vector, IVT writes, f000:xxx stub construction)
  -> RM->PM raw-mode-switch stub (f000:fba0: push edx(cs);push eax(eip);
  retfd) -> lands in app at cs=0xab1.
- New blocker: retfd pops eip=0xd22b0646 (garbage eax — the app entry
  eip read/loaded wrong; cs=0xab1 = app para is CORRECT). Executes ~90
  insns in wrapped high-mem fetch then int1. Suspect: app entry eip not
  staged — likely an int31 service result or task-record field we stub.
- The DPMI-client path activated because int2f/1687 reports a DPMI host —
  the kernel prefers it over standalone init; earlier "missing task init"
  was the right diagnosis, wrong cause: it IS reached, via relocation.
  - eip masking (NEW BUG FIX): a retfd/32-bit far frame into a use16
    code seg leaves garbage in eip high bits; real hw fetches via IP.
    step() now masks cpu.eip &= 0xffff when !cpu.big — retfd 0xd22b0646
    -> 0x0646 lands in the app. App 16-bit code at cs=0xab1 runs REAL
    routines (rep movsb, pusha, stack ops) and far-calls a second app
    segment cs=0xa850 — which holds a data table, not code: the app's
    callf[ds:0x22] service-vector entry points at misplaced content
    (downstream of the int15/0x87 svc frame or LE object placement).
  - int15/0x87 probe shows es:si points at CODE, not a block-move GDT —
    DOS16M's int15 usage is its own svc ABI, not the BIOS one; stubbed
    benign (CF=0, no write).
  - Open: app obj placement / service-vector resolution for a850:0x629;
    entry-eip dword 0xd22b0646 low word 0x0646 worked because of the
    use16 mask, but whether the kernel intended 0x0646 is unverified.
  - audit: safe-anything scoped on tools/dosemu — clean; cve.now
    "DOS emulator DPMI extender" — no mapped CVE class (run-149 same).

## run-151 — DOS16M app svc-vectors resolved: app init runs ~24K insns
- The run-150 blocker (callf[ds:0x22] -> a850:data) was a TWO-part decode:
  - [cs] print shows STALE cpu.eip — the "0629" was the call-site's own
    offset, not the target. Real read: {off=0x0ba5, sel=0xa850}.
  - The app's svc-vector table at ds:0x16-0x48 of a task DGROUP is
    file-borne (file 0x983fc, verbatim in guest) — entries {off,seg} with
    correct kernel-routine OFFS but stale link-time paragraph SEGS
    (0xba1/0xba5/0xa850...). Kernel bind should have patched seg to the
    resident-kernel code para but never did.
- Resident kernel code para = 0x21bd (guest base 0x21bd0; kernrm file
  0x21c5 -> guest 0x22775, a second copy at 0x21fc5). ALL ~16 vector
  offs land on real kernel routines at 21bd:off — int21 wrappers,
  port-I/O services (out 0x140/0x92/0xf0/0xf2), frame-init routines.
  Verified by disasm: 0xba5 = port svc (in 0xf2,cmp ds:0x2f,out 0x140).
- KEY ABI: the kernel svc routines are NEAR-callable (end `c3`), invoked
  via the far-vector callf[ds:0xNN] — DOS16M's service-call idiom is a
  far ptr to a routine that returns NEAR inside the kernel seg. Plain
  far call mis-returns (near ret pops only ip -> stays in kernel seg).
- Fix — synthetic near-call: when a far-ptr read lands on dead/zero
  target but off maps to kernel code at 0x21bd, do NOT far-call. Instead
  push {ocs, ret} far frame then push a synthetic near-ret to an
  in-kernel `retf` stub (0x52cc = `...c9 cb` boundary), set cs=21bd,
  eip=off. Routine near-rets -> 21bd:0x52cc `retf` -> pops {ret,ocs}
  -> clean return to caller. Works: port svc ran, retf returned to
  ab1:0x62d, app continued.
- Result: app runs ~24K insns (was ~2.8K). After svc return the app
  chain-returned through the staged retfd frame {0x0c3a,0x448} (second
  stack entry) -> 0448:0c3a -> real app init: port writes (0x92,0x70,
  0x71 CMOS/NMI), PM descriptor-table construction at 0xa090+ and
  0x100xx (GDT stubs), code-gen of mode-switch stubs.
- New blocker: execution dropped to cs=0 and ran the just-built
  descriptor table as code (sequential eips 0x39-0x9a of descriptor
  bytes -> int1 `f1` at 0xc0). The transition into cs=0 is the next
  thing to trace — likely a far jmp/retf to a low-mem target or the
  code at 0:0x8e05 falling through into the table it built.
- tools/dosemu stays untracked scratch; default (no SELMAP) path
  unchanged — all new behavior is behind the SELMAP=88:20bb0 path.

- run-151 cont — int1 root cause: the derail is the DOS16M
  relocation+context-switch engine at kernrm 0x8d60-0x8e18:
    * reloc pass 0x8d7d-0x8dd8: lodsw a word, cmp against opcode patterns
      (0x489/0x429/0x4c6/0xc80/0x4c7 — `89 04`/`c6 04`/`c7 04`/`80 0c`
      mov [si]-type insns), writes relocated words es:[di] via an
      int31/0x000a data alias. This BUILT the descriptor/stub tables
      seen at 0xa090+/0x100xx.
    * context switch 0x8ddd-0x8e18: rep movsw copies a 0x15-word
      register frame ss:[bp+0x26]->es:[di], switches ss:sp, popa, iretd.
  The copied frame is CODE/zeros (bp+0x26 -> a code page) -> iretd pops
  {eip=0,cs=0,efl=0} -> executes 00 00 adds through the IVT -> int1@0xc0.
  So bp doesn't reference a valid register save — the routine is an
  exception/interrupt-context dispatcher (frame = int-entry pusha+segs+
  ip/cs/fl) and was reached via a plain svc call with no frame, OR the
  task-context record it reads was never populated (same "standalone
  task/DPMI init incomplete" theme as the svc vectors — each fixed
  symptom exposes the next missing init step).
  Next: find where bp's register frame should come from — trace the
  exception/int entry that builds ss:[bp+0x26], or identify which
  task-record init should have populated the saved context.

- run-152 — gamedir arg + PM int routing fixes; app reaches DOS4GW runtime:
    * CRITICAL ENV FIX: emulator usage is `dosemu /tmp/doomdir/DOOM.EXE /tmp/doomdir/DOOM`
      — argv[2] is gamedir (default /home/zorin/Downloads/doom, absent -> every
      C:\DOOM\DOOM.EXE open silently failed, leaving task/seg records empty).
      With gamedir: opens succeed (fd 5), kernel reads BW header @0xf2a4,
      seg map @0x25214, loads real app code. DOOM.ETX open still fails (benign).
    * int67 derail -> reflected-RM ints route native (soft_int ~line 593):
      kernel's `lidt base=0xc0` overlays IVT[0x30]+ with IDT gate bytes;
      IVT[0x67]={0x8e00,0} was a gate type byte -> int67 -> 0:0x8e00 scan
      handler -> its own int31 re-entered itself (IVT[0x31] also gate bytes).
      Fix: !cpu.pm && rm_reflect && n>=0x20 -> int_gate/svc_int instead of IVT.
    * rm_seg rmbase fix (~line 474): present-descriptor sels used desc_base
      -> garbage rmbase=0x56c9ff9b for sel 0x3010. Now sel<<4 for RM-style
      sels -> rmbase=0x30100.
    * PM int routing rework (~line 587-633): n>=0x20 checks guest IDT gate
      first when cpu.idt_valid (kernel owns real int21/int31/int67 gates at
      sel 0x70), falls back to pmvec[]/native. Previously all n>=0x20 bypassed
      guest gates -> DOS16M private int21 fns (ax=0x00a0 DGROUP-load thunk at
      3010:0xf0xx, called via f000 iret-stub trampoline) hit native dos_21
      AH=0 -> spurious dos_exit(0).
    * Result: app executes DOS4GW runtime code (strupr caller=bf80:0x18d5,
      ds=0x33f6, es=0xe75) — far past all prior blockers.
    * New blocker: execution runs off end of loaded app code into zeros
      above 0xbffff (last_good=bf801); eiphist shows cf7xx add-chain then
      unknown opcode at eip=1 — likely bad ret/retf or unresolved reloc
      into a seg that should hold code but maps past the loaded image.
    * DOS16M private int21 API ref: ax=0xFF00 presence check "RSI",
      ax=0xFFFF mem-alloc strategy (/tmp/dos16m.asm, /tmp/dos4g.htm);
      int15 ax=0xBF02 install check -> XBRK ptr DX:SI; int31 eax=0xA00 = DOS/4G.

- run-153 — app-image truncation found + fixed; kernel tail derail located:
    * WORKING INVOCATION (reconfirmed): `./dosemu /tmp/DOOM.EXE /tmp/doomdir`
      (argv2=/tmp/doomdir -> C:\DOOM\X maps to /tmp/doomdir/DOOM/X). The form
      `dosemu /tmp/doomdir/DOOM.EXE /tmp/doomdir/DOOM` diverges EARLY
      (int03 ax=ffc3 breakpoint -> int0 -> cs=0x10 div0); use the /tmp/DOOM.EXE
      + /tmp/doomdir form for the far path.
    * ROOT CAUSE of the bf80 run-off: file image loads at load_seg_para<<4 =
      0x20000 but was CAPPED at 0xa0000 bytes (`img>0xa0000->0xa0000`,line~3135).
      App code cs=0xbf80 = file off 0x9f800; eip 0x801+ = file off >0xa0000 =
      never loaded -> zeros. File is 0xad411. Fix: cap -> 0xd0000 (f000 stub
      sea starts 0xf0100). App now executes the full segment.
    * bf80 "code" was a data-table being executed (sparse dword arrays);
      real derail entry: PM->RM reflect sel=0xbf80 -> bf80:0 dispatched by
      the kernel's int0 handler (70:41f1 -> task-record write @0x8e60 ->
      reflect to task ctx) after the kernel itself ran off.
    * Kernel run-off: sel 0x70 (base 0xa090) at eip 0xca2 fetched `e9 f3 a5`
      (file 0xb132 — genuine, code NOT modified) = jmp rel16 0xa5f3 ->
      eip 0xb298 past kernel image end -> zero exec (esp=fffffffe) ->
      fault -> int0 dispatch. 0xca2 is MID-INSN: real code is `d1 e9`(0xca1)
      `f3 a5`(0xca3) — execution ENTERED one byte in. Region 0xc30-0xcb2 =
      kernel block-copy/pointer-build loop (rep movsw + es:[bx+0x80] far-ptr
      stores). Next: find what jumped to 0xca2 (bad retf/return or computed
      dispatch one byte off).
    * int15/0x87 via svc thunk `0:14f0` (`cd 15 cb` = int15;retf): es:si =
      0:0xffaa -> kernel stub TEMPLATE in PM-image tail (file 0xf7aa: routine
      ending `5e 5f c9 cb` + `e9 00 00` patch-site jmp). DOS16M private ABI —
      the param block is a stub to relocate/invoke, not a BIOS block-move
      GDT. Still stubbed benign; semantics TBD (may need to relocate the
      template or call it).
    * [wapp] write-watch 0xbf800-0xc8000 + [mvb] svc-0x0b move logging added
      (both silent — confirmed no bulk writes to the app page).
    * Default (no-SELMAP) path unchanged: halts cleanly after 5011 insns.

- run-154 — int21 dispatcher redirect + GUEST_MEM bump; reached deep app code:
    * int21 gate puzzle SOLVED: guest IDT[0x21] deliberately = 70:0xc9e but
      that offset is mid-insn in the low image (0xa090). The REAL private-
      int21 dispatcher is the shared entry at relocated-image eip 0xc9f
      (guest 0x2301f, file 0x2a6f): `cli;push ax;push ds;mov ax,0x20;mov ds,ax;
      mov [0xf7c],ss; mov [0xf7a],sp; cmp ax,[0xf7c]; je nested` -> stack
      switch to kernel stack + pusha + register-frame build at [bp] — THE
      frame builder the context-switch engine (run-151) was missing.
      int20's gate 18:0xc80 -> `call 0x2a6b` trampoline into the same
      dispatcher proves the pattern. Fix: dispatch special-case rewrites
      int21 70:0xc9e -> 18:0xc9f. Kernel later re-installs int21 -> 70:42ed
      (valid low-image handler) — the 0xc9e was an early-boot gate.
    * GUEST_MEM 32MiB -> 256MiB: the kernel's rep-movs/frame machinery writes
      far addresses >0x2010080 which wrapped mod-32MiB into 0x10080 (IVT/PSP),
      later producing corrupt gate `disp n=21 -> 8e:70020000`. With 256MiB the
      run reaches linear code at 0x97bxx (~file 0x77bxx — deep DOS4GW runtime).
    * Crash progression: ~3.6K log lines -> ~65K lines. New derail: kernrm
      int15 dispatcher (cmp ah,0x88/0xbf = memsize/DOS16M vendor fns) chains
      unrecognized calls via `jmp far [cs:0x12c4]` — saved previous-vector
      slot = {0,0} -> jmp 0:0 -> executes IVT -> int1@0x46. The kernel zeroed
      IVT[0x15]'s seg at 21bd:62fe; the save slot was never populated.
      Next: either keep IVT[0x15]=f000-stub (so the saved chain hits our
      svc_int+iret path) or emulate {0,0} far-jmp as return-to-issuer.
    * Dispatch-table region 0x3010:0xfb18+ = far-jmp table `ea XX 21 80 00
      58 0e 50` (jmp far 0080:XXXX; pop ax;push cs;push ax) — kernrm service
      entries. The runtime-patched code at 80:0x2156 does rep-movsw + IVT
      scan/restore loop — real work, not a derail itself.
    * Default path unchanged; all new behavior still behind SELMAP.

- run-155 — chain0 iret + int8 PM-IVT delivery; 369M insns, DOS4GW runtime:
    * int15 chain fix: kernrm chains unrecognized int15 via `jmp far
      [cs:0x12c4]` — the saved previous-vector slot populated by int21
      AH=0x35 (get-vector) at file 0x8308/0x9089, stored {seg,off}, then
      invoked via `pushf; call far [cs:0x12c4]` with ax=0xbf01 (DOS16M
      resident check, XBRK ptr expected in dx:si). Slot = {0,0} because
      IVT[0x15]'s seg was zeroed at 21bd:62fe before the save ran. Fix:
      far-jmp (ff /5 and ea) whose target is {0,0} emulates a bare `iret`
      (pops flags/cs/ip) — semantically "previous handler = bare iret",
      which is exactly what our f000 stub would have done anyway. Fired
      twice at 80:219b; run went 65K -> 369M insns.
    * int8/PM delivery fix: hw_int in PM only dispatched pmvec[n]
      (LE-path only). The DOS16M kernel hooks IVT[8] at lin0 instead.
      IVT[8] = {off=0x2238, seg=0x28} STANDARD order -> 28:2238 -> lin
      0x24b8 = the kernel's A20/enter-PM reflector (in/out 0x92, call
      0x1f0c, out 0x70/0x71) — the RM-side int8 stub that re-enters PM
      itself. Wrong interpretations tried+ruled out: sel 0x28 (GDT[5]
      never built -> base 0 -> mid-insn `0f ee` at 0x223a8); {seg,off}
      reversed (2238:0028 -> runtime port-IO code, not the file's
      trampoline — relocated kernel at 0x22380 holds file 0x22db, the
      OTHER copy with the trampoline is at ~0x216c5). Fix: pmvec empty ->
      dispatch IVT[n] as RM seg:off (push16 frame, cs=seg<<4, pm=0,
      rm_reflect=1). ISR then switches back to PM via its own lmsw path.
    * tick55 now increments in pit_poll (backs int1a AH=0) — was a pure
      set/read var, never bumped.
    * IDT notes: lidt base=0 lim=ffff at init (overlays IVT); IDT[0x1c] =
      real gate 70:0x4261; IDT[6]/[14] = garbage (no #UD/#PF model); the
      i= debug print now shows efl/irq8 count.
    * Result: int8 dispatched, kernel ISR ran, run reached DOS4GW C
      runtime: cs=9d75 (file 0x7d950 region) arg-parse loop `cmpb
      [bx+si],0x2d;jne`, calls into runtime helpers — then `jmp far
      [si-0x7d]` at 9d75:d300 read {off=0x008e, seg=0xd000} from lin
      0x151 -> d000:0x8e -> zero-exec.
    * CURRENT BLOCKER — BW segment placement: the table at lin 0x140+
      (written by rep-movs at 28:2199, source seg 0) holds 8-byte slots
      of {seg=0x8e00:0, seg=0xXX00:0x0070} pairs with XX = cc,d0,d4,d8...
      — DOS4GW runtime block pointers at consecutive 0x400-para (16KB)
      blocks, entry off 0x70. d000 -> lin 0xd0000 is BEYOND the loaded
      file image (file 0xad411 -> image end lin 0xcd411 / para 0xcd41).
      The runtime blocks never populated: kernel copies landed at
      0xa14xx (file 0x81600) / 0xb82xx (file 0x98400) instead. File is
      DOS16M "BW" bound format (hdr at 0xf2a4, seg-descriptor table +
      32-bit size table at 0x25214: entries like 28b8/477/44a/426/3d9).
      Need: decode BW object map -> where each runtime para's content
      actually comes from; check whether the flat image at 0x20000
      overlaps intended block space and whether d000 is a para or a
      DOS16M logical-seg handle resolved via kernel tables.
    * Debug trap z0 narrows to fetch_eip in [0xc0000,0xf0000).
    * Default path unchanged; all new behavior still behind SELMAP.
    * run-156/157 (dosemu.c, continues 154/155):
    * Mirror fix landed: file[0x8c000..] -> lin[0xcc000..] (para cc00+)
      resolves the d000-table blocks; 0x87f0 confirmed base-0x2000 para
      (file 0x68900 = real code vs 0x47f00 mirror = descriptor data).
    * imul (0f af) added to twob().
    * NEW FIX — int15/0x87 is DOS16M "svc" (task-context snapshot):
      es:si points at an RM stub (0:0xffaa) that pops the callf frame's
      cs:ip + pushed regs into the task record at [0xa42]. Our old code
      no-op'd it -> task records held poison -> iretd to 0x87f0:0.
      Now: transfer cs:eip to the stub AND force ds=0 (kernrm globals
      0xaXX/0x3cXX/0xdXX live in the 0-para kernrm image; the svc
      dispatcher establishes ds=0 before entry). Result: stub ran,
      lret->15:355f, jmp far [0:0xaf2] read {0x3e5e,0x70} -> 70:3e5e
      (PM kernel) -> RM->PM reflect -> real DOS4GW app code at cs=ab1/
      cs=448 doing int21 ax=4000 DOS calls. ~970M insns (was ~3.6K
      at session start, 65K at run-154).
    * {0,0} far-jmp->iret fix still fires correctly (int15 chain at
      80:219b, saved-vec slot cs:0x12c4 never populated since kernel
      zeroed IVT[0x15] seg at 21bd:62fe).
    * CURRENT BLOCKER — kernrm ds-leak: 448: (para 0x448 = relocated
      kernrm image) runs kernrm routines with ds=a0 (app/0xa0-para
      inherited from ab1: retf frame). Routine at 448:0x0c3a does
      `mov gs,[0xd66];mov fs,[0xd64];lidt [0xddc]` — all absolute
      kernrm vars needing ds=0 (mem[0xddc]=ff ff 00 00 00 93 desc vs
      ds=a0 -> 0x17dc = ASCII "le no l"). Same class as the svc fix:
      kernrm code wants ds=0 but a deeper call path delivers ds=a0.
      Also marching run-offs past 0x10000 (448:fe10+ -> zeros -> wrap
      -> 0xa hits real code again) and a garbage rfl sel=0x2444 ->
      rmbase=0x7d0639c0 -> cs=639c spin. Next: emulate the kernel's
      ds-restore-on-kernel-entry convention (context-record saved ds)
      or find where ds=a0 legitimately derives.
    * Probes: [lidt] prints ea/ds/ibuf; [waf2] watch 0xaf0-0xb00
      (0xaf2 = kernrm saved-return far-ptr, read as {off,seg} by
      jmp far [0xaf2] return-dispatcher at lin 0x3a5e).
    * Default path unchanged; tools/dosemu untracked.
    * run-158 analysis (dosemu.c): the run-157 "ds=a0 kernrm-leak" is NOT
      the root cause — ds=a0 is RESTORED deliberately (`pop ds` at
      448:0x478 restores a0; a0 is a real kernrm data para for 0x14xx
      task-recs). The `lidt [0xddc]` ASCII read at 448:0xa is a SYMPTOM
      of a linear run-off: 448:0x0c3a (allocator at file 0x52ba) marches
      0xc3a->0xfffe->wrap->0xa through the whole relocated kernrm
      (0x4480-0x10000 code + zeros above 0x10000) hitting `+0x16`-stride
      table stores at @b80. kernrm wants ds=0 for 0xddc/0xaf2/0x3c7e
      globals AND ds=a0 for 0xa42/0x14xx task-recs — per-routine.
    * Chain after lidt: 448: executes real work (int21 ax=4000 @
      448:5008) then rfl PM->RM sel=0x2444 -> rmbase=0x7d0639c0 garbage
      -> cs=639c spin. 0x2444 has TI=1 -> resolved via cpu.ldt (never
      lldt'd -> garbage base) OR is an RM para -> para 0x24440 = file
      0x24640 = "ERRXLAT" string table = DATA. Either way the xfer
      operand was corrupted upstream — kernrm table poison.
    * Next session: the real missing piece is DOS16M's task-record
      context save/restore — the svc stubs (0xffaa save / 0xffec
      `enter 8,0x87` restore) populate per-task reg frames at [0xa42]
      and the dispatcher switches them. Our int15/0x87 runs the SAVE
      stub but the RESTORE path (who feeds saved ds/cs/flags back on
      task switch) isn't emulated — kernrm routines resume with stale/
      app-context regs. Emulate the [0xa42] record layout + the
      dispatcher's swap.
    * Probes added: [lidt]/[lgdt] print ea+ds+ibuf; [seg] logs sel==0xa0
      always; [waf2] watch 0xaf0-0xb00.
    * Default path unchanged; tools/dosemu untracked.
    * run-159 fix (dosemu.c): kernrm (para/sel 0x448) is a 64KB CIRCULAR
      segment — `448:eip -> file[(eip+0x4680)&0xffff]`. Verified via two
      anchors: 448:0x0c3a -> file 0x52ba (allocator, uses [0x1202]/[0x97c])
      and the allocator's `call 0x4490` (rel -0x1295 from file 0x5727)
      landing at 448:0xfe10 = mem 0x14290 which must = file 0x4490 (the
      `int 0x21` marshal routine: push bp; mov sp,bp; load reg-struct
      from [di]; int21; store results back). The two guest kernrm
      copies (mem 0x400-0xa090 = file 0x600+, mem 0xa090-0x10000 = file
      0xa490+) cover only file 0x4680-0x10400 mapped at 448:0-0xbb80;
      the leading kernrm region file 0x200-0x4680 was never copied, so
      448:eip >= 0xbb80 read zeros -> run-off (0xc3a->0xfffe->wrap->0xa,
      ASCII `lidt [0xddc]` on "mode available only with 386"). Fix:
      `memcpy(mem + 0x10000, mem + imb, 0x4680)` — wraps file 0x200-0x4680
      to mem 0x10000-0x14480 (448:0xbb80-0xffff). Result: 448:0xfe10 runs
      file 0x4490 correctly, `lidt [0xddc]` reads ds=0 -> base=0 lim=ffff
      (correct IDT=IVT reload), execution advances into 2238: kernpm
      string-scan (cmpsw, cmp bl,'.') then `int21 AH=0x33` in PM (pmint
      21 csbase=22380).
    * run-159 remaining blocker: task-frame poison persists — esp=
      ffffffXX / eax=d22bXXXX at 2238:/70: entry. The context-RESTORE
      stub at 0x101ee (`enter 0,0`) pops task-rec [si] fields: +4=ds
      +6=es +8=fs +a=gs +c=edi +10=esi +14=ebp +1c=ebx +20=edx +24=ecx
      +28=eax +3a=eflags, then `mov ss,[0]`;`movzwl sp,esp`; pops a
      pushed {eip=0xed6,cs,eflags,ecx,0,ss,esp} frame + `iretl`. The
      es:[bx] secondary struct (bx=arg, fields +2/+6 pushed as the new
      stack) is mis-read -> esp stays ~0 -> pushes go negative. Need to
      decode the [si] rec + es:[bx] stack-struct layout and how the
      dispatcher links them (bx at 0x10212 = 0x6(bp) arg).
    * Probes: [h448] dumps eiphist when 448: first execs >0x10000.
    * Default path unchanged; tools/dosemu untracked.
    * run-159b analysis (dosemu.c): the task-frame poison (esp=ffffffXX /
      eax=d22b) traced to `mov sp,[0x0f50]` at `18:cf0` (file 0x1070,
      relocated kernrm para 0x18 = mem 0x180). With ds=0x20 (kernrm data
      para for 0x9XX/0xfXX vars -> 0x200+offset) it reads mem 0x1150,
      which received NO writes this run -> sp=0 -> pushes wrap to
      0xfffffffe. [0x996] (ds=0x20 -> mem 0xb96 = 0x24cc) is a VALID
      kernrm stack-base loaded by the same `mov sp,[imm]` pattern at
      18:cb7, so ds=0x20 is the right seg — the 0x1150 slot is a task
      stack-ptr field the DOS16M task-record save path never populated.
      The 0xf56-0xf6f region right after is a GDT descriptor table
      ({01d4,0170,9001,008e...} written by stosw at 2238:34c-35a), so
      0x0f50 sits at a table boundary. Next: decode the task-table —
      who writes [0x0f50]/0x1150 on task-create/suspend (the svc save
      stub at 0:fdaa / file 0x101aa region), and why the restore path
      reads it empty. Chain confirmed good up to here: 0:b61 callf ->
      2238:384e kernpm init (GDT build at 0x8xx/0x9xx) -> 18:cb7 task
      dispatch pusha-frame -> mov sp,[0x0f50]=0. Probes: [rst] dumps
      es:[bx] stack-struct in 2238:249d8-24c40; [wf50] watches
      0xf40-0xf70 + 0x1130-0x1170.
    * Default path unchanged; tools/dosemu untracked.
    * run-159c analysis (dosemu.c): [0x0f50] semantics decoded. It is the
      task-switch SP slot — ONE global the kernpm swaps tasks through.
      Writers: `mov [0xf50],bp` at file 0x90c4 (app-LAUNCH: builds iret
      frame on task stack at es:[bp+0xe], mov ss=es, lea sp=[di-6], saves
      bp->[0xf50] as the kernpm resume frame, mov ds/es=bx, iret into
      task) and `mov [0xf50],sp` at file 0x9045/0x808e/0x3240 (task
      SUSPEND). Reader: `mov sp,[0x0f50]` at the generic resume
      dispatcher 0x23070 (kernpm sel 0x18, mem 0x23070; reached via the
      0x23020 routine: mov ds,0x20; mov [0xf7c],ss; mov [0xf7a],sp;
      mov ss,0x20; mov sp,[0x996]; sub 0x180; pusha; lds si,[0xf7a] ->
      copies the suspended task's saved frame, mov [0x996],bp, then
      mov sp,[0xf50]; call 0x22cac). KEY: @f50/@f51 got ZERO writes all
      run -> 0x90c4 launch AND the suspend paths never ran -> [0xf50]=0
      -> mov sp=0 -> pushes wrap to ss:0xfffe. So a task is being
      RESUMED via 0x23070 before it was ever LAUNCHED (0x90c4) or
      SUSPENDED — a task-lifecycle control-flow gap. ds=0x20 at the
      resume resolves base=0 (GDT idx4 flat) -> reads mem 0xf50 directly
      (NOT 0x1150 — earlier ds=0x20->0x1150 model was wrong). Values at
      the 18:cf0 read: [996]=21b4 [f4e]=1bcc [f4c]=2376 [f50]=0. Task
      block base 0x1bcc (alloc'd via lcall 0:0xb12), rec ptrs 0x2376.
      Next: find why resume 0x23070 runs with no prior launch — is the
      app supposed to first-run via 0x90c4 iret, and did the dispatch
      reach it? grep the dispatch-call chain into 0x23020/0x90c4.
    * Default path unchanged; tools/dosemu untracked.
    * run-160 decode (dosemu.c, REA/objdump): [0x0f50] semantics FULLY
      resolved via 16-bit disasm of DOOM.EXE (objdump -b binary -m i8086).
      [0xf50] = the PM kernel's SERVICE-STACK SP slot (a pure stack-switch
      scratch — no imm/lss/pop writers, only mov [0xf50],sp at file 0x3240/
      0x808e/0x9045 and mov [0xf50],bp at 0x90c4). Pair: readers
      mov sp,[0xf50] (11 sites: 0x298a,0x2ac0,0x3360,0x34c4,0x325f,0x1dea
      gate-trampoline w/ mov ss,[cs:0]) resume the kernel stack; writers
      save it when switching to a task/other stack (ss=ax,sp=[0x8a8]).
      * LAUNCH: file 0x802f routine (mov sp,[0xcda]) -> 0x807a reads task
        rec es:[0xcea]+0xa -> IP:CS->[0x10c2/0x10c4] -> 0x808e mov [0xf50],sp
        -> if [0x2e]==0 call 0x9040. 0x9040: sub sp,0x54;bp=sp;0x9045
        mov [0xf50],sp; alloc via lcall 0:0xb12; save/set int35h vec
        cs:[0x12c4]->cs:0x7253; 0x90a8 es=[bp+2](task ss);di=[bp+0xe];stosw
        x3 push ip/cs/flags onto task stack; ss=es;sp=di-6; 0x90c4
        mov [0xf50],bp (kernel resume frame); iret -> task.
      * DERAIL SITE pinned: fetch_eip 0x23070 = file 0x2ac0 = the 0x2a90
        int-dispatch routine (18:ca0 entry: cli;ds=ss=0x20;[0xf7a/0xf7c]=
        saved caller ss:sp;sp=[0x996]; copy caller 0x180-frame via
        lds si,[0xf7a];[0x996]=bp; mov sp,[0xf50];call 0x26fc svc).
        Reached via: 448:fe2b pmint21(AH=0x48 malloc) -> gate 1c8 -> sel18
        -> 18:c9f. [sw] probe (op 8b26/8926/892e on 0xf50/0x996/svc slots)
        logged ONLY 3 hits (0x23037 mov sp,[0x996];0x2306c mov [0x996],bp;
        0x23070 mov sp,[0xf50]) — 0x808e/0x9045/0x90c4/0x3240 writers and
        0x2964 init-dispatcher NEVER ran.
      * ROOT CAUSE: 448: int21 -> 0x2a90 dispatcher tries to resume the
        kernel service stack [0xf50], but the kernel task was never
        launched via the 0x802f->0x807a->0x9040->0x90c4 chain (kernrm
        svc-entry). Our PM entry path (lidt+reflect) bypassed the kernel
        task bootstrap. sp=0 -> pushes at ss:0xfffe corrupt kernrm stubs.
      * NEXT: find how 0x802f dispatch routine is invoked (int vector /
        lcall gate installed by DOS4GW loader — grep vectors/int gates
        for seg covering file 0x802f), and whether the emulator must run
        that kernrm svc-entry before servicing PM int21s. File->mem map:
        file 0x2ac0 -> mem 0x23070 (delta file=mem-0x205b0); file 0x325f
        -> mem 0x2305f for a DIFFERENT copy (reloc image not contiguous).
      * tools/dosemu untracked; default path unchanged.
    * run-161 decode (dosemu.c, [sw]+[svc-entry]+widened-wf50 probes):
      * widened wf50 to (a&0xfff)==0xf50 (any para-aligned ds) — mem[0xf50]/
        0x1f50 stay 0 all run (0x1f50 hit is an init memset of 0). The slot
        is GENUINELY never populated.
      * 0x802f DID run: [sw 27e2f] op=8b26 [mcda] at insn ~1212 (mem 0x27e2f
        = file 0x802f via the 0x20000 SELMAP image, file+0x200->mem+0x20000).
        It is the DOS16M "enter PM" routine: mov sp,[0xcda] (kernrm resident
        stack) -> call 0x55f9,0x29dd,0x4d5f -> [0x2e]!=0: 0x376a,0x8267,
        0x81cd,0x1f3c,0x8356 -> 0x8073 push 0xf8a;call 0x3050(rep-movsw,
        returns) -> 0x807a read task rec es:[0xcea]+0xa -> IP:CS->[0x10c2/4]
        -> 0x808e mov [0xf50],sp -> 0x80a5 call 0x9040 -> ... -> 0x90c4
        mov [0xf50],bp -> iret -> task.
      * BUT 0x808e (89 26 50 0f -> [sw mf50]) NEVER ran at ANY alias — one
        of the init calls inside 0x802f enters PM (0:b61 -> 2238:384e at
        insn ~1258) and never returns to kernrm 0x807a. So [0xf50] stays 0.
      * FLOW: 0x802f -> (init chain) -> PM kernel init 2238:384e -> dispatch
        ab1 -> 448:0c3a allocator -> 448:fe2b int21 -> gate -> 0x2a90 disp ->
        mov sp,[0xf50]=0 -> sp=0 -> call 0x26fc pushes @ ss:0xfffe (kernrm
        stub region) -> cascade.
      * 0x26fc = nop; jmp *[0x9bc] (svc trampoline; [0x9bc]/[0x9be] set by
        0x802f from cs:[bx-4/-2] via mode byte [0x2e]).
      * ROOT: kernel task launch 0x807a/0x808e/0x9040 is bypassed because
        the PM-entering call inside 0x802f doesn't return to kernrm. In real
        DOS16M that call returns so 0x807a saves [0xf50]=kernrm-svc-stack.
      * NEXT: identify which 0x802f call (0x55f9/0x29dd/0x4d5f/0x376a/
        0x8267/0x81cd/0x1f3c/0x8356) holds the PM-entry that should return;
        check if 0x807a executes at mem 0x27e7a (unprobed alias) and whether
        the PM kernel should reflect back to kernrm 0x807a before the first
        task dispatch. 0x4b90 routine (ends call 0x802f @0x4c7e) is the
        upstream trigger.
      * tools/dosemu untracked; default path unchanged.
    * run-162 decode (dosemu.c, [svc-entry] widened to 0x27e2f-0x27f00 +
      0x285c0-0x28700, objdump -m i8086 full call-chain):
      * 0x802f runs at 21bd:625f (mem 0x27e2f = file 0x802f; 21bd: & 2238:
        BOTH map file[eip+0x1dd0], bases 0x21bd0/0x22380 = same image).
      * svc-entry trace: 0x802f body 0x27e2f-0x27e38 (mov sp,[0xcda];smsw;
        call 0x55f9) -> returns under 2238: alias 0x285eb-0x28617 (call
        0x29dd;[0x35/0x37]=cl;call 0x4d5f;cmpb[0x2e];call 0x376a;[0x2e]!=9
        skips 0x81cd -> call 0x1f3c at file 0x8067 = LAST continuation).
      * 0x1f3c = GDT builder (0x100 descs {4k,70,8e00,0} + 0x11 @41f1+0x1c +
        named fields [0x128]=1f96,[0x248]=448e,...) -> call 0x3e41 -> ret
        expected but 0x806a (0x2861a) never logged -> diverted INSIDE 0x1f3c.
      * 0x3e41: call 0x2060; ljmp $0x70,$0x5401 -> ONE-WAY into kernpm main
        (0x5401 = eip in sel-0x70 space = kernpm main loop). 0x802f/0x1f3c
        never return to 0x807a -> 0x808e (mov [0xf50],sp) never runs.
      * REVISED ROOT: [0xf50] = global KERNEL-STACK SP slot. Written
        kernel->task (mov [0xf50],sp on switch-away), read task->kernel
        (mov sp,[0xf50] on resume). Set by kernrm task-launch 0x807a/
        0x808e/0x9040 via a PM->RM reflect (or an equiv PM-side init) —
        NEITHER ran. Kernel dispatched ab1 via PM-side 0:fbbc/es:[di]
        task-record path, bypassing kernrm launch -> [0xf50]=0.
      * The int-dispatcher 0x2a90 (18:c9f) is the PM int-gate handler:
        saves caller ss:sp->[0xf7a/0xf7c], sp=[0x996], copies caller's
        0x180 stack frame (lds si,[0xf7a]), [0x996]=bp, mov sp,[0xf50]
        -> switch to kernel svc stack -> call 0x26fc (jmp *[0x9bc]).
      * NEXT: find the kernpm-side [0xf50] init — does kernpm main 70:0x5401
        (or its int-handler gate setup) write [0xf50]=kernel-svc-stack?
        Or must the emulator reflect PM int21 -> kernrm 0x807a to launch?
        0x1de3 gate-trampoline: mov ss,[cs:0];mov sp,[ss:0xf50] — [0xf50]
        pairs with a cs:0 stack-selector = per-gate svc stack.
      * tools/dosemu untracked; default path unchanged.
    * run-163/164 fixes (dosemu.c): TWO verified wins — run went 3.6K ->
      268M+ insns, into real PM DOOM-load code:
      * FIX-A [0xf50] svc-stack seed (soft_int int21 override): [0xf50] is
        the kernel's flat svc-stack SP (ds/ss=0x20/0 -> mem[0xf50]). All
        dispatchers (0x2a6f/0x2964/0xa490/0x1de3/...) do `mov sp,[0xf50]`
        unconditionally; populating task-launch coroutine 0x802f->0x807a->
        0x808e/0x9045/0x90c4 was bypassed by the one-way `ljmp 70:0x5401`.
        With 0, mov sp->ss:0xfffe pushed onto/corrupted the f000-stub page.
        Seed ww(0xf50,0x9ff0) in the 0x8000-0xa000 flat gap when 0.
      * FIX-B 16-bit SS stack addressing (push16/pop16/push32/pop32 +
        new ssbig()): stack ADDRESS size is the SS descriptor B-bit
        (seg[S_SS].attr & 0x4, gran bit6>>4), NOT the operand-size prefix
        nor CS's D-bit. push32/pop32 used full esp -> in flat ss=0/0x20
        (B=0) `xchg esp,eax`/`mov esp,ebp` left the DOS4GW 0xd22b cookie
        in esp high, then popal/iretl deref'd 0xd22bXXXX -> OOB -> cs=0.
        Now: 16-bit ss ops use sp=(uint16_t)esp and preserve esp high
        (faithful: 0xd22b junk stays but only sp addresses). Fixed both
        directions — push16/pop16 also wrongly masked a 32-bit ss before.
      * Derail chain resolved: 0:d22b0646 retfd pushes eip32 w/ 0xd22b
        high (16-bit truncation-safe); int21 gate file 0xe77d does
        `xchg esp,eax` (66 94) moving eax=0xd22b1037 into esp; only the
        sp-vs-esp fix stops the OOB. Verified: second int21 ran on the
        seeded 0x9ff0 stack through the guest's REAL rebuilt-IDT gate
        70:0x42ed (=file 0xe77d, the 0x1f3c-built gate {off=42ed,sel=70}).
      * Audit: safe-anything scoped 0 findings; cve.now no applicable
        class (x86-emu correctness, no boundary/deps).
      * NEW failure deep in launch (~96K lines / 268M insns): guest
        `rep stosb` zero-fill of 0x3be0000-0x3c00000 (~2MB), then loads
        s3=0xa0, then far-transfer sets cs=0x6520 (ASCII " e"!) — a
        far-ptr pulled from the "needed memory... not a" error STRING.
        strupr svc uppercases "...ended memory not a..." -> guest hit an
        out-of-mem/error report and the error path executes the string
        as code -> spins on zeros at 6520:xxxx. Probe rst 24b14 scans
        es:[bx+2]/es:[bx+6] over es=ffff bx=0-0x88 (0xffff0-0x100078 =
        HMA/1MB boundary) reading zeros -> a far-table/A20 check region
        DOS4GW expects populated is empty. int15/88 already returns
        0x3c00=15MB ext; xms_top=0x1e00000. Suspect a HMA/1MB-boundary
        far-table or the direct A20-boundary probe region unpopulated.
      * tools/dosemu untracked; default path unchanged.

### run-165 — direct-mode bypass runs REAL DOOM _cstart; CMOVcc added
  * The error string decoded: stack holds "ended memory" + "not a
    DOS/16M executable." (file 0x1829) — the DOS16M LOADER rejected a
    module, NOT an OOM. sel=0x6520/eip=0x6867756f both ASCII — a far-ptr
    read out of the error string; the whole 268M-insn "PM run" was the
    error path executing the string as code, not real game code.
  * LE image is valid (bound MZ @0x25214, e_lfanew=0x28b8 -> "LE" sig
    @0x27acc; 3 objs, 108 pages, type 0x200 exe). DOS16M loader rejected
    it anyway — load/reloc produces wrong bytes at validate time. Only 9
    file reads total, all header probes; int21/0x48 NEVER hit (dead code,
    top/rm_brk change was a no-op red herring, kept top=0x10000 as it's
    more correct than the underflow).
  * *** direct mode is the way forward ***: `./dosemu EXE dir direct`
    -> le_direct_load bypasses the DOS16M extender entirely (parses LE,
    maps objs at VAs, applies 12104 fixups, flat segs, LEENTRY override).
  * Found real entry: LE eip=0x40b48->0x50b48 lands MID-__InitRtns (uses
    esi/edi unset). _cstart head = 0x4e30b: `and esp,~3`, PSP sel 0x24,
    int21/0x3000 extender detect (cmp 'XD'), env sel 0x2c, int21/0x4a.
    Matches fabricated LDT (sel 0x24->PSP 0x400000, 0x2c->env).
  * LEENTRY=0x4e30b direct RUNS _cstart: extender detect, NO87 env scan,
    PSP/env copy, BSS zero (0x95500-0x75e08), __InitRtns calls, real
    hardware init (VGA/PIC port outs, int5 DOS16M svc loop).
  * FIX: added 0x0f 0x40-0x4f CMOVcc (cmovae etc) in twob() — app uses
    it; was the first hard fault at 0xb350.
  * esp=0xf5e10 sits at ROM-sea 0xcf boundary (obj3 top 0x70000-0xf5e10
    overlaps init_ivt 0xcf fill 0xf0000+; obj3 memset cleared f0000-f5e10
    to 0, but f5e10+ is cf). EFL=cfcfc70e shows cf leaking into eflags
    high via a popfd/iretd reading cf region.
  * NEW blocker: int5 (DOS16M svc, ax=0/ffcd/f6/f9, does PIC/PIT port
    outs) -> pmint 05 gate resolves cs=0:eip=a009 = kernpm DATA (hex
    table) — direct mode has cpu.idt.base=0 so PM ints read the IVT as
    gates -> sel=0 -> cs=0 executes kernpm resident data. Needs the
    DOS16M resident kernel + int-svc machinery wired in, OR ints treated
    as no-op irets if spurious probes.
  * Audit: safe-anything scoped 0 findings; cve.now no dosemu matches.
  * tools/dosemu untracked; default path unchanged.

### run-166 — DOS16M kernel-svc mechanism mapped; wall is kernel ctx state
  * Closed fixup forensics for good: DOS4GW skips internal fixups when
    objects load at preferred VA (spec line + DOS/32A apply_fixups
    confirmed `obj_base+trgoff` written unconditionally — irrelevant
    here). NOFIX=1 is the faithful model. All stored-operand analyses
    dead-ended because they'd been reading the WRONG pagemap entries
    (fpt/frt at LE+0x68/+0x6c, not +0x50/+0x54; page N -> file
    le+doff+(N-1)*0x1000). 12104 records, zero straddles — real but
    correctly unused.
  * Derail root-caused to [ds:0x1150] = 0xfffffa03 — one of ~10
    {off16, sel=0xffff} kernel-svc far-ptrs in a table at obj3+0x1140.
    Dispatch site 0x239b8: `call [eax+4]` invokes entry->handler then
    clears slot. Sel 0xffff isn't PM — DOS16M real-mode-style kernel
    vectors the extender thunks (kernel data expected at linear ~0x6fa03
    when read via DGROUP ds).
  * Scheduler 0x26c38 runs 4 sub-services (0x23638/0x23428/0x239b8/
    0x26948); svc D 0x26948 has ANOTHER `call [eax+4]` at 0x2699e via
    slot [0x1154]. Whole svc registry = DOS16M d16Invoke/kernel layer.
  * Marshal 0x4f430 = DOS16M kernel-call trampoline: caller 0x4dcea/
    wrapper 0x4dd07 packs a {es,cs,ss,ds,fs,gs} selector block (0x4dcc2),
    marshal pushes ebp/es/ebx/ds/edx, calls inner 0x4f467 which does
    `lea esi,[esi+esi*2]; push eax=0x41dc0+esi*3; ...regs-restore; ret`
    = computed CALL into a thunk table (esi must be idx*4 for 12-byte
    thunks; the thunk rets to pushed 0x4f43a which stores result regs).
  * Failure: esi=0x31 (not a valid offset index) -> dispatched to
    0x41e53 = mid-operand of argv-scanner 0x41e38 -> wanders to its ret
    -> pops stale saved-ebp 0xf5ae0 -> executes stack. esi came from
    eax=0x31 = a kernel callback's return value — our ret-stub left
    eax=[0x1154] instead of a real ctx index.
  * Stub experiments: Z1150 (null slot) and KSTUB (0x55-fill kernel zone
    + ret seas at 0x05500000/0x0ffe0000) both move the crash, not fix it
    — the marshal is correct app code needing kernel ctx state, not a
    byte fix. NOTICK proved IRQ8 frame delivery innocent (identical
    crash). Stack primitives/pusha/enter/leave/pop-r-m/sreg widths all
    verified correct.
  * Wall: DOS16M resident-kernel service layer required. Options: (A)
    map the bound kernpm kernel image at its expected region (kernel
    data at ~0x6xxxx + kern code reachable via the 0xffff:off vectors);
    (B) implement the ~dozen svc semantics (d16GetProc/allocCBack/int
    reflection — each `call [eax+4]` needs its return contract); (C)
    return to non-direct kernpm path (prev. abandoned for complexity).
  * Debug scaffolding in dosemu.c (env-gated, uncommitted): KSTUB,
    Z1150, NOTICK (tick w/o frame), [bad0]/[badret]/[marsh]/[wstk]
    watches. Recipe: NOFIX=1 DG=1 LEENTRY=0x4e30b [KSTUB=1] -> log.

run-170: option C — kernpm-path LE rejection root-caused to a MEMORY error, not format.
  * Reproduced: SELMAP=88:20bb0 ./dosemu -> 436M insns -> cs=6520 executing
    the DOS16M error-table STRING as code (pmcs sel=6520 tbl=8c0
    base=e0c48ac2). Selector AND descriptor are ASCII — a far-ptr into
    string data used as code.
  * String = error #1 "not enough extended memory" (table @file 0x17f0:
    err0 involuntary-switch, err1 not-enough-ext-mem, err2 not-a-DOS16M).
    NOT the format reject run-164/165 assumed — a memory-config failure.
  * File I/O verified byte-perfect: the seek->0x25214 MZ read lands exactly
    (cmp True) — reads are NOT corrupt. Loader opens DOOM.EXE fd5, probes
    0xf2a4 "BWp" bound sig, seeks 0x25214 (bound MZ e_lfanew=0x28b8->LE
    @0x27acc), tries DOOM.ETX (fail=ok, bound internally).
  * Kernel RUNS: does PM int21s (pmint ga=1c8/108), resident-kernel calls
    (callf->svc 21bd:ba5), writes IVT/GDT (wivt/wgdt), builds a memory
    table spanning ~16MB ([wkpm] writes di->0xfff690 at 18:d020). So it
    detected ~15MB ext mem — then the svc/init path far-jumps through a
    ptr table whose entries are string bytes -> executes err text.
  * DPMI detect via int2f/1687 returns present (entry f000:0100); NO int31
    calls ever happen — kernel doesn't use DPMI-alloc for ext mem.
  * CMOS fix attempted: added cmos_idx/cmos_reg, port 70/71 rd+wr, init
    0x15/16=640K 0x17/18+0x30/31=15360K (matches int15/88=0x3c00) —
    IDENTICAL crash. CMOS is not the detection path.
  * Same wall as direct mode: the resident-kernel svc/vector table that
    should hold code-farptrs holds string offsets — the kernel-side
    install that populates it never ran its init (table read from bound
    image's string region). The 80K-insn memory-table build IS the kernel
    init; it completes then transfers through the unpopulated table.
  * Next: find the far-ptr table the 0x2f451->6520 jump read (which
    seg/addr the bad {6520,756f} came from) and the init that's supposed
    to populate it — likely the SAME svc-slot/marshal state as direct mode.

run-170b: the bad fetch is a stack-frame read, not a code-table read.
  * [emu] stack shows ss=0 esp=0x9110f pointing INTO the error table:
    stack bytes decode literally to "ened memory\x02\x00no t a DOS/16M
    execuable...\x00\x03 no DOS". So a retf/pop/iret off a stack that
    overlaps the error-string region pops {off,sel} = ASCII -> cs=6520.
  * pmcs at= shows the 6520 re-load came from cs ALREADY =6520 (string
    bytes contain seg-load patterns) — original entry via retf/iret/pop,
    not a logged callf. So: kernel decided error #1, built a frame on a
    buffer holding the error table, and the report path executed the
    strings (secondary artifact; real fault is the error decision).
  * Kernel DID detect ~16MB (filled mem table di->0xfff690) — so
    "not enough" is a specific allocation/region it can't satisfy, not
    total size. int15/88=15MB, CMOS fixed, no int31, own PM via smsw/lmsw.
  * Honest state: this is faithful DOS16M resident-kernel bootstrap —
    research-grade RE, both paths converge on kernel svc-table state.
    Most tractable route forward = direct-mode + implement the ~dozen
    DOS16M svc semantics DOOM actually calls (option B), since svc-table
    slots/marshal are already mapped. kernpm full-init is far deeper.

run-171: kernpm crash root-caused to a thunk-vs-stack layout collision.
  * Mechanism (fully traced): DOS16M ctx-restore `pop ds;pop es;popad;
    add esp,2;retf` at seg18:0x2f454 (lin ~0x517d4) runs with esp inside
    the svc-thunk table -> pops thunk code as far-frame -> cs=6520.
  * The kernel's svc scheduler WORKS: normal task-switch via popad/iretd
    to 0x87f0:0 contexts running thunks `mov edx,N;mov eax,ecx;call svc`.
  * Thunk table is RUNTIME-GENERATED at 0x90eac-0x927xx (~370 thunks)
    by a copy at 18:d020: moves [0x91300..0x92d00]->[0x90e00..0x92800]
    via es=a (GDT-alias, base=0x8c0). Dest 0x90e00 is a fixed abs addr.
  * The collision: this copy executes with esp=0x910e1 INSIDE [0x90e00,
    0x92800) -> clobbers the live task stack mid-copy. esp legitimately
    ran at ~0x91187-0x91200 for ~95K insns before the copy (C-function
    frames at d1:ab8d region). So thunks land on an in-use stack.
  * Ruled out: CMOS 30/31+17/18, XMEM, int15/88=15MB, BDA 0x413=640K —
    none change it. Kernel detects ~16MB on its own; "not enough ext mem"
    (err#1) is just the string adjacent to the thunk table it executes.
  * Stack should likely be ~0x9ff00 (task-stack tbl [f50]=0x9ff0) not
    0x91187 -> a task-context ss:esp or kernel workspace base is off.
  * This is faithful DOS/4GW-Professional kernel bootstrap: preemptive
    scheduler + svc-thunk dispatch + conventional-mem layout. No
    watcom/dos16m source on disk. Deep RE; next = find the task-context
    esp field / workspace base that placed the stack at 0x91187.
  * dosemu.c additions (uncommitted, env-gated/debug): cmos_idx/cmos_reg
    + port70/71, BDA 0x413=640, XMEM knob, espw/wthunk watches, bad0
    guest+stack dump. CMOS/BDA are correct improvements regardless.

## run-172 — ia32 compat foundation: ELF32 + int 0x80 + low-4GiB address spaces

DOS/DOOM emulation abandoned per user directive — pivot to real
32/64-bit app support. This rung is the SHARED foundation both i386
ELF and a future PE32 need: compat-mode execution + a second
syscall-entry path + a low-4GiB user address space.

* cpu.rs: GDT slot 7 = 32-bit user code segment (0x00cffa00 — D=1,L=0
  -> IA-32e compat mode on iret); UC32_SEL=0x3b. USER DATA (0x28) D/B
  bit 0->1 like Linux __USER_DS — compat SS.B governs push width
  (B=0 truncated esp to 16 bits: first boot faulted esp 0x7ffeff50
  -> 0xff50, found by cr2). set_gate DPL variant; IDT 0x80 = DPL3
  interrupt gate (0xee -> IF masked) to int80_entry.
* elf.rs: class-agnostic parse — ELF32 ehdr (52B)/phdr (32B) layout,
  EM_386, u32 fields at their own offsets; Elf.is32 flag; phdrs()
  decodes both; parse_at bounds-checks the 64-bit path only.
* syscall.rs: int80_entry stub — int gate lands on TSS.rsp0
  (INTR_STACK); xchg to CUR_KSTACK, copy the 5-word frame down with
  push [rax+n] so NO user GPR is clobbered (ia32 REX code may hold
  r8-r15). Builds the same UCtx shape, calls handle_int80, iretq —
  never sysretq (can't load compat CS; CVE-2012-0217 class). Compat
  `syscall` insn -> handle_syscall ENOSYS guard (AMD runs it, Intel
  #UDs — either way the 64-bit ABI contract doesn't apply).
* handle_int80: ia32 numbers (1=exit,4=write,20=getpid,45=brk,122=
  uname,192=mmap2-offset-shl-12,224=gettid,252=exit_group,...) routed
  to existing sys_*; nr + all 6 args masked to u32 like the real
  compat entry (CVE-2007-4573/CVE-2010-3301 class — OOB table index);
  bounded match not an index; ENOSYS + printk otherwise.
* user.rs: Task.is_compat (set by load_inner from e.is32, inherited
  at fork like pers). COMPAT_LO..HI = [0x40000000,0x80000000) — the
  1GiB dead zone between RAM top and PCI BARs (fb@0x80000000): phys
  frames the identity map shadows there don't exist, so splicing user
  pages over supervisor entries costs nothing. <1GiB VAs are REJECTED
  by map_page32 — real phys frames there would alias kernel phys
  accesses made under the task's cr3.
* map_page32: PML4[0] copied kernel PDPT -> private PDPT clone on
  first map; per-GiB private PD clones spliced in place of shared
  kernel PDs; 2M supervisor identity leaves SPLIT into PTs of IDENT
  supervisor fills (PTE bit 9, CPU-ignored) around the user page.
  USER rides every spliced TABLE entry — kernel leaves never gain it.
* translate/translate_r: the U/S chain IS the window bound now —
  kernel slots never carry USER at any level, IDENT fills rejected at
  the leaf; covers the 64-bit window AND the compat space (a real
  generalization, not a special case). translate_r keeps PROT_NONE
  acceptance for write_task_bytes_force.
* unmap/leaf_ent/mprotect skip IDENT fills (kernel mirrors, never
  task-owned); free_user_mappings frees only USER-marked private
  tables + present non-IDENT leaves (PROT_NONE compat pages too —
  one audit fix landed here); fork_address_space deep-copies a compat
  parent's private PDPT (shared kernel PDs by reference, IDENT leaves
  verbatim, user leaves fresh frames); exec's shared-mm np path
  unaffected (load_inner re-stamps slot 0 from the kernel pml4).
* Stack/auxv: CSTACK 0x7fef0000 (1MiB), setup_stack32 = u32 slots
  (argc/argv/envp + 8-byte auxv pairs, same auxv ids); mmap arena
  0x60000000-0x70000000 via mmap_find. sys_uname -> "i686".
* Signal gate: no ia32 frame ABI — caught signals on compat tasks
  take the default-fatal path (maybe_deliver + fault_signal both);
  SIG_IGN/default semantics unchanged. SIGTRAMP page skipped.
* Divergences recorded: no sysenter/sysenter32 (int 0x80 only);
  ELF32+PT_INTERP fails exec (no 32-bit dynlinker); ia32 fork/clone/
  execve/wait4/signals not wired (ctx-forging paths stay off this
  rung's table); compat struct ABIs (timeval32, iovec32, stat64,
  linux_dirent) ENOSYS until their shims.
* Proof: kernel/user/ia32test.c — gcc -m32 -nostdlib raw int 0x80,
  linked 0x50000000; argv0 read via naked _start (esp BEFORE the C
  prologue); write/getpid/gettid/brk+touch/uname-i686/mmap2/munmap/
  getrandom/ENOSYS(999)/exit all pass.
* Bugs found by boot: udata D/B=0 (esp truncation above); headers
  LOAD at 0x08048000 out-of-window fixed by -Ttext-segment.
* Follow-on rungs: full ia32 table (fork/clone/execve/wait4, ia32
  signal frames, set_thread_area TLS, sysenter32); PE32 loader +
  int 0x2e on the same foundation.

Suite: make run PASS exit 33 — 73 tasks incl. ia32test exit(0);
frames 214356 -> 214356 zero leak; ptytest slave-write EIO flake
(known run-138 item) failed once in 3 runs and leaked its 2 ring
frames — attribution confirmed, unrelated to compat teardown.
Audit: scoped quick review + cve.now (CVE-2007-4573, CVE-2010-3301,
CVE-2012-0217, CVE-2010-3081, CVE-2021-47364/CVE-2023-53035 — first
three protected by masking + iretq-only + no compat_alloc_user_space;
ioctl classes N/A this rung). One self-review fix (PROT_NONE compat
leaf teardown). needs_validation: none.

## run-173 — physmap: supervisor mirror of all RAM + compat window opens to <4GiB

The run-172 note "exec's shared-mm np path unaffected" was WRONG and is
corrected here (see the slot-source fix). This rung is the enabler for
REAL i386 binaries: busybox-i386 and every stock i386 ELF link at
0x08048000, below the old 1GiB compat floor. The floor existed because
the kernel dereferenced phys AS LINEAR under whatever cr3 was loaded —
a user PTE at VA=P would hijack kernel access to phys P. Fix: a
supervisor-only physmap so kernel phys access can never be shadowed.

* mm.rs: PHYSMAP = 0xFFFF_8000_0000_0000 (PML4 slot 256, inside the
  kernel-shared band every task cr3 copies). build_identity_map now
  also lays one physmap PDPT per 512 GiB + one PD per GiB mirroring
  phys 0..map_gib GiB at PHYSMAP+phys, supervisor-only; table_frames =
  1 + 2*(npdpt+ngib). (First cut used ONE PDPT for the whole mirror —
  1024 GiB overflowed entry 511 into the adjacent PDs; the kmalloc
  proof caught it, kind=0 on every free.)
* pmap(p) = p + PHYS_OFF, unpmap(l) = l>=PHYSMAP ? l-PHYSMAP : l.
  PHYS_OFF is 0 pre-switch (identity, during table build) and PHYSMAP
  after physmap_on() — called right after load_cr3 in rustux_main, so
  both UEFI and BIOS paths flip at the same point, BEFORE kalloc::init
  (no identity-era heap pointer survives). unpmap passes identity
  values through so either-era linear addresses convert correctly.
* All phys-as-linear derefs converted: rd64/wr64/write64/read64 (one
  place), alloc_frame zeroing, kalloc freelist/headers (buddy stays in
  raw phys; kmalloc returns pmap'd linear), pipe ring buffers,
  procfs scratch, fork copy loops, all ~20 translate()-result sites,
  initrd slice, acpi rd, apic lread/lwrite/ioapic, e1000 rd/wr + DMA
  (descriptors/registers get raw phys via unpmap), fbcon (stores raw
  phys, pmaps at each deref — from_desc runs pre-flip).
* Slot copies extended to (0..128).chain(256..512) in load_inner,
  pe_load_inner, exec's np path, fork_address_space — every cr3
  carries the physmap.
* Compat window widened: COMPAT_LO=0x1000, COMPAT_HI=0x1_0000_0000.
  KRESV spans (4 slots, overflow now asserts) ban VAs that would
  shadow identity PTEs the kernel still derefs as linear: kernel image
  (UEFI LoadedImage.info / BIOS __kernel_start..__kernel_end) and the
  boot-stack 2MiB region (rsp snapshot). map_page32 rejects them.
  CMMAP arena 0x40000000-0xf0000000; CSTACK 0x7fef0000 unchanged.
* map_page32 mechanics unchanged (private PDPT/PD clones, 2M-leaf
  splits into IDENT fills, U/S chain as the translate bound).
* SLOT-SOURCE FIX (audit): exec's np copy and load_inner/pe_load_inner
  sourced kernel slots from opml4 / cpu::read_cr3() — under a compat
  caller slot 0 is the task's private USER-marked PDPT, so np[0] would
  alias a user-owned hierarchy by reference (double-free on teardown).
  Now all three source from mm::kernel_pml4() (KPML4 stored in
  build_identity_map); cpu::read_cr3 removed. Latent today — ia32
  handle_int80 has no execve/fork/clone — live the moment compat exec
  lands. fork_address_space already had the right slot-0 rule
  (!c.is_compat || e & USER == 0).
* Proof: ia32test relinked at 0x08048000 (Makefile
  -Wl,-Ttext-segment,0x08048000) — the canonical i386 base, previously
  banned — entry 0x8049020, LOADs at 0x08048000+, exit(0).

Suite: make run PASS exit 33 — 73 tasks incl. ia32test exit(0) at
0x08048000; frames 213333 -> 213333 zero leak on clean runs; ptytest
slave-write EIO flake (run-138 item) still intermittent and still
leaks its 2 ring frames on failing runs — attribution confirmed again
this rung (leak rides with the flake, zero on clean runs).
Audit: scoped quick run (run-1 in the audit output dir) + cve.now
(CVE-2026-99463 page-table lifecycle UAF, CVE-2025-71089 IOMMU
caching kernel PTEs, ret2dir 0 hits, plus the run-172 compat classes
re-checked: CVE-2007-4573/CVE-2010-3301 masking, CVE-2012-0217
iretq-only, CVE-2010-3081 N/A, CVE-2021-47364/CVE-2023-53035 N/A).
Findings: one latent slot-source defect found+fixed+independently
verified (needs_validation record — no runtime trigger until ia32
execve); KRESV overflow now asserts. Hunter subagents and the final
coverage critic were rate-limited; parent performed both passes, so
no independent clean-coverage claim. Follow-on: ia32 execve/clone/
fork/wait4 + set_thread_area TLS; then PE32 loader + int 0x2e.

## run-174 — real i386 busybox runs: set_thread_area + i386 TLS via GDT slots

Milestone: the unmodified Ubuntu i386 static busybox (ELFCLASS32,
linked 0x08048000, 2.0 MB, glibc-static) loads, runs glibc startup,
dispatches its multicall applet from argv[0], calls sys_uname and
prints "Rustux" to the console, then exit(0). Proof task is the
initrd entry named "uname" (the cpio name IS argv[0]).

* Root blocker was TLS: static i386 glibc calls set_thread_area
  (nr 243) before it touches %gs-based errno/TCB. Implemented:
  - cpu.rs: GDT grown to 12 slots; 8-11 are the TLS entries
    (selectors 0x43/0x4b/0x53/0x5b). install_tls(slot, desc) writes
    a slot (long mode re-reads GDT memory per segment load — no
    lgdt needed); load_gs(sel) lets CPL0 reload a DPL3 data segment
    (max(CPL,RPL)<=DPL). GDTR limit now derived from the array.
  - Task gains tls:[u64;4] + gs_sel:u16; inherited at fork/clone,
    reset at NT thread creation. switch_to installs all four slots
    from the incoming task and reloads its %gs selector (0 clears).
  - sys_set_thread_area (compat-only): validates the 16-byte
    struct user_desc — the flags are ONE u32 bitfield at offset 12
    (seg_32bit:1, contents:2, read_exec_only:1, limit_in_pages:1,
    seg_not_present:1, useable:1, lm:1) — builds the descriptor the
    way fill_ldt does (DPL forced 3, S=1, ACCESS bit set), entry -1
    picks the first free slot, explicit entries must be 8..11,
    writes the entry NUMBER back (glibc derives sel = entry*8+3).
* Three bugs found by boot:
  1. descriptor packing dropped base31_24 (<<56) — glibc's TLS base
     0x0824c380 arrived as 0x24c380 -> gs:8 #PF.
  2. user_desc flag offsets: they are a bitfield u32 at 12, not six
     u16s (the first cut read garbage).
  3. IA-32e takes FS/GS BASE from the MSR whenever the segment is
     loaded at CPL0 in 64-bit mode — the descriptor alone is not
     enough. Fixed by mirroring base_addr into t.gs_base (written to
     MSR_GS_BASE on every switch); a compat-mode load (the task's
     own `mov gs`) reads the descriptor, which carries the same base.
* New ia32 nrs, each reusing a validated 64-bit implementation:
  172 prctl, 191 ugetrlimit (i386 rlimit32, 8 bytes), 243
  set_thread_area, 305 readlinkat, 311 set_robust_list (len==12),
  386 rseq (32-byte struct). Still ENOSYS (recorded divergences):
  300 fstatat64 (i386 stat64 layout — next rung's struct shims),
  383 name_to_handle_at. Busybox tolerates both.
* Makefile: kernel/user/busybox-i386 (Ubuntu busybox-static:i386
  1:1.36.1) added to USER_ELFS + initrd as "uname"; lstest count 56.

Suite: make run PASS exit 33 — 74 tasks incl. ia32test exit(0) and
uname exit(0) with "Rustux" on the console; frames 213330 -> 213330
zero leak on the clean run. Known flakes seen and attributed: ptytest
slave-write EIO (run-138 item; its 2-frame leak rides with the failing
run) and one run-147-class userspace stall after bashtest (heartbeat
spinning, no progress) that cleared on re-run.
Audit: scoped quick run (run-2) + cve.now (TLS/GDT descriptor class,
CVE-2014-9322-family IRET segment confusion — N/A, no kernel-mode iret
with a user segment). No findings; DPL forced 3 and u32 bases keep
%gs inside the task's own U/S checks. Parent performed hunt/critic
inline (rate limit) — no independent clean-coverage claim.
Follow-on: ia32 fstatat64/stat64 + timeval32/iovec32 shims (unblocks
`ls`, `cat`, `sh` applets), then fork/clone/execve/wait4 + ia32
signal frames (makes the run-173 slot-source fix's validation plan
executable).

## run-175 — i386 stat64 shims: fstatat64/stat64/statx/clock_gettime32

glibc's stat family on i386 lands on fstatat64 (300) and friends, and
its struct stat64 is the PACKED 96-byte i386 layout — not the 144-byte
x86_64 struct stat the kernel already produced. This rung adds the
compat shims; `busybox ls` now lists the root directory (openat +
getdents64 + fstatat64 + statx all green; it exits 1 only because a
linktest scratch symlink vanished between getdents and stat — a real
race, not an ABI failure).

* user.rs: emit_stat64() — builds the packed layout into a zeroed
  [u8;96] with explicit LE field writes (dev@0, __st_ino@12, mode@16,
  nlink@20, uid@24, gid@28, rdev@32, size@44, blksize@52, blocks@56,
  atime@64, mtime@72, ctime@80, ino@88) then one bounded copy-out.
  newfstatat32() — empty path only under AT_EMPTY_PATH (stats the
  dirfd), else fill_stat's canon/getname discipline.
  sys_clock_gettime32() — timespec32 (two i32) for ia32 nr 265.
* syscall.rs: sys_fstatat64() helper (NULL path requires
  AT_EMPTY_PATH) + ia32 arms 195 stat64, 196 lstat64, 197 fstat64,
  265 clock_gettime32, 295 openat, 300 fstatat64, 383 statx,
  403 clock_gettime64.
* ia32test.c: compiled proof — sizeof(struct stat64)==96, openat +
  fstat64 regular-file fields, fstatat64 by path, AT_SYMLINK_NOFOLLOW,
  fstat64 on the console fd (S_IFCHR), statx mask/size, timespec32 and
  timespec64 clock_gettime. All pass (ia32test exit(0)).

Divergences still open: i386 old-style stat/lstat/fstat (106/107/108,
__old_kernel_stat) unwired — modern glibc never uses them; stat64
32-bit time fields truncate past 2038 (statx carries 64-bit times).

Suite: make run PASS exit 33 — 74 tasks incl. ia32test exit(0) and
uname exit(0) printing "Rustux"; frames 213330 -> 213330 zero leak on
the clean run. ptytest slave-write EIO flake seen again (its 2-frame
leak rides with the failing run) — unchanged run-138 item.
Audit: scoped quick run (run-3). No findings; every arm routes to an
already-validated implementation or writes a fixed-size struct into a
range_ok_w range, padding always zeroed. Parent performed hunt/critic
inline (rate limit) — no independent clean-coverage claim.
Follow-on: ia32 fork/clone/execve/wait4 + ia32 signal frames (also
makes run-173's slot-source fix validation plan executable), then
timeval32/iovec32 shims.
