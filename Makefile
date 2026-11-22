# Rustux: run inside WSL (Ubuntu). `make run` builds the kernel, packs it
# into a read-only FAT disk image, and boots it in QEMU; the kernel prints over
# COM1 and exits QEMU via isa-debug-exit.
#
# The ESP is a real disk image (esp.img), not a QEMU vvfat share: vvfat maps
# guest writes onto host files, which would let anything running in the VM
# overwrite esp/EFI/BOOT/BOOTX64.EFI in this directory.

ESP      := esp
ESP_IMG  := esp.img
OVMF     ?= /usr/share/ovmf/OVMF.fd
QEMU     ?= qemu-system-x86_64
TARGET   := x86_64-unknown-uefi
KERNEL   := target/$(TARGET)/release/kernel.efi

# demo_net gates the socket-link protocol demos (ipv8/ipv6/tcp
# selftests driven by the MAC-byte role check). Enabled for `run` and
# `demo` (the two-guest proof image); a plain `make build` produces a
# kernel with no demo code paths at all.
DEMO_RUSTFLAGS := --cfg demo_net

.PHONY: build run demo clean FORCE

build: $(ESP_IMG)

# `run`/`demo` propagate this to the $(KERNEL) recipe below; FORCE
# makes the kernel/esp recipes always re-run so cargo (not make's
# timestamps) decides — RUSTFLAGS changes invalidate the fingerprint.
run demo: RUSTFLAGS = $(DEMO_RUSTFLAGS)
export RUSTFLAGS

demo: $(ESP_IMG)
	@echo "demo image (demo_net) ready at $(ESP_IMG)"

FORCE:

# Ring-3 milestone images: static ELF64s loaded by kernel/src/elf.rs.
USER_ELFS := kernel/user/hello.elf kernel/user/selftest.elf kernel/user/fstest.elf kernel/user/lstest.elf kernel/user/exectest.elf kernel/user/spinA.elf kernel/user/spinB.elf kernel/user/forktest.elf kernel/user/pipetest.elf kernel/user/sigtest.elf kernel/user/faulttest.elf kernel/user/fputest.elf kernel/user/sigfault.elf kernel/user/polltest.elf kernel/user/udptest.elf kernel/user/tcptest.elf kernel/user/mmtest.elf kernel/user/realbin.elf kernel/user/parent.elf kernel/user/iotest.elf kernel/user/shelltest.elf kernel/user/wiotest.elf kernel/user/termtest.elf kernel/user/kbdtest.elf kernel/user/rsh.elf kernel/user/rshtest.elf kernel/user/vmtest.elf kernel/user/fxtest.elf kernel/user/ftest.elf kernel/user/thrtest.elf kernel/user/aptest.elf kernel/user/clftest.elf kernel/user/dtest.elf kernel/user/fmaptest.elf kernel/user/bbtest.elf kernel/user/vtest.elf kernel/user/dyntest.elf kernel/user/dashtest.elf kernel/user/rtest.elf kernel/user/bashtest.elf kernel/user/pgtest.elf kernel/user/ttoutest.elf kernel/user/petest kernel/user/peitest kernel/user/hello_win.exe kernel/user/crt_hello.exe
INITRD    := initrd.cpio

kernel/user/%.elf: kernel/user/%.S
	as -o kernel/user/$*.o $<
	ld -nostdlib -e _start -Ttext 0x555500000000 -o $@ kernel/user/$*.o

# petest is a real PE32+ .exe — flat code wrapped by mkpe.py; the
# kernel detects MZ and runs it under the NT personality.
kernel/user/petest: kernel/user/petest.S tools/mkpe.py
	as -o kernel/user/petest.o $<
	objcopy -O binary kernel/user/petest.o kernel/user/petest.bin
	python3 tools/mkpe.py kernel/user/petest.bin $@

kernel/user/peitest: kernel/user/peitest.S tools/mkpe.py
	as -o kernel/user/peitest.o $<
	objcopy -O binary kernel/user/peitest.o kernel/user/peitest.bin
	python3 tools/mkpe.py kernel/user/peitest.bin $@

# Real-binary tests: GCC static-PIE — glibc self-relocates, so the
# kernel just maps PT_LOADs at LOAD_BIAS and jumps to entry.
kernel/user/%.elf: kernel/user/%.c
	gcc -static-pie -O2 -o $@ $<

# dyntest is deliberately DYNAMIC — PT_INTERP names the real glibc
# loader, which the kernel maps into the mmap arena; ld.so then maps
# libc.so.6 itself via the rpath. The loader+libc are staged from the
# build host at initrd time so they always match the gcc that built
# the test (no binaries committed).
kernel/user/dyntest.elf: kernel/user/dyntest.c
	gcc -O2 -Wl,-rpath,/lib/x86_64-linux-gnu -o $@ $<

# The initrd: a newc cpio archive carrying the user images plus a data
# file, read from the ESP by the kernel before ExitBootServices. The
# archive doubles as the fd layer's read-only root filesystem.
$(INITRD): $(USER_ELFS) kernel/user/busybox kernel/user/dash kernel/user/bash kernel/user/libtinfo.so.6 kernel/user/motd.txt tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6
	python3 tools/mkinitrd.py kernel/user/hello.elf init kernel/user/selftest.elf selftest kernel/user/fstest.elf fstest kernel/user/lstest.elf lstest kernel/user/exectest.elf exectest kernel/user/spinA.elf spinA kernel/user/spinB.elf spinB kernel/user/forktest.elf forktest kernel/user/pipetest.elf pipetest kernel/user/sigtest.elf sigtest kernel/user/faulttest.elf faulttest kernel/user/fputest.elf fputest kernel/user/sigfault.elf sigfault kernel/user/polltest.elf polltest kernel/user/udptest.elf udptest kernel/user/tcptest.elf tcptest kernel/user/mmtest.elf mmtest kernel/user/realbin.elf realbin kernel/user/parent.elf parent kernel/user/iotest.elf iotest kernel/user/shelltest.elf shelltest kernel/user/wiotest.elf wiotest kernel/user/termtest.elf termtest kernel/user/kbdtest.elf kbdtest kernel/user/rsh.elf rsh kernel/user/rshtest.elf rshtest kernel/user/vmtest.elf vmtest kernel/user/fxtest.elf fxtest kernel/user/ftest.elf ftest kernel/user/thrtest.elf thrtest kernel/user/aptest.elf aptest kernel/user/clftest.elf clftest kernel/user/dtest.elf dtest kernel/user/fmaptest.elf fmaptest kernel/user/bbtest.elf bbtest kernel/user/vtest.elf vtest kernel/user/dyntest.elf dyntest kernel/user/dashtest.elf dashtest kernel/user/rtest.elf rtest kernel/user/bashtest.elf bashtest kernel/user/pgtest.elf pgtest kernel/user/petest petest kernel/user/peitest peitest kernel/user/hello_win.exe hello_win kernel/user/crt_hello.exe crt_hello kernel/user/busybox busybox kernel/user/dash bin/dash kernel/user/bash bin/bash kernel/user/libtinfo.so.6 lib/x86_64-linux-gnu/libtinfo.so.6 kernel/user/motd.txt motd.txt /lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 > $@

$(KERNEL): kernel/src/*.rs kernel/Cargo.toml klib/src/*.rs klib/Cargo.toml Cargo.toml kernel/user/hello.elf FORCE
	cargo build --release --target $(TARGET) -p kernel

$(ESP_IMG): $(KERNEL) $(INITRD)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD) ::/initrd.cpio

run: build
	$(QEMU) \
		-machine q35 \
		-m 512M \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_IMG),format=raw,if=ide \
		-snapshot \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "boot test: PASS (qemu exit 33)"; \
	else echo "boot test: FAIL (qemu exit $$status)"; exit 1; fi

INITRD_BASH := initrd-bash.cpio
ESP_BASH    := esp-bash.img

# Interactive login shell on the serial console: a solo initrd whose
# only task is -bash (the argv0 dash makes it a login shell). Type
# into the terminal — UART RX feeds the tty ldisc like kbd scancodes.
$(INITRD_BASH): kernel/user/bash kernel/user/libtinfo.so.6 kernel/user/motd.txt tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6
	python3 tools/mkinitrd.py kernel/user/bash -bash /lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 kernel/user/libtinfo.so.6 lib/x86_64-linux-gnu/libtinfo.so.6 kernel/user/motd.txt motd.txt > $@

$(ESP_BASH): $(KERNEL) $(INITRD_BASH)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD_BASH) ::/initrd.cpio

run-bash: $(ESP_BASH)
	$(QEMU) \
		-machine q35 \
		-m 512M \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_BASH),format=raw,if=ide \
		-snapshot \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot

INITRD_TOUT := initrd-ttout.cpio
ESP_TOUT    := esp-ttout.img

# TOSTOP/SIGTTOU gate test: a SOLO initrd — with TOSTOP armed, every
# task of the console's session writing from a background pgrp is
# stopped for good (nobody job-controls it back), so ttoutest must
# own the whole run rather than sharing the standard suite.
$(INITRD_TOUT): kernel/user/ttoutest.elf tools/mkinitrd.py
	python3 tools/mkinitrd.py kernel/user/ttoutest.elf ttoutest > $@

$(ESP_TOUT): $(KERNEL) $(INITRD_TOUT)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD_TOUT) ::/initrd.cpio

run-ttout: $(ESP_TOUT)
	$(QEMU) \
		-machine q35 \
		-m 512M \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_TOUT),format=raw,if=ide \
		-snapshot \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot

INITRD_DEMO := initrd-demo.cpio
ESP_DEMO    := esp-demo.img

# Scripted bash demo for docs/assets/rustux-bash.gif: demodrv is the
# solo task — it prints the interactive prompt + "typed" lines and
# execs real /bin/bash -c per command, so every output byte is real
# bash under real fork/exec/ld.so. (Headless QEMU 8.2.2 cannot feed
# UART input while a capture channel is up, so the session is
# scripted guest-side; live input is proven by run-bash.)
$(INITRD_DEMO): kernel/user/demodrv.elf kernel/user/bash kernel/user/busybox kernel/user/libtinfo.so.6 kernel/user/motd.txt tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6
	python3 tools/mkinitrd.py kernel/user/demodrv.elf demodrv kernel/user/bash bin/bash kernel/user/busybox bin/busybox /lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 kernel/user/libtinfo.so.6 lib/x86_64-linux-gnu/libtinfo.so.6 kernel/user/motd.txt motd.txt > $@

$(ESP_DEMO): $(KERNEL) $(INITRD_DEMO)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD_DEMO) ::/initrd.cpio

run-demo: $(ESP_DEMO)
	$(QEMU) \
		-machine q35 \
		-m 512M \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_DEMO),format=raw,if=ide \
		-snapshot \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "demo: PASS (qemu exit 33)"; \
	else echo "demo: FAIL (qemu exit $$status)"; exit 1; fi

clean:
	cargo clean
	rm -rf $(ESP) $(ESP_IMG)
