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
USER_ELFS := kernel/user/hello.elf kernel/user/selftest.elf kernel/user/fstest.elf kernel/user/lstest.elf kernel/user/exectest.elf kernel/user/spinA.elf kernel/user/spinB.elf kernel/user/forktest.elf kernel/user/pipetest.elf kernel/user/sigtest.elf kernel/user/faulttest.elf kernel/user/fputest.elf kernel/user/sigfault.elf kernel/user/polltest.elf kernel/user/udptest.elf kernel/user/tcptest.elf kernel/user/mmtest.elf kernel/user/realbin.elf kernel/user/parent.elf kernel/user/iotest.elf kernel/user/shelltest.elf kernel/user/wiotest.elf kernel/user/termtest.elf kernel/user/kbdtest.elf kernel/user/rsh.elf kernel/user/rshtest.elf kernel/user/vmtest.elf kernel/user/fxtest.elf kernel/user/ftest.elf kernel/user/thrtest.elf kernel/user/aptest.elf kernel/user/clftest.elf kernel/user/dtest.elf kernel/user/fmaptest.elf kernel/user/bbtest.elf kernel/user/vtest.elf kernel/user/dyntest.elf kernel/user/dashtest.elf kernel/user/rtest.elf kernel/user/bashtest.elf kernel/user/pgtest.elf kernel/user/ttoutest.elf kernel/user/petest kernel/user/peitest kernel/user/hello_win.exe kernel/user/crt_hello.exe kernel/user/winfile.exe kernel/user/windir.exe kernel/user/winheap.exe.gz kernel/user/winmisc.exe.gz kernel/user/winmem.exe.gz kernel/user/winthr.exe.gz kernel/user/winmap.exe.gz kernel/user/windll.dll.gz kernel/user/windlltest.exe.gz kernel/user/wbase.dll.gz kernel/user/wchain.dll.gz kernel/user/winchain.exe.gz kernel/user/winstatic.exe.gz kernel/user/windetach.exe.gz kernel/user/windexit.exe.gz kernel/user/winthrnt.exe.gz kernel/user/winchild.exe.gz kernel/user/winspawn.exe.gz kernel/user/winsys.exe.gz kernel/user/winfs2.exe.gz kernel/user/htoptest.elf kernel/user/nettest.elf kernel/user/wgettest.elf kernel/user/debtest.elf kernel/user/linktest.elf kernel/user/dpkgtest.elf kernel/user/alarmtest.elf kernel/user/nbtest.elf kernel/user/ia32test.elf kernel/user/ia32child.elf kernel/user/blktest.elf kernel/user/hvctest.elf kernel/user/vintest.elf kernel/user/sgtest.elf kernel/user/nvmtest.elf kernel/user/pkttest.elf kernel/user/unixtest.elf kernel/user/nltest.elf kernel/user/tuntest.elf kernel/user/memfdtest.elf kernel/user/pidfdtest.elf kernel/user/cl3test.elf kernel/user/oa2test.elf kernel/user/fxvtest.elf kernel/user/mm3test.elf kernel/user/ft2test.elf kernel/user/pmtvtest.elf kernel/user/msltest.elf kernel/user/xattest.elf kernel/user/xat2test.elf kernel/user/seltest.elf kernel/user/shmtest.elf kernel/user/pmvtest.elf kernel/user/stest.elf kernel/user/fatest.elf kernel/user/sptest.elf kernel/user/schtest.elf kernel/user/credtest.elf kernel/user/msgtest.elf kernel/user/semtest.elf kernel/user/ptmtest.elf kernel/user/busybox-i386
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

# ia32test is ELFCLASS32/EM_386 — gcc -m32 with no libc at all, raw
# int 0x80 syscalls. Linked at 0x08048000, the canonical i386 load
# base real 32-bit binaries use — reachable now that the physmap
# opened the whole below-4GiB compat window. More specific than the
# .c pattern rule above, so make prefers it.
kernel/user/ia32test.elf: kernel/user/ia32test.c
	gcc -m32 -static -nostdlib -no-pie -Wl,-Ttext-segment,0x08048000 -O2 -o $@ $<

kernel/user/ia32child.elf: kernel/user/ia32child.c
	gcc -m32 -static -nostdlib -no-pie -Wl,-Ttext-segment,0x08048000 -O2 -o $@ $<

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
$(INITRD): $(USER_ELFS) kernel/user/busybox kernel/user/dash kernel/user/bash kernel/user/libtinfo.so.6 kernel/user/libncursesw.so.6 kernel/user/libm.so.6 kernel/user/libnl-3.so.200 kernel/user/libnl-genl-3.so.200 kernel/user/htop kernel/user/motd.txt kernel/user/winseed.txt kernel/user/busybox-i386 kernel/user/terminfo_x/xterm kernel/user/dpkg kernel/user/dpkg-deb kernel/user/dpkg-query kernel/user/dpkg-split kernel/user/tar kernel/user/ldconfig kernel/user/libdpkg/libmd.so.0 kernel/user/libdpkg/libselinux.so.1 kernel/user/libdpkg/libpcre2-8.so.0 kernel/user/libdpkg/libacl.so.1 kernel/user/libdpkg/libz.so.1 kernel/user/libdpkg/liblzma.so.5 kernel/user/libdpkg/libzstd.so.1 kernel/user/libdpkg/libbz2.so.1.0 tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6
	python3 tools/mkinitrd.py kernel/user/hello.elf init kernel/user/selftest.elf selftest kernel/user/fstest.elf fstest kernel/user/lstest.elf lstest kernel/user/exectest.elf exectest kernel/user/spinA.elf spinA kernel/user/spinB.elf spinB kernel/user/forktest.elf forktest kernel/user/pipetest.elf pipetest kernel/user/sigtest.elf sigtest kernel/user/faulttest.elf faulttest kernel/user/fputest.elf fputest kernel/user/sigfault.elf sigfault kernel/user/polltest.elf polltest kernel/user/udptest.elf udptest kernel/user/tcptest.elf tcptest kernel/user/mmtest.elf mmtest kernel/user/realbin.elf realbin kernel/user/parent.elf parent kernel/user/iotest.elf iotest kernel/user/shelltest.elf shelltest kernel/user/wiotest.elf wiotest kernel/user/termtest.elf termtest kernel/user/kbdtest.elf kbdtest kernel/user/rsh.elf rsh kernel/user/rshtest.elf rshtest kernel/user/vmtest.elf vmtest kernel/user/fxtest.elf fxtest kernel/user/ftest.elf ftest kernel/user/thrtest.elf thrtest kernel/user/aptest.elf aptest kernel/user/clftest.elf clftest kernel/user/dtest.elf dtest kernel/user/fmaptest.elf fmaptest kernel/user/bbtest.elf bbtest kernel/user/vtest.elf vtest kernel/user/dyntest.elf dyntest kernel/user/dashtest.elf dashtest kernel/user/rtest.elf rtest kernel/user/bashtest.elf bashtest kernel/user/pgtest.elf pgtest kernel/user/petest petest kernel/user/peitest peitest kernel/user/hello_win.exe hello_win kernel/user/crt_hello.exe crt_hello kernel/user/winfile.exe winfile kernel/user/windir.exe windir kernel/user/winheap.exe.gz winheap kernel/user/winmisc.exe.gz winmisc kernel/user/winmem.exe.gz winmem kernel/user/winthr.exe.gz winthr kernel/user/winmap.exe.gz winmap kernel/user/windll.dll.gz windll.dll kernel/user/windlltest.exe.gz windlltest kernel/user/wbase.dll.gz wbase.dll kernel/user/wchain.dll.gz wchain.dll kernel/user/winchain.exe.gz winchain kernel/user/winstatic.exe.gz winstatic kernel/user/windetach.exe.gz windetach kernel/user/windexit.exe.gz windexit kernel/user/winthrnt.exe.gz winthrnt kernel/user/winchild.exe.gz winchild.exe kernel/user/winspawn.exe.gz winspawn kernel/user/winsys.exe.gz winsys kernel/user/winfs2.exe.gz winfs2 kernel/user/winseed.txt winseed.txt kernel/user/busybox busybox kernel/user/dash bin/dash kernel/user/bash bin/bash kernel/user/libtinfo.so.6 lib/x86_64-linux-gnu/libtinfo.so.6 kernel/user/htoptest.elf htoptest kernel/user/nettest.elf nettest kernel/user/htop bin/htop kernel/user/wgettest.elf wgettest kernel/user/resolv.conf etc/resolv.conf kernel/user/debtest.elf debtest kernel/user/linktest.elf linktest kernel/user/dpkgtest.elf dpkgtest kernel/user/alarmtest.elf alarmtest kernel/user/nbtest.elf nbtest kernel/user/blktest.elf blktest kernel/user/ia32test.elf ia32test kernel/user/ia32child.elf ia32child kernel/user/busybox-i386 uname kernel/user/ptytest.elf ptytest kernel/user/hvctest.elf hvctest kernel/user/vintest.elf vintest kernel/user/sgtest.elf sgtest kernel/user/nvmtest.elf nvmtest kernel/user/pkttest.elf pkttest kernel/user/unixtest.elf unixtest kernel/user/nltest.elf nltest kernel/user/tuntest.elf tuntest kernel/user/memfdtest.elf memfdtest kernel/user/pidfdtest.elf pidfdtest kernel/user/cl3test.elf cl3test kernel/user/oa2test.elf oa2test kernel/user/fxvtest.elf fxvtest kernel/user/mm3test.elf mm3test kernel/user/ft2test.elf ft2test kernel/user/pmtvtest.elf pmtvtest kernel/user/msltest.elf msltest kernel/user/xattest.elf xattest kernel/user/xat2test.elf xat2test kernel/user/seltest.elf seltest kernel/user/shmtest.elf shmtest kernel/user/pmvtest.elf pmvtest kernel/user/stest.elf stest kernel/user/fatest.elf fatest kernel/user/sptest.elf sptest kernel/user/schtest.elf schtest kernel/user/credtest.elf credtest kernel/user/msgtest.elf msgtest kernel/user/semtest.elf semtest kernel/user/ptmtest.elf ptmtest kernel/user/hello-traditional_2.10-6_amd64.deb hello-traditional_2.10-6_amd64.deb kernel/user/dpkg usr/bin/dpkg kernel/user/dpkg-deb usr/bin/dpkg-deb kernel/user/dpkg-query usr/bin/dpkg-query kernel/user/dpkg-split usr/bin/dpkg-split kernel/user/tar bin/tar kernel/user/dash bin/sh kernel/user/busybox bin/rm kernel/user/busybox bin/diff kernel/user/busybox bin/cat kernel/user/busybox sbin/start-stop-daemon kernel/user/ldconfig sbin/ldconfig kernel/user/ldconfig usr/sbin/ldconfig kernel/user/libdpkg/libmd.so.0 lib/x86_64-linux-gnu/libmd.so.0 kernel/user/libdpkg/libselinux.so.1 lib/x86_64-linux-gnu/libselinux.so.1 kernel/user/libdpkg/libpcre2-8.so.0 lib/x86_64-linux-gnu/libpcre2-8.so.0 kernel/user/libdpkg/libacl.so.1 lib/x86_64-linux-gnu/libacl.so.1 kernel/user/libdpkg/libz.so.1 lib/x86_64-linux-gnu/libz.so.1 kernel/user/libdpkg/liblzma.so.5 lib/x86_64-linux-gnu/liblzma.so.5 kernel/user/libdpkg/libzstd.so.1 lib/x86_64-linux-gnu/libzstd.so.1 kernel/user/libdpkg/libbz2.so.1.0 lib/x86_64-linux-gnu/libbz2.so.1.0 kernel/user/libncursesw.so.6 lib/x86_64-linux-gnu/libncursesw.so.6 kernel/user/libm.so.6 lib/x86_64-linux-gnu/libm.so.6 kernel/user/libnl-3.so.200 lib/x86_64-linux-gnu/libnl-3.so.200 kernel/user/libnl-genl-3.so.200 lib/x86_64-linux-gnu/libnl-genl-3.so.200 kernel/user/terminfo_x/xterm usr/share/terminfo/x/xterm kernel/user/motd.txt motd.txt /lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 > $@

# A REAL ext2 image for the driver's boot-time test: mke2fs writes it,
# the kernel include_bytes!s it. Built before cargo runs so the file
# always exists at compile time. Generated, never committed.
EXT2_TEST := kernel/src/ext2_test.img
$(EXT2_TEST): FORCE
	rm -f $@
	dd if=/dev/zero of=$@ bs=1M count=4 2>/dev/null
	mkdir -p /tmp/ext2src
	printf 'hello ext2\n' > /tmp/ext2src/hi.txt
	mke2fs -q -t ext2 -b 1024 -I 256 -d /tmp/ext2src $@

# ext3/ext4 proofs: same mke2fs -d contract. ext4's big.bin is sparse
# with 8 holes — enough extents to force a depth-1 extent tree, so the
# index->leaf walk runs on a real Linux-written image.
EXT3_TEST := kernel/src/ext3_test.img
$(EXT3_TEST): FORCE
	rm -f $@
	dd if=/dev/zero of=$@ bs=1M count=4 2>/dev/null
	mkdir -p /tmp/ext3src
	printf 'hello ext3\n' > /tmp/ext3src/hi.txt
	mke2fs -q -t ext3 -b 1024 -I 256 -d /tmp/ext3src $@

EXT4_TEST := kernel/src/ext4_test.img
$(EXT4_TEST): FORCE
	rm -f $@
	dd if=/dev/zero of=$@ bs=1M count=8 2>/dev/null
	rm -rf /tmp/ext4src && mkdir -p /tmp/ext4src
	printf 'hello ext4\n' > /tmp/ext4src/hi.txt
	python3 -c "f=open('/tmp/ext4src/big.bin','wb'); \
	    [ (f.seek(i*2*4096), f.write((b'chunk%d-'%i)*512)) for i in range(8) ]; \
	    f.truncate(16*4096); f.close()"
	mke2fs -q -t ext4 -b 1024 -I 256 -d /tmp/ext4src $@

# virtio-blk proof for `make run`: a whole-disk image with a real MBR
# partition holding the ext4 test filesystem — the boot scan mounts it
# over the virtqueue datapath, end-to-end.
VIRTIO_DISK := kernel/src/virtio_test.img
# GPT-partitioned twin: the scan must mount the ext4 partition via
# the GPT path, not the MBR path.
GPT_DISK := kernel/src/gpt_test.img
$(GPT_DISK): $(EXT4_TEST) tools/mkgpt.py
	python3 tools/mkgpt.py $@ $(EXT4_TEST)
$(VIRTIO_DISK): $(EXT4_TEST)
	dd if=/dev/zero of=$@ bs=1M count=16 2>/dev/null
	dd if=$(EXT4_TEST) of=$@ bs=512 seek=2048 conv=notrunc 2>/dev/null
	python3 -c "import struct; \
	    d=bytearray(512); \
	    d[446+4]=0x83; \
	    struct.pack_into('<II', d, 446+8, 2048, 32768-2048); \
	    d[510]=0x55; d[511]=0xaa; \
	    open('$@','r+b').write(d)"

$(KERNEL): kernel/src/*.rs kernel/Cargo.toml klib/src/*.rs klib/Cargo.toml Cargo.toml kernel/user/hello.elf $(EXT2_TEST) $(EXT3_TEST) $(EXT4_TEST) FORCE
	cargo build --release --target $(TARGET) -p kernel

$(ESP_IMG): $(KERNEL) $(INITRD)
	dd if=/dev/zero of=$@ bs=1M count=128
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD) ::/initrd.cpio

TEST_ISO := kernel/src/cdtest.iso

$(TEST_ISO):
	mkdir -p /tmp/cdroot && printf 'cdrom-proof\n' > /tmp/cdroot/proof.txt
	mkisofs -quiet -o $@ -V RUSTUX-TEST /tmp/cdroot

run: build $(VIRTIO_DISK) $(GPT_DISK) $(TEST_ISO)
	rm -f /tmp/hvc.sock /tmp/hvc_captured.log; python3 tools/hvcfeed.py & \
	rm -f /tmp/vkbd-qmp.sock; python3 tools/kbdfeed.py & \
	rm -f /tmp/balloon-qmp.sock /tmp/balloon_proof.log; python3 tools/balloonfeed.py & \
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_IMG),format=raw,if=ide \
		-drive file=$(TEST_ISO),format=raw,media=cdrom,if=ide,index=2 \
		-drive file=$(VIRTIO_DISK),format=raw,if=virtio \
		-drive file=$(VIRTIO_DISK),format=raw,if=none,id=nvm0 \
		-drive file=$(VIRTIO_DISK),format=raw,if=none,id=nvm1 \
		-drive file=$(GPT_DISK),format=raw,if=none,id=nvm2 \
		-device nvme,id=nvme0,serial=nv0 \
		-device nvme-ns,drive=nvm0,nsid=1 \
		-device nvme-ns,drive=nvm1,nsid=2 \
		-device nvme-ns,drive=nvm2,nsid=3 \
		-netdev user,id=n0 -device e1000e,netdev=n0 \
		-netdev user,id=n1 -device virtio-net-pci-non-transitional,netdev=n1 \
		-device virtio-rng-pci \
		-device virtio-serial-pci \
		-chardev socket,path=/tmp/hvc.sock,server=on,wait=off,id=vc0 \
		-device virtconsole,chardev=vc0 \
		-device virtio-keyboard-pci \
		-qmp unix:/tmp/vkbd-qmp.sock,server=on,wait=off \
		-device virtio-balloon-pci \
		-device virtio-scsi-pci \
		-drive file=$(VIRTIO_DISK),format=raw,if=none,id=sc0 \
		-device scsi-hd,drive=sc0 \
		-qmp unix:/tmp/balloon-qmp.sock,server=on,wait=off \
		-snapshot \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "boot test: PASS (qemu exit 33)"; \
	else echo "boot test: FAIL (qemu exit $$status)"; exit 1; fi

# Visible-display variant: opens a QEMU window so the boot can be
# watched on the emulated framebuffer (the kernel paints its console
# there via fbcon). Serial still goes to the terminal, so the PASS
# line and the per-task exits stay visible. DISPLAY is honored by
# QEMU's gtk backend; override with `make run-gui DISPLAY_MODE=sdl`.
DISPLAY_MODE ?= gtk
run-gui: build
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_IMG),format=raw,if=ide \
		-snapshot \
		-serial stdio -display $(DISPLAY_MODE) \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "boot test: PASS (qemu exit 33)"; \
	else echo "boot test: FAIL (qemu exit $$status)"; exit 1; fi

INITRD_BASH := initrd-bash.cpio

# Same suite with QEMU user networking (slirp) + an e1000e NIC: the
# kernel probe runs the wire selftests + DHCP at boot, and nettest
# does real DNS/TCP/HTTP through slirp instead of skipping.
run-net: build
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_IMG),format=raw,if=ide \
		-snapshot \
		-netdev user,id=n0 \
		-device e1000e,netdev=n0 \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "boot test: PASS (qemu exit 33)"; \
	else echo "boot test: FAIL (qemu exit $$status)"; exit 1; fi

# Same suite with the virtio-net NIC as the ONLY link — proves the
# socket layer rides the virtio datapath (identity seeded statically,
# no e1000 DHCP): ARP/TX/RX all cross the virtqueue.
run-vnet: build
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_IMG),format=raw,if=ide \
		-snapshot \
		-netdev user,id=n1 -device virtio-net-pci-non-transitional,netdev=n1 \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "boot test: PASS (qemu exit 33)"; \
	else echo "boot test: FAIL (qemu exit $$status)"; exit 1; fi

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
		-m 1G \
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
		-m 1G \
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
		-m 1G \
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

INITRD_APT := initrd-apt.cpio
ESP_APT    := esp-apt.img
APTROOT    := kernel/user/aptroot

# Real Debian apt end-to-end: aptprobe stages a minimal apt config
# ([trusted=yes], GzipIndexes, no persistent binary caches — the
# in-RAM VFile ceiling cannot hold the uncompressed index or the
# ~36 MiB srcpkgcache), then execs the real dynamically linked
# apt-get update over slirp. Methods and helper libs are the actual
# Debian binaries. gpgv exits nonzero (no keyring is shipped) and
# apt's http helper can exit 100 after a completed transfer —
# trusted=yes carries apt-get itself through to exit 0.
$(INITRD_APT): kernel/user/aptprobe.elf kernel/user/dpkg kernel/user/dpkg-deb kernel/user/dpkg-split kernel/user/dpkg-query kernel/user/tar kernel/user/ldconfig kernel/user/busybox kernel/user/resolv.conf tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 kernel/user/libdpkg/libacl.so.1 kernel/user/libdpkg/libz.so.1 $(APTROOT)/apt-get $(APTROOT)/apt-helper $(APTROOT)/gpgv $(wildcard $(APTROOT)/methods/*) $(wildcard $(APTROOT)/dpkgtables/*) $(wildcard $(APTROOT)/lib*.so*)
	python3 tools/mkinitrd.py \
		kernel/user/aptprobe.elf aptprobe \
		$(APTROOT)/apt-get usr/bin/apt-get \
		$(APTROOT)/apt-helper usr/lib/apt/apt-helper \
		kernel/user/dpkg usr/bin/dpkg \
		kernel/user/dpkg-deb usr/bin/dpkg-deb \
		kernel/user/dpkg-split usr/bin/dpkg-split \
		kernel/user/dpkg-query usr/bin/dpkg-query \
		kernel/user/tar bin/tar \
		kernel/user/ldconfig sbin/ldconfig \
		kernel/user/ldconfig usr/sbin/ldconfig \
		kernel/user/busybox busybox \
		kernel/user/busybox bin/sh \
		kernel/user/busybox bin/rm \
		kernel/user/busybox bin/diff \
		kernel/user/busybox sbin/start-stop-daemon \
		kernel/user/busybox usr/sbin/start-stop-daemon \
		kernel/user/libdpkg/libacl.so.1 lib/x86_64-linux-gnu/libacl.so.1 \
		kernel/user/libdpkg/libz.so.1 lib/x86_64-linux-gnu/libz.so.1 \
		kernel/user/resolv.conf etc/resolv.conf \
		$(APTROOT)/methods/gpgv usr/lib/apt/methods/gpgv \
		$(APTROOT)/methods/http usr/lib/apt/methods/http \
		$(APTROOT)/methods/store usr/lib/apt/methods/store \
		$(APTROOT)/methods/copy usr/lib/apt/methods/copy \
		$(APTROOT)/methods/file usr/lib/apt/methods/file \
		$(APTROOT)/dpkgtables/cputable usr/share/dpkg/cputable \
		$(APTROOT)/dpkgtables/ostable usr/share/dpkg/ostable \
		$(APTROOT)/dpkgtables/tupletable usr/share/dpkg/tupletable \
		$(APTROOT)/dpkgtables/abitable usr/share/dpkg/abitable \
		$(APTROOT)/libapt-pkg.so.6.0 lib/x86_64-linux-gnu/libapt-pkg.so.6.0 \
		$(APTROOT)/libapt-private.so.0.0 lib/x86_64-linux-gnu/libapt-private.so.0.0 \
		$(APTROOT)/libassuan.so.0 lib/x86_64-linux-gnu/libassuan.so.0 \
		$(APTROOT)/libbz2.so.1.0 lib/x86_64-linux-gnu/libbz2.so.1.0 \
		$(APTROOT)/libcap.so.2 lib/x86_64-linux-gnu/libcap.so.2 \
		$(APTROOT)/libffi.so.8 lib/x86_64-linux-gnu/libffi.so.8 \
		$(APTROOT)/libgcc_s.so.1 lib/x86_64-linux-gnu/libgcc_s.so.1 \
		$(APTROOT)/libgcrypt.so.20 lib/x86_64-linux-gnu/libgcrypt.so.20 \
		$(APTROOT)/libgmp.so.10 lib/x86_64-linux-gnu/libgmp.so.10 \
		$(APTROOT)/libgnutls.so.30 lib/x86_64-linux-gnu/libgnutls.so.30 \
		$(APTROOT)/libgpg-error.so.0 lib/x86_64-linux-gnu/libgpg-error.so.0 \
		$(APTROOT)/libhogweed.so.6 lib/x86_64-linux-gnu/libhogweed.so.6 \
		$(APTROOT)/libidn2.so.0 lib/x86_64-linux-gnu/libidn2.so.0 \
		$(APTROOT)/liblz4.so.1 lib/x86_64-linux-gnu/liblz4.so.1 \
		$(APTROOT)/liblzma.so.5 lib/x86_64-linux-gnu/liblzma.so.5 \
		$(APTROOT)/libmd.so.0 lib/x86_64-linux-gnu/libmd.so.0 \
		$(APTROOT)/libm.so.6 lib/x86_64-linux-gnu/libm.so.6 \
		$(APTROOT)/libnettle.so.8 lib/x86_64-linux-gnu/libnettle.so.8 \
		$(APTROOT)/libnpth.so.0 lib/x86_64-linux-gnu/libnpth.so.0 \
		$(APTROOT)/libp11-kit.so.0 lib/x86_64-linux-gnu/libp11-kit.so.0 \
		$(APTROOT)/libpcre2-8.so.0 lib/x86_64-linux-gnu/libpcre2-8.so.0 \
		$(APTROOT)/libseccomp.so.2 lib/x86_64-linux-gnu/libseccomp.so.2 \
		$(APTROOT)/libselinux.so.1 lib/x86_64-linux-gnu/libselinux.so.1 \
		$(APTROOT)/libstdc++.so.6 lib/x86_64-linux-gnu/libstdc++.so.6 \
		$(APTROOT)/libsystemd.so.0 lib/x86_64-linux-gnu/libsystemd.so.0 \
		$(APTROOT)/libtasn1.so.6 lib/x86_64-linux-gnu/libtasn1.so.6 \
		$(APTROOT)/libudev.so.1 lib/x86_64-linux-gnu/libudev.so.1 \
		$(APTROOT)/libunistring.so.5 lib/x86_64-linux-gnu/libunistring.so.5 \
		$(APTROOT)/libxxhash.so.0 lib/x86_64-linux-gnu/libxxhash.so.0 \
		$(APTROOT)/libz.so.1 lib/x86_64-linux-gnu/libz.so.1 \
		$(APTROOT)/libzstd.so.1 lib/x86_64-linux-gnu/libzstd.so.1 \
		$(APTROOT)/gpgv usr/bin/gpgv \
		/lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 \
		$(APTROOT)/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 > $@

$(ESP_APT): $(KERNEL) $(INITRD_APT)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD_APT) ::/initrd.cpio

run-apt: $(ESP_APT)
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_APT),format=raw,if=ide \
		-snapshot \
		-netdev user,id=n0 \
		-device e1000e,netdev=n0 \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "apt probe: PASS (qemu exit 33)"; \
	else echo "apt probe: FAIL (qemu exit $$status)"; exit 1; fi

# Bootable demo ISO — live session + self-installer. livemenu is the
# solo task (pid1): it offers a live shell or a raw install of
# hd.img (a ready-made FAT boot image carrying this same kernel +
# the live initrd) onto /dev/sda via the ATA PIO driver, then
# reboots. The installed disk boots the same live payload — the
# installer option hides itself there because /hd.img is absent.
INITRD_LIVE := initrd-live.cpio
INITRD_ISO  := initrd-iso.cpio
HD_IMG      := hd.img
ESP_ISO     := esp-iso.img
ISO         := rustux-demo.iso
INSTALLDISK := target.img
ISOROOT     := isoroot

# One real busybox copy + symlink applets (link:<target> is a
# mkinitrd symlink record — multicall resolves argv[0]). A curated
# demo set; unimplemented syscalls just report ENOSYS honestly.
LIVE_PAIRS := \
	kernel/user/livemenu.elf livemenu \
	kernel/user/busybox bin/busybox \
	kernel/user/dash bin/sh \
	kernel/user/dash bin/dash \
	link:/bin/busybox bin/ash \
	link:/bin/busybox bin/ls \
	link:/bin/busybox bin/cat \
	link:/bin/busybox bin/cp \
	link:/bin/busybox bin/mv \
	link:/bin/busybox bin/rm \
	link:/bin/busybox bin/mkdir \
	link:/bin/busybox bin/touch \
	link:/bin/busybox bin/echo \
	link:/bin/busybox bin/pwd \
	link:/bin/busybox bin/df \
	link:/bin/busybox bin/du \
	link:/bin/busybox bin/free \
	link:/bin/busybox bin/ps \
	link:/bin/busybox bin/top \
	link:/bin/busybox bin/uname \
	link:/bin/busybox bin/hostname \
	link:/bin/busybox bin/date \
	link:/bin/busybox bin/mount \
	link:/bin/busybox bin/umount \
	link:/bin/busybox bin/dd \
	link:/bin/busybox bin/sync \
	link:/bin/busybox bin/grep \
	link:/bin/busybox bin/sed \
	link:/bin/busybox bin/diff \
	link:/bin/busybox bin/find \
	link:/bin/busybox bin/xargs \
	link:/bin/busybox bin/sort \
	link:/bin/busybox bin/tr \
	link:/bin/busybox bin/md5sum \
	link:/bin/busybox bin/chown \
	link:/bin/busybox bin/chmod \
	link:/bin/busybox bin/ln \
	link:/bin/busybox bin/rmdir \
	link:/bin/busybox bin/test \
	link:/bin/busybox bin/install \
	link:/bin/busybox bin/mkfifo \
	link:/bin/busybox bin/sleep \
	link:/bin/busybox bin/expr \
	link:/bin/busybox bin/head \
	link:/bin/busybox bin/tail \
	link:/bin/busybox bin/wc \
	link:/bin/busybox bin/more \
	link:/bin/busybox bin/less \
	link:/bin/busybox bin/vi \
	link:/bin/busybox bin/clear \
	link:/bin/busybox bin/which \
	link:/bin/busybox bin/dmesg \
	link:/bin/busybox bin/whoami \
	link:/bin/busybox bin/gzip \
	link:/bin/busybox bin/gunzip \
	link:/bin/busybox bin/basename \
	link:/bin/busybox bin/dirname \
	link:/bin/busybox bin/mktemp \
	link:/bin/busybox bin/readlink \
	link:/bin/busybox bin/cmp \
	link:/bin/busybox bin/cut \
	link:/bin/busybox bin/stat \
	link:/bin/busybox bin/seq \
	link:/bin/busybox bin/true \
	link:/bin/busybox bin/false \
	link:/bin/busybox bin/zcat \
	link:/bin/busybox bin/tee \
	link:/bin/busybox bin/uniq \
	link:/bin/busybox bin/printf \
	link:/bin/busybox usr/bin/env \
	link:/bin/busybox usr/bin/awk \
	link:/bin/busybox usr/bin/realpath \
	link:/bin/busybox usr/bin/getopt \
	link:/bin/busybox usr/bin/flock \
	link:/bin/busybox usr/bin/run-parts \
	link:/bin/busybox usr/bin/sha1sum \
	link:/bin/busybox usr/bin/sha256sum \
	link:/bin/busybox usr/bin/id \
	link:/bin/busybox usr/bin/logname \
	link:/bin/busybox usr/bin/groups \
	link:/bin/busybox sbin/reboot \
	link:/bin/busybox sbin/poweroff \
	link:/bin/busybox sbin/halt \
	kernel/user/bash bin/bash \
	kernel/user/htop bin/htop \
	$(APTROOT)/apt-get usr/bin/apt-get \
	link:/usr/bin/apt-get usr/bin/apt \
	$(APTROOT)/apt-helper usr/lib/apt/apt-helper \
	$(APTROOT)/methods/gpgv usr/lib/apt/methods/gpgv \
	$(APTROOT)/methods/http usr/lib/apt/methods/http \
	$(APTROOT)/methods/store usr/lib/apt/methods/store \
	$(APTROOT)/methods/copy usr/lib/apt/methods/copy \
	$(APTROOT)/methods/file usr/lib/apt/methods/file \
	$(APTROOT)/gpgv usr/bin/gpgv \
	kernel/user/dpkg usr/bin/dpkg \
	kernel/user/dpkg-deb usr/bin/dpkg-deb \
	kernel/user/dpkg-split usr/bin/dpkg-split \
	kernel/user/dpkg-query usr/bin/dpkg-query \
	kernel/user/update-alternatives usr/bin/update-alternatives \
	kernel/user/tar bin/tar \
	kernel/user/ldconfig sbin/ldconfig \
	kernel/user/ldconfig usr/sbin/ldconfig \
	link:/bin/busybox sbin/start-stop-daemon \
	link:/bin/busybox usr/sbin/start-stop-daemon \
	kernel/user/stubs/noinit usr/sbin/update-rc.d \
	kernel/user/stubs/locale usr/bin/locale \
	kernel/user/stubs/getent usr/bin/getent \
	link:/usr/sbin/update-rc.d usr/sbin/invoke-rc.d \
	link:/usr/sbin/update-rc.d usr/bin/deb-systemd-helper \
	link:/usr/sbin/update-rc.d usr/bin/deb-systemd-invoke \
	$(APTROOT)/dpkgtables/cputable usr/share/dpkg/cputable \
	$(APTROOT)/dpkgtables/ostable usr/share/dpkg/ostable \
	$(APTROOT)/dpkgtables/tupletable usr/share/dpkg/tupletable \
	$(APTROOT)/dpkgtables/abitable usr/share/dpkg/abitable \
	$(APTROOT)/libapt-pkg.so.6.0 lib/x86_64-linux-gnu/libapt-pkg.so.6.0 \
	$(APTROOT)/libapt-private.so.0.0 lib/x86_64-linux-gnu/libapt-private.so.0.0 \
	$(APTROOT)/libassuan.so.0 lib/x86_64-linux-gnu/libassuan.so.0 \
	$(APTROOT)/libcap.so.2 lib/x86_64-linux-gnu/libcap.so.2 \
	$(APTROOT)/libffi.so.8 lib/x86_64-linux-gnu/libffi.so.8 \
	$(APTROOT)/libgcc_s.so.1 lib/x86_64-linux-gnu/libgcc_s.so.1 \
	$(APTROOT)/libgcrypt.so.20 lib/x86_64-linux-gnu/libgcrypt.so.20 \
	$(APTROOT)/libgmp.so.10 lib/x86_64-linux-gnu/libgmp.so.10 \
	$(APTROOT)/libgnutls.so.30 lib/x86_64-linux-gnu/libgnutls.so.30 \
	$(APTROOT)/libgpg-error.so.0 lib/x86_64-linux-gnu/libgpg-error.so.0 \
	$(APTROOT)/libhogweed.so.6 lib/x86_64-linux-gnu/libhogweed.so.6 \
	$(APTROOT)/libidn2.so.0 lib/x86_64-linux-gnu/libidn2.so.0 \
	$(APTROOT)/liblz4.so.1 lib/x86_64-linux-gnu/liblz4.so.1 \
	$(APTROOT)/libnettle.so.8 lib/x86_64-linux-gnu/libnettle.so.8 \
	$(APTROOT)/libnpth.so.0 lib/x86_64-linux-gnu/libnpth.so.0 \
	$(APTROOT)/libp11-kit.so.0 lib/x86_64-linux-gnu/libp11-kit.so.0 \
	$(APTROOT)/libseccomp.so.2 lib/x86_64-linux-gnu/libseccomp.so.2 \
	$(APTROOT)/libstdc++.so.6 lib/x86_64-linux-gnu/libstdc++.so.6 \
	$(APTROOT)/libsystemd.so.0 lib/x86_64-linux-gnu/libsystemd.so.0 \
	$(APTROOT)/libtasn1.so.6 lib/x86_64-linux-gnu/libtasn1.so.6 \
	$(APTROOT)/libudev.so.1 lib/x86_64-linux-gnu/libudev.so.1 \
	$(APTROOT)/libunistring.so.5 lib/x86_64-linux-gnu/libunistring.so.5 \
	$(APTROOT)/libxxhash.so.0 lib/x86_64-linux-gnu/libxxhash.so.0 \
	kernel/user/libdpkg/libselinux.so.1 lib/x86_64-linux-gnu/libselinux.so.1 \
	kernel/user/libdpkg/libpcre2-8.so.0 lib/x86_64-linux-gnu/libpcre2-8.so.0 \
	kernel/user/libdpkg/libacl.so.1 lib/x86_64-linux-gnu/libacl.so.1 \
	kernel/user/libdpkg/libz.so.1 lib/x86_64-linux-gnu/libz.so.1 \
	kernel/user/libdpkg/liblzma.so.5 lib/x86_64-linux-gnu/liblzma.so.5 \
	kernel/user/libdpkg/libzstd.so.1 lib/x86_64-linux-gnu/libzstd.so.1 \
	kernel/user/libdpkg/libbz2.so.1.0 lib/x86_64-linux-gnu/libbz2.so.1.0 \
	kernel/user/libdpkg/libmd.so.0 lib/x86_64-linux-gnu/libmd.so.0 \
	kernel/user/aptetc/sources.list etc/apt/sources.list \
	kernel/user/aptetc/99rustux etc/apt/apt.conf.d/99rustux \
	kernel/user/resolv.conf etc/resolv.conf \
	kernel/user/etc/nsswitch.conf etc/nsswitch.conf \
	kernel/user/etc/hosts etc/hosts \
	kernel/user/etc/passwd etc/passwd \
	kernel/user/etc/shadow etc/shadow \
	kernel/user/etc/group etc/group \
	kernel/user/etc/securetty etc/securetty \
	/lib/x86_64-linux-gnu/libnss_dns.so.2 lib/x86_64-linux-gnu/libnss_dns.so.2 \
	/lib/x86_64-linux-gnu/libnss_files.so.2 lib/x86_64-linux-gnu/libnss_files.so.2 \
	/lib/x86_64-linux-gnu/libresolv.so.2 lib/x86_64-linux-gnu/libresolv.so.2 \
	kernel/user/libncursesw.so.6 lib/x86_64-linux-gnu/libncursesw.so.6 \
	kernel/user/libm.so.6 lib/x86_64-linux-gnu/libm.so.6 \
	kernel/user/libnl-3.so.200 lib/x86_64-linux-gnu/libnl-3.so.200 \
	kernel/user/libnl-genl-3.so.200 lib/x86_64-linux-gnu/libnl-genl-3.so.200 \
	kernel/user/terminfo_x/xterm usr/share/terminfo/x/xterm \
	kernel/user/terminfo_l/linux usr/share/terminfo/l/linux \
	/lib64/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 \
	/lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/libc.so.6 \
	kernel/user/libtinfo.so.6 lib/x86_64-linux-gnu/libtinfo.so.6 \
	kernel/user/motd.txt motd.txt

# livemenu links libcrypt for the real /etc/shadow check.
kernel/user/livemenu.elf: kernel/user/livemenu.c kernel/user/mke2.c
	gcc -static-pie -O2 -o $@ $< -lcrypt

LIVE_DEPS := kernel/user/livemenu.elf kernel/user/busybox kernel/user/bash \
	kernel/user/dash \
	$(addprefix kernel/user/etc/,passwd shadow group securetty) \
	kernel/user/htop kernel/user/libncursesw.so.6 kernel/user/libm.so.6 \
	kernel/user/libnl-3.so.200 kernel/user/libnl-genl-3.so.200 \
	kernel/user/terminfo_x/xterm kernel/user/terminfo_l/linux \
	kernel/user/libtinfo.so.6 kernel/user/motd.txt \
	kernel/user/dpkg kernel/user/dpkg-deb kernel/user/dpkg-split kernel/user/dpkg-query \
	kernel/user/update-alternatives \
	kernel/user/tar kernel/user/ldconfig kernel/user/resolv.conf \
	kernel/user/aptetc/sources.list kernel/user/aptetc/99rustux \
	$(APTROOT)/apt-get $(APTROOT)/apt-helper $(APTROOT)/gpgv \
	$(wildcard $(APTROOT)/methods/*) $(wildcard $(APTROOT)/dpkgtables/*) \
	$(wildcard $(APTROOT)/lib*.so*) $(wildcard kernel/user/libdpkg/lib*.so*) \
	tools/mkinitrd.py /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 \
	/lib/x86_64-linux-gnu/libnss_dns.so.2 /lib/x86_64-linux-gnu/libnss_files.so.2 \
	/lib/x86_64-linux-gnu/libresolv.so.2 \
	kernel/user/etc/nsswitch.conf kernel/user/etc/hosts

$(INITRD_LIVE): $(LIVE_DEPS)
	python3 tools/mkinitrd.py $(LIVE_PAIRS) > $@

$(INITRD_ISO): $(LIVE_DEPS) $(HD_IMG)
	python3 tools/mkinitrd.py $(LIVE_PAIRS) $(HD_IMG) hd.img > $@

# The installed image is a PARTITIONED disk: an ESP at LBA 2048
# carrying the kernel + initrd, with room after it for the ext2
# root the installer formats. mkfs.fat --offset places the
# filesystem inside the partition and -h records the hidden
# sectors so the firmware finds /EFI/BOOT/BOOTX64.EFI there.
$(HD_IMG): $(KERNEL) $(INITRD_LIVE)
	dd if=/dev/zero of=$@ bs=1M count=48
	mkfs.fat -F 16 --offset=2048 -h 2048 -n RUSTUX $@
	mmd -i $@@@$$((2048 * 512)) ::/EFI
	mmd -i $@@@$$((2048 * 512)) ::/EFI/BOOT
	mcopy -i $@@@$$((2048 * 512)) $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@@@$$((2048 * 512)) $(INITRD_LIVE) ::/initrd.cpio
	python3 -c 'import zlib; print("%08x" % zlib.crc32(open("$(INITRD_LIVE)","rb").read()))' > hd-initrd.crc
	mcopy -i $@@@$$((2048 * 512)) hd-initrd.crc ::/initrd.crc

$(ESP_ISO): $(KERNEL) $(INITRD_ISO)
	dd if=/dev/zero of=$@ bs=1M count=96
	mformat -F -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(INITRD_ISO) ::/initrd.cpio
	python3 -c 'import zlib; print("%08x" % zlib.crc32(open("$(INITRD_ISO)","rb").read()))' > iso-initrd.crc
	mcopy -i $@ iso-initrd.crc ::/initrd.crc

$(ISO): $(ESP_ISO) $(KERNEL) $(INITRD_ISO)
	rm -rf $(ISOROOT) && mkdir -p $(ISOROOT)/EFI/BOOT
	cp $(ESP_ISO) $(ISOROOT)/esp.img
	cp $(KERNEL) $(ISOROOT)/EFI/BOOT/BOOTX64.EFI
	cp $(INITRD_ISO) $(ISOROOT)/initrd.cpio
	# 512B BIOS stub — makes the El Torito catalog match distro media
	# (BIOS default entry + UEFI alt entry). It only ever runs on legacy
	# BIOS, which we don't support; the signature is all firmware checks.
	printf '\372\374\364%.0s' $$(seq 170) > $(ISOROOT)/biosboot.img
	printf '\125\252' >> $(ISOROOT)/biosboot.img
	xorriso -as mkisofs -o $@ -V RUSTUX_DEMO -J -r \
		-b biosboot.img -no-emul-boot -boot-load-size 4 -boot-info-table \
		-eltorito-alt-boot -e esp.img -no-emul-boot \
		-isohybrid-mbr /usr/lib/syslinux/mbr/gptmbr.bin \
		-isohybrid-gpt-basdat $(ISOROOT)

$(INSTALLDISK):
	# 256 MiB: the root must hold the whole payload (~35 MiB of
	# binaries + libs); the previous 64 left 16 MiB and mke2 ran
	# out of blocks mid-format (install FAILED -21).
	dd if=/dev/zero of=$@ bs=1M count=256

# End-to-end install proof in one guest session: `-boot order=dc`
# prefers the CD while it's inserted and falls back to the disk
# after the monitor eject — the real installer flow (once= proved
# unreliable: OVMF picked a stale boot entry over it). monitor-
# sendkey drives the menu: "1" picks install, Enter takes the
# default root size, "yes" confirms (the PS/2 path — QEMU does not
# deliver piped stdio to the guest UART). The installer streams
# hd.img to /dev/sda, reports status, and waits for ENTER; sendkey
# answers it, the guest resets into the installed system, and "1"
# lands in the shell. The ATA driver binds the i440fx IDE
# controller — hence -machine pc.
run-iso: $(ISO) $(INSTALLDISK) tools/sendkey.py
	rm -f isomon.sock isoph.log
	$(QEMU) \
		-machine pc \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(INSTALLDISK),format=raw,if=none,id=hd0 \
		-device ide-hd,drive=hd0,bus=ide.0,unit=0,bootindex=1 \
		-drive file=$(ISO),format=raw,if=none,id=cd0,media=cdrom \
		-device ide-cd,drive=cd0,bus=ide.1,unit=0,bootindex=0 \
		-netdev user,id=n0 -device e1000e,netdev=n0 \
		-boot order=dc \
		-serial file:isoph.log -display none \
		-monitor unix:isomon.sock,server,nowait \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 & \
	qpid=$$!; \
	ok=0; \
	for i in $$(seq 1 40); do \
		sleep 15; \
		grep -q "ENTER to reboot" isoph.log && { ok=1; break; }; \
		python3 tools/sendkey.py isomon.sock 1 ret str:yes ret; \
	done; \
	[ $$ok -eq 1 ] \
		&& echo "iso install: PASS" \
		|| { echo "iso install: FAIL"; tail -20 isoph.log; kill $$qpid; exit 1; }; \
	echo "eject -f cd0" | socat - UNIX-CONNECT:isomon.sock > /dev/null; \
	python3 tools/sendkey.py isomon.sock ret; \
	ok=0; \
	for i in $$(seq 1 12); do \
		sleep 15; \
		python3 tools/sendkey.py isomon.sock "str:root" ret "str:rustux" ret; \
		sleep 5; \
		python3 tools/sendkey.py isomon.sock "str:echo _RXOK" ret; \
		sleep 3; \
		grep -q "_RXOK" isoph.log && { ok=1; break; }; \
	done; \
	grep -q "_RXOK" isoph.log \
		&& echo "installed boot + live shell: PASS" \
		|| { echo "installed boot: FAIL"; tail -20 isoph.log; kill $$qpid; exit 1; }; \
	python3 tools/sendkey.py isomon.sock "str:sh -c 'dpkg --version | head -1'" ret; \
	sleep 15; \
	grep -q "usr/bin/dpkg exit(0)" isoph.log \
		&& echo "installed sh-dpkg resolution: PASS" \
		|| { echo "installed sh-dpkg resolution: FAIL"; grep -i "dpkg\|busybox\|exit(" isoph.log | tail -15; \
		     echo quit | socat - UNIX-CONNECT:isomon.sock > /dev/null 2>&1 || kill $$qpid; exit 1; }; \
	python3 tools/sendkey.py isomon.sock "str:apt update" ret; \
	ok=0; \
	for i in $$(seq 1 24); do \
		sleep 15; \
		grep -q "apt-get exit(0)" isoph.log && { ok=1; break; }; \
		grep -q "apt-get exit(100)\|apt: not found" isoph.log \
			&& { sleep 5; python3 tools/sendkey.py isomon.sock "str:apt update" ret; }; \
	done; \
	[ $$ok -eq 1 ] \
		&& echo "installed apt update: PASS" \
		|| { echo "installed apt update: FAIL"; grep -i "err:\|ign:\|get:\|exit(" isoph.log | tail -15; \
		     echo quit | socat - UNIX-CONNECT:isomon.sock > /dev/null 2>&1 || kill $$qpid; exit 1; }; \
	python3 tools/sendkey.py isomon.sock "str:apt install -y nano" ret; \
	ok=0; \
	for i in $$(seq 1 24); do \
		sleep 15; \
		grep -q "Setting up nano" isoph.log && { ok=1; break; }; \
		grep -q "apt-get exit(100)\|apt-get exit(127)\|Unable to locate" isoph.log \
			&& { sleep 5; python3 tools/sendkey.py isomon.sock "str:apt install -y nano" ret; }; \
	done; \
	[ $$ok -eq 1 ] \
		&& echo "installed apt install nano: PASS" \
		|| { echo "installed apt install nano: FAIL"; grep -i "err:\|postinst\|exit(" isoph.log | tail -15; \
		     echo quit | socat - UNIX-CONNECT:isomon.sock > /dev/null 2>&1 || kill $$qpid; exit 1; }; \
	echo quit | socat - UNIX-CONNECT:isomon.sock > /dev/null 2>&1 || kill $$qpid

# DOOM proof-of-concept: doomgeneric (the GPL'd original id source)
# built static-pie against the new /dev/fb0 fbdev device, running the
# game data from a user-supplied DOOM.WAD (not committed — drop it at
# kernel/user/doom.wad). Solo-task initrd: doom spawns, the attract
# demo plays on the GOP framebuffer. Input is stubbed — attract mode
# needs none.
DOOM_SRC  := $(wildcard third_party/doomgeneric/*.c)
DOOM_INITRD := initrd-doom.cpio
ESP_DOOM  := esp-doom.img

kernel/user/doom.elf: kernel/user/doom_rustux.c $(DOOM_SRC)
	gcc -static-pie -O2 -DNORMALUNIX -DLINUX \
		-Ithird_party/doomgeneric -o $@ $^ -lm

$(DOOM_INITRD): kernel/user/doom.elf kernel/user/doom.wad tools/mkinitrd.py
	python3 tools/mkinitrd.py kernel/user/doom.elf doom \
		kernel/user/doom.wad doom.wad > $@

$(ESP_DOOM): $(KERNEL) $(DOOM_INITRD)
	dd if=/dev/zero of=$@ bs=1M count=64
	mformat -i $@ ::
	mmd -i $@ ::/EFI
	mmd -i $@ ::/EFI/BOOT
	mcopy -i $@ $(KERNEL) ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $@ $(DOOM_INITRD) ::/initrd.cpio

run-doom: $(ESP_DOOM)
	$(QEMU) \
		-machine q35 \
		-m 1G \
		-cpu qemu64,+rdrand \
		-bios $(OVMF) \
		-drive file=$(ESP_DOOM),format=raw,if=ide \
		-snapshot \
		-serial stdio

# Bootable DOOM ISO — same distro-structure catalog as the demo ISO,
# but the media spawns doom straight into the attract demo.
ISO_DOOM  := rustux-doom.iso
ISOROOT_DOOM := isoroot-doom

$(ISO_DOOM): $(ESP_DOOM) $(KERNEL) $(DOOM_INITRD)
	rm -rf $(ISOROOT_DOOM) && mkdir -p $(ISOROOT_DOOM)/EFI/BOOT
	cp $(ESP_DOOM) $(ISOROOT_DOOM)/esp.img
	cp $(KERNEL) $(ISOROOT_DOOM)/EFI/BOOT/BOOTX64.EFI
	cp $(DOOM_INITRD) $(ISOROOT_DOOM)/initrd.cpio
	printf '\372\374\364%.0s' $$(seq 170) > $(ISOROOT_DOOM)/biosboot.img
	printf '\125\252' >> $(ISOROOT_DOOM)/biosboot.img
	xorriso -as mkisofs -o $@ -V RUSTUX_DOOM -J -r \
		-b biosboot.img -no-emul-boot -boot-load-size 4 -boot-info-table \
		-eltorito-alt-boot -e esp.img -no-emul-boot \
		-isohybrid-mbr /usr/lib/syslinux/mbr/gptmbr.bin \
		-isohybrid-gpt-basdat $(ISOROOT_DOOM)

clean:
	cargo clean
	rm -rf $(ESP) $(ESP_IMG)

# Legacy BIOS boot — the same kernel built for x86_64-unknown-none as a
# static Multiboot2 ELF (kernel/bios.ld, image at 1 MiB). GRUB's
# i386-pc core does the real-mode work we don't want to hand-roll (A20,
# E820, VBE, disk reads); its multiboot2 loader hands bios::entry the
# mmap/framebuffer/RSDP/initrd-module that UEFI used to provide, the
# 32-bit trampoline enters long mode, and rustux_main runs unchanged.
BIOS_TARGET  := x86_64-unknown-none
KERNEL_BIOS  := target/$(BIOS_TARGET)/release/kernel
ISO_BIOS     := rustux-bios.iso
ISOROOT_BIOS := isoroot-bios
BIOS_RUSTFLAGS := --cfg demo_net -C relocation-model=static \
	-C link-args=-no-pie -C link-arg=-T$(CURDIR)/kernel/bios.ld

$(KERNEL_BIOS): kernel/src/*.rs kernel/bios.ld kernel/Cargo.toml klib/src/*.rs FORCE
	cd kernel && RUSTFLAGS="$(BIOS_RUSTFLAGS)" \
		cargo build --release --target $(BIOS_TARGET)

$(ISO_BIOS): $(KERNEL_BIOS) $(INITRD)
	rm -rf $(ISOROOT_BIOS) && mkdir -p $(ISOROOT_BIOS)/boot/grub
	cp $(KERNEL_BIOS) $(ISOROOT_BIOS)/boot/kernel.elf
	cp $(INITRD) $(ISOROOT_BIOS)/boot/initrd.cpio
	printf '%s\n' 'set timeout=0' 'set default=0' 'insmod all_video' \
		'set gfxmode=auto' 'menuentry "Rustux" {' \
		'    multiboot2 /boot/kernel.elf' \
		'    module2 /boot/initrd.cpio' '}' \
		> $(ISOROOT_BIOS)/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(ISOROOT_BIOS) 2>/dev/null

# BIOS boot proof: SeaBIOS (QEMU's default firmware — no -bios flag)
# -> GRUB i386-pc -> multiboot2 -> trampoline -> long mode -> the same
# Windowed BIOS variant: same ISO and suite, visible framebuffer.
run-bios-gui: $(ISO_BIOS)
	$(QEMU) \
		-machine pc \
		-m 1G \
		-cpu qemu64,+rdrand \
		-drive file=$(ISO_BIOS),format=raw,if=none,id=cd0,media=cdrom \
		-device ide-cd,drive=cd0,bus=ide.1,unit=0 \
		-netdev user,id=n0 -device e1000e,netdev=n0 \
		-serial stdio -display $(DISPLAY_MODE) \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "bios boot test: PASS (qemu exit 33)"; \
	else echo "bios boot test: FAIL (qemu exit $$status)"; exit 1; fi

# suite, gated on the same isa-debug-exit 33 contract as `make run`.
run-bios: $(ISO_BIOS)
	$(QEMU) \
		-machine pc \
		-m 1G \
		-cpu qemu64,+rdrand \
		-drive file=$(ISO_BIOS),format=raw,if=none,id=cd0,media=cdrom \
		-device ide-cd,drive=cd0,bus=ide.1,unit=0 \
		-netdev user,id=n0 -device e1000e,netdev=n0 \
		-serial stdio -display none \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-no-reboot; \
	status=$$?; \
	if [ $$status -eq 33 ]; then echo "bios boot test: PASS (qemu exit 33)"; \
	else echo "bios boot test: FAIL (qemu exit $$status)"; exit 1; fi
