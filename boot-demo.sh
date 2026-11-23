#!/bin/bash
cd /home/zorin/linux-rust || exit 1

# Demo modes:
#   ./boot-demo.sh        selftest suite (72 tasks incl. ptytest, ~25s)
#   ./boot-demo.sh apt    real Debian apt-get update + install over slirp
#                         (aptprobe solo image, ~3min)
#   ./boot-demo.sh iso    live/install CD: boot rustux-demo.iso, pick
#                         [2] at the menu to write the system to
#                         target.img, then the script boots the
#                         installed disk automatically
MODE="${1:-suite}"

QEMU_FLAGS=(
  -machine q35
  -m 1G
  -cpu qemu64,+rdrand
  -bios /usr/share/ovmf/OVMF.fd
  -snapshot
  -serial stdio -display gtk
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
  -no-reboot
)

case "$MODE" in
  apt)
    IMG=esp-apt.img
    TIMEOUT=360
    echo '=== rustux: real Debian apt demo ==='
    echo 'apt-get update + install hello-traditional over slirp,'
    echo 'dpkg unpack/configure under a real kernel pty, then /usr/bin/hello'
    echo 'serial output below; QEMU window shows firmware/kernel display'
    echo
    make "$IMG" || exit 1
    QEMU_FLAGS+=(-drive file=$IMG,format=raw,if=ide
                 -netdev user,id=n0 -device e1000e,netdev=n0)
    ;;
  iso)
    echo '=== rustux: live/install ISO demo ==='
    echo 'boots rustux-demo.iso on i440fx (the ATA disk driver needs'
    echo 'the PIIX3 IDE channel). At the menu:'
    echo '  [1] live session  - busybox ash on the demo rootfs'
    echo '  [2] install       - raw-writes hd.img to /dev/sda'
    echo 'when the installer prompts, remove the medium — either let'
    echo 'the ATAPI eject stand, or from another terminal run:'
    echo "  echo 'eject -f cd0' | socat - UNIX-CONNECT:/tmp/rustux-mon.sock"
    echo 'then press ENTER — the reboot lands on installed target.img.'
    echo
    make rustux-demo.iso target.img || exit 1
    rm -f /tmp/rustux-mon.sock
    setsid timeout 600 qemu-system-x86_64 \
      -machine pc -m 1G -cpu qemu64,+rdrand \
      -bios /usr/share/ovmf/OVMF.fd \
      -drive file=target.img,format=raw,if=none,id=hd0 \
      -device ide-hd,drive=hd0,bus=ide.0,unit=0,bootindex=1 \
      -drive file=rustux-demo.iso,format=raw,if=none,id=cd0,media=cdrom \
      -device ide-cd,drive=cd0,bus=ide.1,unit=0,bootindex=0 \
      -netdev user,id=n0 -device e1000e,netdev=n0 \
      -boot order=dc \
      -serial stdio -display gtk \
      -monitor unix:/tmp/rustux-mon.sock,server,nowait \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04
    echo
    echo '=== QEMU closed (mode: iso) ==='
    exec bash
    ;;
  *)
    IMG=esp.img
    TIMEOUT=60
    echo '=== rustux kernel booting in QEMU ==='
    echo 'serial output below; QEMU window shows firmware/kernel display'
    echo
    make "$IMG" || exit 1
    QEMU_FLAGS+=(-drive file=$IMG,format=raw,if=ide)
    ;;
esac

setsid timeout "$TIMEOUT" qemu-system-x86_64 "${QEMU_FLAGS[@]}"
echo
echo "=== QEMU closed (mode: $MODE) ==="
exec bash
