#!/usr/bin/env bash
# Boot rustux-demo.iso in QEMU (UEFI/OVMF).
#   ./boot-iso.sh           — live CD boot (menu), no install target
#   ./boot-iso.sh install   — CD boot with a scratch disk attached so
#                             the menu's "install Rustux to disk" works
# Display: GTK window when $DISPLAY is set, otherwise serial-only.
set -euo pipefail
cd "$(dirname "$0")"

ISO=rustux-doom.iso
OVMF=/usr/share/ovmf/OVMF.fd
DISK=install-tgt.img

[ -f "$ISO" ] || { echo "missing $ISO — run: make iso"; exit 1; }
[ -f "$OVMF" ] || { echo "missing $OVMF — install ovmf"; exit 1; }

ARGS=(
  -machine pc -m 1G -cpu qemu64,+rdrand -bios "$OVMF"
  -drive file="$ISO",format=raw,if=none,id=cd0,media=cdrom
  -device ide-cd,drive=cd0,bus=ide.1,unit=0,bootindex=0
  -netdev user,id=n0 -device e1000e,netdev=n0
  -boot order=dc
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
)

if [ "${1:-}" = "install" ]; then
  [ -f "$DISK" ] || dd if=/dev/zero of="$DISK" bs=1M count=64
  ARGS+=(
    -drive file="$DISK",format=raw,if=none,id=hd0
    -device ide-hd,drive=hd0,bus=ide.0,unit=0,bootindex=1
  )
  echo "install target: $DISK (wiped by the installer)"
fi

if [ -n "${DISPLAY:-}" ]; then
  exec qemu-system-x86_64 "${ARGS[@]}" -serial stdio
else
  exec qemu-system-x86_64 "${ARGS[@]}" -serial stdio -display none
fi
