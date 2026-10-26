#!/bin/sh
# Extract the root filesystem of a UniFi MIPS/QCA956x AP firmware (.bin).
# Layout: UBNTBZ header -> uImage (lzma kernel) -> inner lzma stream -> cpio initramfs.
# Usage: tools/fw-extract.sh <firmware.bin> <outdir>   (needs xz, cpio, binwalk)
set -e
fw=$1; out=$2
[ -f "$fw" ] && [ -n "$out" ] || { echo "usage: $0 firmware.bin outdir" >&2; exit 2; }
mkdir -p "$out/root"
work=$out/work; mkdir -p "$work"

# uImage offset: binwalk's "uImage firmware image" line, payload starts 64 bytes later.
binwalk "$fw" > "$work/bw1.txt" 2>/dev/null || true
off=$(awk '/uImage firmware image/ {print $1}' "$work/bw1.txt" | head -n 1)
[ -n "$off" ] || { echo "no uImage found (ARM64 U6/U7 images are not supported)" >&2; exit 1; }
dd if="$fw" of="$work/k.lzma" bs=1 skip=$((off + 64)) 2>/dev/null
xz -dc --format=lzma "$work/k.lzma" > "$work/kernel.bin" 2>/dev/null || true

# The initramfs is the largest lzma stream embedded in the decompressed kernel.
binwalk "$work/kernel.bin" > "$work/bw2.txt" 2>/dev/null || true
inner=$(awk '/LZMA compressed data/ {print $1}' "$work/bw2.txt" | tail -n 1)
[ -n "$inner" ] || { echo "no inner lzma stream in kernel" >&2; exit 1; }
dd if="$work/kernel.bin" of="$work/inner.lzma" bs=1 skip="$inner" 2>/dev/null
xz -dc --format=lzma "$work/inner.lzma" > "$work/initramfs.cpio" 2>/dev/null || true
head -c 6 "$work/initramfs.cpio" | grep -q 070701 || { echo "inner stream is not a cpio archive" >&2; exit 1; }

# /dev nodes cannot be created unprivileged; the errors are harmless.
(cd "$out/root" && cpio -idm --quiet < "$work/initramfs.cpio" 2>/dev/null) || true
[ -x "$out/root/usr/bin/mcad" ] || { echo "extracted tree has no usr/bin/mcad" >&2; exit 1; }
echo "ok: $out/root ($(cat "$out/root/usr/lib/version" 2>/dev/null))"
