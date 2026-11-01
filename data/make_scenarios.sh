#!/bin/bash
# Rebuilds Scenario A and B images from data/planted*/ (run from data/).
# Volume IDs are fixed and story timestamps are stamped by set_fat_times.py,
# so the images (and their SHA-256/MD5) are identical on every rebuild.
set -e
export TZ=UTC
for s in b a; do
  dir=planted; [ $s = a ] && dir=planted_a
  vol=4C53B0B0; [ $s = a ] && vol=0A0A2026
  rm -f scenario_$s.img
  dd if=/dev/zero of=scenario_$s.img bs=1M count=64 status=none
  mkfs.vfat -F 32 --invariant -i $vol -n "USB_$(echo $s | tr a-z A-Z)" scenario_$s.img > /dev/null
  for f in $(ls $dir | sort); do mcopy -m -i scenario_$s.img "$dir/$f" ::; done
done
mattrib -i scenario_b.img +h ::secret.txt
mdel -i scenario_b.img ::salary.xlsx ::passwords.txt
python3 set_fat_times.py scenario_b.img times_b.json
python3 set_fat_times.py scenario_a.img times_a.json
echo "Scenario images rebuilt."
