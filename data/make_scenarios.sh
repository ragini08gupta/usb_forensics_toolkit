#!/bin/bash
# Rebuilds Scenario A and B images from data/planted*/ (run from data/)
set -e
for s in b a; do
  dir=planted; [ $s = a ] && dir=planted_a
  dd if=/dev/zero of=scenario_$s.img bs=1M count=64 status=none
  mkfs.vfat -F 32 scenario_$s.img > /dev/null
  mcopy -i scenario_$s.img $dir/* ::
done
mattrib -i scenario_b.img +h ::secret.txt
mdel -i scenario_b.img ::salary.xlsx ::passwords.txt
echo "Scenario images rebuilt."
