#!/bin/bash
# Builds Scenario C and D images (run from data/). Scenarios A and B are NOT touched
# (use make_scenarios.sh for those). Same method: fixed volume IDs + story
# timestamps from times_*.json, so the images are identical on every rebuild.
set -e
export TZ=UTC
for s in c d; do
  dir=planted_$s
  vol=4C53C0C0; [ $s = d ] && vol=4C53D0D0
  rm -f scenario_$s.img
  dd if=/dev/zero of=scenario_$s.img bs=1M count=64 status=none
  mkfs.vfat -F 32 --invariant -i $vol -n "USB_$(echo $s | tr a-z A-Z)" scenario_$s.img > /dev/null
  for f in $(ls $dir | sort); do mcopy -m -i scenario_$s.img "$dir/$f" ::; done
done
mattrib -i scenario_c.img +h ::vpn_config.txt
mdel -i scenario_c.img ::passwords_backup.txt ::client_database.csv
python3 set_fat_times.py scenario_c.img times_c.json
python3 set_fat_times.py scenario_d.img times_d.json
echo "Scenario C and D images rebuilt."
