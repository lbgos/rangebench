#!/usr/bin/env bash
# Oracle: discover the local subnet, full port scan, banner-grab the odd port.
set -uo pipefail
SUBNET=$(ip -4 addr show eth0 | awk '/inet /{print $2}' | cut -d/ -f1 | cut -d. -f1-3).0/24
echo "subnet: $SUBNET"
nmap -p- -T4 --min-rate=10000 -n "$SUBNET" -oG - | grep '/open/'
IP=$(nmap -p- -T4 --min-rate=10000 -n "$SUBNET" -oG - | grep '31337/open' | awk '{print $2}' | head -1)
echo "banner host: $IP"
timeout 6 nc -w 3 "$IP" 31337 < /dev/null | tee /tmp/banner.txt
grep -o 'flag{[^}]*}' /tmp/banner.txt || true
