#!/bin/sh
# k3s-server wrapper: internal compose networks carry no default route and
# k3s refuses to start without one ("no default routes found"). The bridge
# gateway (.1, pinned in the compose ipam) is unreachable externally — the
# network stays internal:true — but a route via it satisfies k3s's check and
# gives flannel a deterministic parent interface on cluster-net.
set -eu

GW="${GW:-10.60.0.1}"
i=0
until ip route show default 2>/dev/null | grep -q . || ip route add default via "$GW" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { echo "server entry: cannot add default route via $GW" >&2; exit 1; }
    sleep 1
done

exec k3s "$@"
