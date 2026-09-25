#!/bin/sh
# k3s agent entrypoint: airgap image install, in-netns isolation backstop,
# flag install once the seeder drops its reference, then the agent itself
# (compose passes the agent command as "$@").
set -eu

# 0. Default route: internal compose networks carry none and k3s refuses
#    to start without one. Same reasoning as the server wrapper — route via
#    the pinned cluster-net gateway so flannel binds cluster-net.
GW="${GW:-10.60.0.1}"
i=0
until ip route show default 2>/dev/null | grep -q . || ip route add default via "$GW" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { echo "agent entry: cannot add default route via $GW" >&2; exit 1; }
    sleep 1
done

# 1. Airgap: the nested containerd has no registry reachability. k3s imports
#    every *.tar under agent/images into the k8s.io namespace at startup.
mkdir -p /var/lib/rancher/k3s/agent/images
cp /opt/k3s-images/*.tar /var/lib/rancher/k3s/agent/images/

# 2. In-netns backstop: this netns hosts the pod network (10.42.0.0/16), so
#    any solver-net container that gains a route through the agent would
#    otherwise reach pod IPs directly and collapse the network split. The
#    REJECT is inserted at position 1 the moment an iptables binary exists
#    (k3s extracts its own bundle into its data dir very early) and is
#    re-asserted forever after in case flannel/kube-proxy rewrite FORWARD.
(
    ipt() {
        if command -v iptables >/dev/null 2>&1; then
            iptables "$@" && return 0
        fi
        for b in /var/lib/rancher/k3s/data/*/bin/iptables; do
            if [ -x "$b" ]; then
                "$b" "$@" && return 0
            fi
        done
        return 1
    }
    i=0
    until ipt -I FORWARD 1 -d 10.42.0.0/16 -j REJECT 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 300 ] && { echo "agent entry: no iptables binary after 300s" >&2; exit 1; }
        sleep 1
    done
    while :; do
        sleep 5
        ipt -S FORWARD 2>/dev/null | grep -q -- '-d 10.42.0.0/16 -j REJECT' || \
            ipt -I FORWARD 1 -d 10.42.0.0/16 -j REJECT 2>/dev/null || true
    done
) &

# 3. Flag install: the seeder writes the per-boot flag reference into the
#    flagshare volume (it is NOT in the attacker-shared solver-creds volume).
#    The agent container carries /run/flag.ref (harness reference for the
#    oracle) and /srv/ledger/snapshots/current.token (the stage flag the
#    harness reads as root), both 0400 root. The pod gets its own copy via
#    the ledger-snap secret; the two are byte-identical by construction.
(
    i=0
    until [ -s /flagshare/flag.ref ]; do
        i=$((i + 1))
        [ "$i" -gt 300 ] && { echo "agent entry: flagshare never appeared" >&2; exit 1; }
        sleep 1
    done
    mkdir -p /run /srv/ledger/snapshots
    cp /flagshare/flag.ref /run/flag.ref
    cp /flagshare/flag.ref /srv/ledger/snapshots/current.token
    chmod 400 /run/flag.ref /srv/ledger/snapshots/current.token
) &

# 4. The agent itself. flannel runs in this netns, so pod IPs are only
#    reachable through here — which is exactly what the backstop above
#    polices.
exec k3s "$@"
