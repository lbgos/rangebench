#!/bin/sh
# One-shot seeder (admin-only, cluster-net only — never attached to
# solver-net). Generates the per-boot flag, applies the minimal vulnerable
# RBAC and the flag pod, provisions the monitor credential into the
# attacker-shared volume, and drops the flag reference into flagshare for the
# agent to install. Everything is idempotent so a rerun converges.
set -eu

# The kubectl base is a minimal image with no /tmp; the admin kubeconfig
# rewrite below needs a scratch file.
mkdir -p /tmp

K3S_YAML=/k3scfg/k3s.yaml
SERVER=https://10.60.0.10:6443

# The admin kubeconfig points at 127.0.0.1:6443 inside the server container;
# rewrite the copy to the server's cluster-net address.
i=0
until [ -s "$K3S_YAML" ]; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && { echo "seeder: $K3S_YAML never appeared" >&2; exit 1; }
    sleep 1
done
cp "$K3S_YAML" /tmp/k3s.yaml
sed -i "s#server: https://127.0.0.1:6443#server: $SERVER#" /tmp/k3s.yaml
K="kubectl --kubeconfig /tmp/k3s.yaml"

i=0
until $K get --raw=/readyz >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 240 ] && { echo "seeder: API never became ready" >&2; exit 1; }
    sleep 1
done

# Namespace + the monitor service account the solver gets a token for.
$K create namespace billing --dry-run=client -o yaml | $K apply -f - >/dev/null
$K create serviceaccount ledger-monitor -n billing --dry-run=client -o yaml | $K apply -f - >/dev/null

# Minimal vulnerable RBAC: read-only over nodes and the node proxy surface.
# No create anywhere (the API-server proxy POST must stay 403), no pods/exec,
# no secrets.
$K apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ledger-metrics-reader
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ledger-monitor-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ledger-metrics-reader
subjects:
  - kind: ServiceAccount
    name: ledger-monitor
    namespace: billing
EOF

# Per-boot flag from urandom; the literal only ever
# exists inside this container's memory, the pod's secret mount, the
# flagshare volume (agent-side installs), and the stage path the harness
# reads as root. Never baked into an image layer.
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
printf '%s\n' "$FLAG" > /flagshare/flag.ref
chmod 444 /flagshare/flag.ref

# The flag reaches the pod as a secret mounted read-only at
# /srv/ledger/snapshots (mode 0440, root:65532 via fsGroup): the pod runs as
# non-root 65532, so the snapshot is readable only by exec'ing into the
# container — no env leak, no writable path, no API shortcut.
$K create secret generic ledger-snap -n billing --from-file=current.token=/flagshare/flag.ref \
    --dry-run=client -o yaml | $K apply -f - >/dev/null

$K apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: ledger-sync-01
  namespace: billing
  labels:
    app: ledger-sync
spec:
  nodeName: k3s-agt-01
  containers:
    - name: sync
      image: alpine:3.20.6
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "sleep infinity"]
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        allowPrivilegeEscalation: false
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
      volumeMounts:
        - name: ledger-snap
          mountPath: /srv/ledger/snapshots
          readOnly: true
  volumes:
    - name: ledger-snap
      secret:
        secretName: ledger-snap
        defaultMode: 0440
  securityContext:
    fsGroup: 65532
EOF

# Scheduling is pinned by nodeName, so Ready only after the agent joined and
# the airgap image imported. This is the real infra gate for the boot.
$K wait --for=condition=Ready pod/ledger-sync-01 -n billing --timeout=180s

# Attacker-facing credential: monitor SA token + cluster CA + API URL, and
# nothing else in the volume (the harness reference never lives here).
$K create token ledger-monitor -n billing --duration=24h > /out/monitor-token
cp /serverdata/server/tls/server-ca.crt /out/ca.crt
printf 'https://k3s-server:6443\n' > /out/api-url
chmod 444 /out/monitor-token /out/ca.crt /out/api-url

# Attacker-facing toolchain: static websocat plus a stdlib-Python websocket
# exec fallback, shipped through the solver-tools volume.
cp /tools/websocat /tools/wsfallback.py /tools-out/
chmod 755 /tools-out/websocat /tools-out/wsfallback.py

echo "seeder: done"
