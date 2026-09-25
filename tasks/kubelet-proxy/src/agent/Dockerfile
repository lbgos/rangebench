# k3s agent target. rancher/k3s pinned to the manifest-list digest of
# v1.31.14+k3s1 (k8s 1.31.14, released 2025-11-20). Do not bump minors
# silently: KubeletFineGrainedAuthz exists as a gate from k8s 1.32 (alpha)
# onward and is default-on from 1.33 — the 1.31 pin predates the gate
# entirely, so the coarse get nodes/proxy exec mapping is the only behavior
# the kubelet can have.
FROM rancher/k3s:v1.31.14-k3s1@sha256:6c33f6a8ff6dd6ae63428d5c8e331e059a4111d5ec3f5beaa9df6c50ba6b7ce8

# The nested containerd has no registry reachability, so every image the
# agent node needs is vendored as a docker-save archive and imported from
# the k3s airgap dir at startup:
# - the flag pod's alpine:3.20.6 (manifest-list digest
#   sha256:de4fe7064d8f98419ea6b49190df1abbf43450c1702eeb864fe9ced453c1cc5f,
#   amd64 manifest sha256:43180c492a5e6cedd8232e8f77a454f666f247586853eecb90258b26688ad1d3);
# - the pod-sandbox (pause) image rancher/mirrored-pause:3.6, digest
#   sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893
#   (without it every pod sticks in ContainerCreating behind a registry
#   lookup that can never succeed on the internal network).
COPY alpine-3.20.6-docker.tar pause-3.6-docker.tar /opt/k3s-images/
# No RUN: the base image already bundles busybox/coreutils (/bin/sh, ip, cp,
# grep all work), and COPY preserves the 755 bit entrypoint.sh carries.
COPY entrypoint.sh /entry.sh
ENTRYPOINT ["/entry.sh"]
