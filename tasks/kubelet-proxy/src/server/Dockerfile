# k3s server target. Same pin as the agent (k8s 1.31.14, predates the
# fine-grained kubelet-authz gate entirely).
#
# The base image already bundles busybox/coreutils, so /bin/sh, ip, grep and
# friends work with no extra layers. Deliberately no RUN here: the image has
# no separate shell for builders that wrap RUN in /bin/sh, and COPY
# preserves the 755 bit entry.sh already carries.
FROM rancher/k3s:v1.31.14-k3s1@sha256:6c33f6a8ff6dd6ae63428d5c8e331e059a4111d5ec3f5beaa9df6c50ba6b7ce8
COPY entry.sh /entry.sh
ENTRYPOINT ["/entry.sh"]
