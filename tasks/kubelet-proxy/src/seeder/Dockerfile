# One-shot seeder. The bare kubectl image ships no /bin/sh, but the seed
# script needs one (heredocs, redirects, od/tr flag generation), so the
# shell plus the handful of applets seed.sh uses come from pinned alpine.
# Symlinks copy as symlinks and resolve to the vendored busybox; no RUN is
# used (nothing to run it with on this base). `[`/`test` are busybox-ash
# builtins, so no binaries are needed for those.
FROM alpine:3.20.6@sha256:de4fe7064d8f98419ea6b49190df1abbf43450c1702eeb864fe9ced453c1cc5f AS bb
FROM rancher/kubectl:v1.31.14@sha256:c01afebbff02d9e67108604f48a8cc780ff7dd1af0ea12d108f0fc019e532301
COPY --from=bb /bin/busybox /bin/busybox
COPY --from=bb /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=bb /bin/sh /bin/sed /bin/cp /bin/chmod /bin/cat /bin/grep /bin/sleep /bin/mkdir /bin/
COPY --from=bb /usr/bin/head /usr/bin/od /usr/bin/tr /usr/bin/
COPY seed.sh /seed.sh
ENTRYPOINT ["/seed.sh"]
