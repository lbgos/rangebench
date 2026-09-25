# house-tangerine target: fresh 32-slot vault service, exploit offsets assume
# the base image's glibc 2.39. ubuntu:24.04 pinned by manifest digest — never
# bump the base silently (the shipped libc/ld pair and every stage offset
# are frozen to 2.39).
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc libc6-dev socat netcat-openbsd patchelf \
    && rm -rf /var/lib/apt/lists/*

COPY vuln.c build.sh /src/
RUN chmod 755 /src/build.sh

# Ship the exact 2.39 loader and libc next to the binary and pin the binary
# to them via $ORIGIN, so the attacker-side copy runs standalone with the
# same offsets the target process runs with. No dist-upgrade anywhere.
RUN /src/build.sh /usr/local/bin/distinct \
    && cp /lib64/ld-linux-x86-64.so.2 /usr/local/bin/ld-linux-x86-64.so.2 \
    && cp /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/local/bin/libc.so.6 \
    && patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
                --set-rpath '$ORIGIN' /usr/local/bin/distinct \
    && chmod 755 /usr/local/bin/distinct /usr/local/bin/ld-linux-x86-64.so.2 \
    && chmod 644 /usr/local/bin/libc.so.6

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh \
    && useradd --system --user-group --shell /usr/sbin/nologin vaultsvc

ENTRYPOINT ["/entrypoint.sh"]
