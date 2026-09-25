# zkvm-fs verifier service.
#
# Stage 1 compiles the pinned (pre-fix) zkVM stack plus the harness binary from
# the vendored workspace; stage 2 ships only the binary, guest ELF, baked
# statement, and socat. No toolchain, no git history, no vendored sources in
# the runtime image.
FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential clang pkg-config git ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly-2025-04-06 \
      --profile minimal --component rust-src \
      --target riscv32im-unknown-none-elf \
    && rustup default nightly-2025-04-06

WORKDIR /src
COPY nexus/ /src/
COPY vendor.tar.gz /src/vendor.tar.gz
RUN tar -xzf /src/vendor.tar.gz -C /src/

ENV CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2
# Harness (verifier + forge tool), x86_64 release.
RUN cargo build --offline --release -p nexus-harness --target-dir /src/target
# Guest program (RISC-V ELF), cross target.
RUN cargo build --offline --release --target riscv32im-unknown-none-elf \
      -p fltea-guest --target-dir /src/target-guest

# Bake the statement with the guest ELF hash pinned at build time. The guest
# path is relative to the statement file so the same statement works in the
# verifier image (/etc/zkvm/) and in the attacker bundle (/work/harness/).
RUN sha256sum /src/target-guest/riscv32im-unknown-none-elf/release/fltea-guest > /tmp/elf.sha \
    && printf 'guest = guest.elf\nguest_sha256 = %s\npublic_input = 23,34,61\nexit_code = 0\nexpected_output = true\nflag_file = /flag\n' \
       "$(cut -c1-64 /tmp/elf.sha)" > /tmp/statement

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/nexus-harness /usr/local/bin/nexus-harness
COPY --from=builder /src/target-guest/riscv32im-unknown-none-elf/release/fltea-guest /etc/zkvm/guest.elf
COPY --from=builder /tmp/statement /etc/zkvm/statement
COPY harness-README.md /opt/task/harness-README.md
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /usr/local/bin/nexus-harness && chmod 644 /etc/zkvm/statement /etc/zkvm/guest.elf

ENTRYPOINT ["/entrypoint.sh"]
