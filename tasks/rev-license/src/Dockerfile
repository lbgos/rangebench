FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev socat netcat-openbsd upx-ucl && rm -rf /var/lib/apt/lists/*
COPY lic.c /src/lic.c
RUN gcc -o /usr/local/bin/lic.bin -no-pie -O2 -s /src/lic.c \
 && upx -q -o /usr/local/bin/lic /usr/local/bin/lic.bin \
 && chmod 755 /usr/local/bin/lic
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
