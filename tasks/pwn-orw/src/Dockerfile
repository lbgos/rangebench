FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev socat netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY vuln.c /src/vuln.c
RUN gcc -o /usr/local/bin/quote -static -no-pie -fno-stack-protector -O0 /src/vuln.c && chmod 755 /usr/local/bin/quote
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
