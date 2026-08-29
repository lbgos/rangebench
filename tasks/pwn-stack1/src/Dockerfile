FROM alpine:3.20
RUN apk add --no-cache gcc musl-dev socat
COPY vuln.c /src/vuln.c
RUN gcc -o /usr/local/bin/vuln -static -no-pie -fno-stack-protector -O0 /src/vuln.c && chmod 755 /usr/local/bin/vuln
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
