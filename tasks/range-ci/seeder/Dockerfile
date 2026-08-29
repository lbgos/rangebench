FROM alpine:3.20
RUN apk add --no-cache git bash
COPY seed.sh /seed.sh
RUN chmod 755 /seed.sh
ENTRYPOINT ["/bin/sh", "/seed.sh"]
