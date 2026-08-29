FROM alpine:3.20
RUN apk add --no-cache git bash tar
COPY seed.sh /seed.sh
ENTRYPOINT ["sh", "/seed.sh"]
