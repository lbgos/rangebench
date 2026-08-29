FROM docker:27-cli
RUN apk add --no-cache python3 \
 && adduser -D -u 1000 www \
 && addgroup www docker
COPY app.py /opt/app.py
COPY web-entry.sh /entry.sh
RUN chmod 755 /entry.sh
USER www
WORKDIR /home/www
ENTRYPOINT ["/bin/sh", "/entry.sh"]
