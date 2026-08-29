FROM python:3.12-alpine
RUN mkdir -p /srv/www
COPY entry.sh /entry.sh
RUN chmod 755 /entry.sh
ENTRYPOINT ["/bin/sh", "/entry.sh"]
