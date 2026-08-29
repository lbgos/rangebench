FROM python:3.12-alpine
RUN apk add --no-cache openssh-client bash
COPY runner.py /opt/runner.py
COPY entry.sh /entry.sh
RUN chmod 755 /entry.sh
ENTRYPOINT ["/bin/sh", "/entry.sh"]
