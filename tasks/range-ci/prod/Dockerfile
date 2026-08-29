FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh
COPY entry.sh /entry.sh
RUN chmod 755 /entry.sh
EXPOSE 22
ENTRYPOINT ["/entry.sh"]
