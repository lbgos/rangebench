FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* \
 && useradd -ms /bin/bash ops && mkdir -p /run/sshd
COPY vault-entry.sh /vault-entry.sh
RUN chmod 755 /vault-entry.sh
EXPOSE 22
ENTRYPOINT ["/vault-entry.sh"]
