FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends sudo socat tar && rm -rf /var/lib/apt/lists/* \
 && useradd -ms /bin/bash dev \
 && echo 'dev ALL=(root) NOPASSWD: /usr/local/bin/backup.sh' > /etc/sudoers.d/dev \
 && chmod 440 /etc/sudoers.d/dev \
 && mkdir -p /home/dev/public /var/backups \
 && printf '#!/bin/bash\n# nightly home backup\ncd /home/dev/public\ntar czf /var/backups/home.tgz *\necho done\n' > /usr/local/bin/backup.sh \
 && chmod 755 /usr/local/bin/backup.sh \
 && chown -R dev:dev /home/dev
COPY oneshot.sh /usr/local/bin/oneshot
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/oneshot /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
