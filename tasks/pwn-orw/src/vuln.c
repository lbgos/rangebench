#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>

/* Plain stack overflow, static build, but seccomp kills execve.
 * The only way out is an open/read/write ROP chain. */

static void install_seccomp(void) {
    /* allow: read(0) write(1) open(2) close(3) exit(60) exit_group(231) mmap(9)
       openat(257) rt_sigreturn(15); kill everything else.
       Layout: [0] arch load, [1] arch check (bad -> kill [13]), [2] nr load,
       [3..11] syscall checks (hit -> allow [12]), [12] allow, [13] kill */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),                        /* [0]  */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 11), /* [1]  */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                        /* [2]  */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 8, 0),                 /* [3]  read */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 7, 0),                 /* [4]  write */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 6, 0),                 /* [5]  open */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 3, 5, 0),                 /* [6]  close */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 60, 4, 0),                /* [7]  exit */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 231, 3, 0),               /* [8]  exit_group */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 2, 0),                 /* [9]  mmap */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 257, 1, 0),               /* [10] openat */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 15, 0, 1),                /* [11] rt_sigreturn */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),                 /* [12] */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),          /* [13] */
    };
    struct sock_fprog prog = { .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) exit(2);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) exit(3);
}

int main(void) {
    char fav[72];
    setvbuf(stdout, NULL, _IONBF, 0);
    install_seccomp();
    puts("QUOTE v2: enter your favorite quote (max 400 chars):");
    printf("debug: input buffer at %p\n", (void *) fav);  /* debug line left in: stack leak */
    read(STDIN_FILENO, fav, 400);
    printf("Stored: %.60s\n", fav);
    puts("Bye.");
    return 0;
}
