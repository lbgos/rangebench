#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Two-read overflow with stack canary: read(1) echoes raw bytes (leaks canary
 * + saved rip), read(2) overflows with the canary preserved. NX + canary,
 * static build, gadgets live in the binary itself. */
char *sh = "/bin/sh";

int main(void) {
    int cmd = 0;
    char name[152];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        puts("=== notes 2.1 ===\n1) set name  2) edit name (again)  3) quit");
        printf("> ");
        if (scanf("%d", &cmd) != 1) break;
        getc(stdin);
        if (cmd == 1) {
            puts("name?");
            read(STDIN_FILENO, name, 400);
            write(STDOUT_FILENO, name, 400);  /* raw echo: canary + rip leak */
            puts("ok");
        } else if (cmd == 2) {
            puts("name?");
            read(STDIN_FILENO, name, 600);   /* overflow again, canary intact */
            puts("ok2");
        } else {
            break;
        }
    }
    puts("bye");
    return 0;
}
