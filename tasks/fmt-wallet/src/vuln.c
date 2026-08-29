#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int authorized = 0;

void show_vault(void) {
    char buf[256];
    FILE *f;
    if (!authorized) {
        puts("vault locked: authorization flag not set");
        return;
    }
    f = fopen("/flag", "r");
    if (!f) { puts("no flag"); return; }
    fgets(buf, sizeof buf, f);
    printf("vault: %s", buf);
}

int main(void) {
    char in[128];
    double balance = 100.0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("WALLET v3 // balance %.2f\n", balance);
    for (;;) {
        printf("op> ");
        if (!fgets(in, sizeof in, stdin)) break;
        if (strncmp(in, "quit", 4) == 0) {
            show_vault();
            break;
        }
        if (strncmp(in, "bal", 3) == 0) {
            printf("balance %.2f\n", balance);
            continue;
        }
        /* echo the operation description back */
        printf(in);   /* format string bug */
        putchar('\n');
    }
    return 0;
}
