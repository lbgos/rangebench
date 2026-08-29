#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* win() is never called on the happy path; it prints /flag */
void win(void) {
    char buf[256];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("no flag"); exit(1); }
    fgets(buf, sizeof buf, f);
    printf("flag: %s", buf);
    exit(0);
}

int main(void) {
    char name[72];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Welcome to GREETD v1.0. Enter your name:");
    read(STDIN_FILENO, name, 400);
    printf("Hello, %.60s\n", name);
    puts("Bye.");
    return 0;
}
