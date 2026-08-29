#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* license = 8 bytes -> two u32 words (little endian), entered as 16 hex chars
 * per word line... simpler: one 32-hex-char line = 4 words d0..d3.
 * valid iff for each word: d * A + C == T[i] (mod 2^32) */
#define A 0x5bd1e995u
#define C 0x9e3779b9u
static const uint32_t T[4] = {0x7c3f1a42u, 0x1d0be777u, 0x4a2f9c11u, 0x65e8b3cdu};

static void win(void) {
    char buf[256];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("err"); return; }
    fgets(buf, sizeof buf, f);
    printf("license ok. flag: %s", buf);
    exit(0);
}

int main(void) {
    char line[128];
    uint32_t d[4];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("LICENSED v4.2. enter license (32 hex):");
    for (;;) {
        printf("lic> ");
        if (!fgets(line, sizeof line, stdin)) return 1;
        if (strlen(line) < 32) { puts("too short"); continue; }
        memset(d, 0, sizeof d);
        for (int w = 0; w < 4; w++) {
            char hex[9];
            memcpy(hex, line + w * 8, 8);
            hex[8] = 0;
            d[w] = (uint32_t)strtoul(hex, NULL, 16);
        }
        int ok = 1;
        for (int w = 0; w < 4; w++) {
            if (d[w] * A + C != T[w]) { ok = 0; break; }
        }
        if (ok) win();
        puts("invalid license");
    }
}
