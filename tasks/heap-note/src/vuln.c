#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN 16

/* UAF on delete (pointer not cleared, edit/show still reach the chunk).
 * Menu option 5 calls g_box.f. Fresh glibc: tcache fd is mangled
 * (PROTECT_PTR), so the leak from show() gives heap>>12 and the poisoned
 * fd must be re-mangled by hand. */
struct note {
    size_t size;
    char *data;
};

static struct note notes[MAXN];

/* dedicated dispatch box: poisoning lands the whole 56-byte note write
 * inside this struct, nothing else gets clobbered */
struct {
    void (*f)(void);
    char pad[56];
} g_box __attribute__((aligned(16)));

static void dispatch_ok(void) { puts("dispatch: no handler installed"); }
static void dispatch_win(void) {
    char buf[256];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("no flag"); exit(1); }
    fgets(buf, sizeof buf, f);
    printf("flag: %s", buf);
    exit(0);
}

int main(void) {
    char line[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    g_box.f = dispatch_ok;
    puts("notes 3.0 (glibc malloc). 1)add 2)del 3)edit 4)show 5)dispatch 6)quit");
    for (;;) {
        int idx, n;
        printf("> ");
        if (!fgets(line, sizeof line, stdin)) break;
        switch (line[0]) {
        case '1':
            printf("idx size data> ");
            if (scanf("%d %zu", &idx, &n) != 2) return 1;
            fgets(line, sizeof line, stdin);
            if (idx < 0 || idx >= MAXN || n < 8 || n > 0x100) { puts("range"); break; }
            notes[idx].size = n;
            notes[idx].data = malloc(n);
            if (fread(notes[idx].data, 1, n, stdin) != (size_t)n) { }
            puts("added");
            break;
        case '2':
            printf("idx> ");
            if (scanf("%d", &idx) != 1) return 1;
            fgets(line, sizeof line, stdin);
            if (idx < 0 || idx >= MAXN || !notes[idx].data) { puts("range"); break; }
            free(notes[idx].data);   /* BUG: pointer not cleared */
            puts("freed");
            break;
        case '3':
            printf("idx data> ");
            if (scanf("%d", &idx) != 1) return 1;
            fgets(line, sizeof line, stdin);
            if (idx < 0 || idx >= MAXN || !notes[idx].data) { puts("range"); break; }
            if (fread(notes[idx].data, 1, notes[idx].size, stdin) != notes[idx].size) {}
            puts("edited");
            break;
        case '4':
            printf("idx> ");
            if (scanf("%d", &idx) != 1) return 1;
            fgets(line, sizeof line, stdin);
            if (idx < 0 || idx >= MAXN || !notes[idx].data) { puts("range"); break; }
            fwrite(notes[idx].data, 1, notes[idx].size, stdout);  /* raw dump, no NUL stop */
            puts("\nshown");
            break;
        case '5':
            g_box.f();
            break;
        case '6':
            puts("bye");
            return 0;
        }
    }
    return 0;
}
