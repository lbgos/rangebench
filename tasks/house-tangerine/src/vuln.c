/* distinct — a 32-slot, reserve-only vault service.
 *
 * Fresh menu-driven target for a heap-grooming exercise. Every payload
 * write into a slot asks for 16 bytes more than the slot's size, so each
 * store/edit overruns linearly into the next chunk header. Nothing is
 * ever freed anywhere in the process: bin state is only ever synthesized
 * by glibc itself. One forked process per connection (socat), unbuffered
 * stdio for byte-stable sessions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NSLOTS   32
#define SIZE_MIN 0x18
#define SIZE_MAX 0xf00
#define OVERREAD 0x10 /* every payload read asks for size + OVERREAD */

struct slot {
    char *chunk;
    size_t size;
};

static struct slot g_slots[NSLOTS];

/* Byte-exact receive: blocks until `want` bytes arrive or the peer goes
 * away. Callers always send the full count, so remote runs stay
 * deterministic (no short-read ambiguity in the overflow window). */
static long read_exact(char *dst, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(0, dst + got, want - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    return (long)got;
}

/* Byte-at-a-time line read through '\n' inclusive; NUL-terminates. */
static size_t read_line(char *dst, size_t cap) {
    size_t got = 0;
    while (got + 1 < cap) {
        char c;
        if (read(0, &c, 1) <= 0)
            break;
        dst[got++] = c;
        if (c == '\n')
            break;
    }
    dst[got] = '\0';
    return got;
}

static int parse_one(char *line, long *out) {
    char *end;
    while (*line == ' ' || *line == '\t')
        line++;
    *out = strtol(line, &end, 0);
    return end != line;
}

static int parse_two(char *line, long *a, long *b) {
    char *p, *end;
    while (*line == ' ' || *line == '\t')
        line++;
    *a = strtol(line, &p, 0);
    if (p == line)
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    *b = strtol(p, &end, 0);
    return end != p;
}

static void vault_store(void) {
    char line[64];
    long slot = 0, size = 0;

    fputs("slot size> ", stdout);
    if (read_line(line, sizeof line) == 0 || !parse_two(line, &slot, &size)) {
        puts("input");
        return;
    }
    if (slot < 0 || slot >= NSLOTS || size < SIZE_MIN || size > SIZE_MAX) {
        puts("range");
        return;
    }
    char *chunk = malloc((size_t)size);
    if (!chunk) {
        puts("oom");
        return;
    }
    fputs("data> ", stdout);
    read_exact(chunk, (size_t)size + OVERREAD); /* BUG: 16 bytes past size */
    g_slots[slot].chunk = chunk;
    g_slots[slot].size = (size_t)size;
    puts("stored");
}

static void vault_show(void) {
    char line[64];
    long slot = 0;

    fputs("slot> ", stdout);
    if (read_line(line, sizeof line) == 0 || !parse_one(line, &slot) ||
        slot < 0 || slot >= NSLOTS) {
        puts("range");
        return;
    }
    struct slot *s = &g_slots[slot];
    if (!s->chunk) {
        puts("empty");
        return;
    }
    puts(s->chunk); /* leak primitive: runs past the data to the first NUL */
    puts("shown");
}

static void vault_edit(void) {
    char line[64];
    long slot = 0;

    fputs("slot> ", stdout);
    if (read_line(line, sizeof line) == 0 || !parse_one(line, &slot) ||
        slot < 0 || slot >= NSLOTS) {
        puts("range");
        return;
    }
    struct slot *s = &g_slots[slot];
    if (!s->chunk) {
        puts("empty");
        return;
    }
    fputs("data> ", stdout);
    read_exact(s->chunk, s->size + OVERREAD); /* BUG: same 16-byte overrun */
    puts("edited");
}

int main(void) {
    char menu[16];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("distinct 1.0 - 32 vault slots, nothing is ever freed");
    puts("1) reserve  2) view  3) rewrite  4) leave");
    for (;;) {
        fputs("> ", stdout);
        if (read_line(menu, sizeof menu) == 0)
            return 0;
        switch (menu[0]) {
        case '1':
            vault_store();
            break;
        case '2':
            vault_show();
            break;
        case '3':
            vault_edit();
            break;
        case '4':
            puts("bye");
            return 0;
        default:
            puts("menu");
            break;
        }
    }
}
