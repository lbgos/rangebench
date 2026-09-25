/* reservoir — a 16-cell heap reservoir with pour/drain/poke/moor ops.
 *
 * Fresh menu-driven target for a heap-grooming exercise. pour() request
 * sizes come strictly from a fixed whitelist, so no arbitrary size exists;
 * drain() hands a cell's chunk back to glibc but never clears the cell
 * mapping — the single use-after-free surface: poke() on a drained cell
 * writes into whatever now occupies that region. poke() reads `len` bytes
 * (1..0x200) to cell_ptr + off (0..0x20000), so a write can land far past
 * any cell edge. There is no read-back op anywhere (leakless by design):
 * pour never takes payload bytes, and stdout is deliberately left on its
 * default (pipe => fully buffered) mode with an explicit flush at every
 * writer point, keeping each session byte-deterministic while the flush
 * state itself stays meaningful. setvbuf is deliberately absent.
 * One forked process per connection (socat): every session starts with
 * fresh ASLR, so heap and libc nibbles re-randomize per attempt.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NCELLS 16

/* pour() hands out exactly these request sizes (chunk classes
 * 0x30/0xa0/0x3e0/0x3f0/0x410/0x420/0x620); no other size is accepted. */
static const size_t POUR_SIZES[] = {0x28, 0x98, 0x3d8, 0x3e8, 0x408, 0x418, 0x618};
#define POUR_N (sizeof POUR_SIZES / sizeof POUR_SIZES[0])

/* poke() reach: any nonnegative offset, bounded length. */
#define POKE_OFF_MAX 0x20000
#define POKE_LEN_MAX 0x200

struct cell {
    char *mem;
    size_t cap;
};

static struct cell g_cells[NCELLS];

/* Every writer point flushes explicitly so each session stays
 * byte-deterministic even though stdout keeps its default buffering. */
static void writer(const char *s) {
    fputs(s, stdout);
    fflush(stdout);
}

/* Byte-exact receive: blocks until `want` bytes arrive or the peer goes
 * away. Callers always send the full count, so remote runs stay
 * deterministic (no short-read ambiguity inside a poke window). */
static long recv_exact(char *dst, size_t want) {
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
static size_t recv_line(char *dst, size_t cap) {
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

static int parse_three(char *line, long *a, long *b, long *c) {
    char *p, *end;
    while (*line == ' ' || *line == '\t')
        line++;
    *a = strtol(line, &p, 0);
    if (p == line)
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    *b = strtol(p, &end, 0);
    if (end == p)
        return 0;
    while (*end == ' ' || *end == '\t')
        end++;
    *c = strtol(end, &p, 0);
    return p != end;
}

/* pour(cell, size): claim a chunk for the cell from the fixed whitelist
 * only; allocation is the whole interaction, no payload bytes are read. */
static void barn_pour(void) {
    char line[64];
    long cell = 0, size = 0;
    size_t i;

    writer("cell size> ");
    if (recv_line(line, sizeof line) == 0 || !parse_two(line, &cell, &size)) {
        writer("dud\n");
        return;
    }
    if (cell < 0 || cell >= NCELLS) {
        writer("bounds\n");
        return;
    }
    for (i = 0; i < POUR_N; i++)
        if ((size_t)size == POUR_SIZES[i])
            break;
    if (i == POUR_N) {
        writer("nofit\n");
        return;
    }
    if (g_cells[cell].mem) {
        writer("full\n");
        return;
    }
    char *mem = malloc(POUR_SIZES[i]);
    if (!mem) {
        writer("swell\n");
        return;
    }
    g_cells[cell].mem = mem;
    g_cells[cell].cap = (size_t)size;
    writer("poured\n");
}

/* drain(cell): the one vulnerability class — the mapping is deliberately
 * NOT cleared, so poke() on this cell lands on whatever glibc re-carved
 * the region into later. */
static void barn_drain(void) {
    char line[64];
    long cell = 0;

    writer("cell> ");
    if (recv_line(line, sizeof line) == 0 || !parse_one(line, &cell)) {
        writer("dud\n");
        return;
    }
    if (cell < 0 || cell >= NCELLS) {
        writer("bounds\n");
        return;
    }
    if (!g_cells[cell].mem) {
        writer("blur\n");
        return;
    }
    free(g_cells[cell].mem);
    writer("freed\n");
}

/* poke(cell, off, len): byte-exact arbitrary-offset write. */
static void barn_poke(void) {
    char line[64];
    long cell = 0, off = 0, len = 0;

    writer("dive off len> ");
    if (recv_line(line, sizeof line) == 0 ||
        !parse_three(line, &cell, &off, &len)) {
        writer("dud\n");
        return;
    }
    if (cell < 0 || cell >= NCELLS || !g_cells[cell].mem ||
        off < 0 || off > POKE_OFF_MAX || len < 1 || len > POKE_LEN_MAX) {
        writer("bounds\n");
        return;
    }
    (void)recv_exact(g_cells[cell].mem + off, (size_t)len);
    writer("poked\n");
}

int main(void) {
    char menu[16];

    writer("reservoir 1.0 - 16 cells, nothing is ever forgotten\n");
    writer("1) pour  2) drain  3) poke  4) moor\n");
    for (;;) {
        writer("weir> ");
        if (recv_line(menu, sizeof menu) == 0)
            return 0;
        switch (menu[0]) {
        case '1':
            barn_pour();
            break;
        case '2':
            barn_drain();
            break;
        case '3':
            barn_poke();
            break;
        case '4':
            writer("moored\n");
            return 0;
        default:
            writer("waste\n");
            break;
        }
    }
}
