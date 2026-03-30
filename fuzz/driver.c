/* A small, deterministic mutation fuzzer around LLVMFuzzerTestOneInput, for machines whose compiler
 * has no libFuzzer (Apple's clang, for one). It is not a coverage-guided fuzzer: it takes the seed
 * inputs of fuzz/corpus, mutates them at random and runs the targets under whatever sanitizers the
 * build has. The same seed gives the same run, so a failure can be replayed.
 *
 *   fuzz_driver [-n INPUTS] [-s SEED] [-t SECONDS] [-o FILE] PATH...
 *
 * Every file in the PATHs (directories are walked) is run once as it is, then INPUTS mutated inputs
 * are run, or as many as fit in SECONDS. The input that is about to run is first written to FILE
 * (default: fuzz-last-input), so that after a crash it is the file that caused it. */

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
size_t sluice_fuzz_target_count(void);

#define MAX_INPUT 4096

typedef struct {
    uint8_t *data;
    size_t size;
} input;

static input *pool;
static size_t pool_n;
static size_t pool_cap;
static uint64_t rng_state = 1;
static const char *last_input_path = "fuzz-last-input";

static uint64_t rnd(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

static size_t below(size_t n)
{
    return n ? (size_t)(rnd() % n) : 0;
}

static void pool_add(const uint8_t *data, size_t size)
{
    if (pool_n == pool_cap) {
        pool_cap = pool_cap ? pool_cap * 2 : 64;
        pool = realloc(pool, pool_cap * sizeof *pool);
        if (pool == NULL) {
            abort();
        }
    }
    pool[pool_n].data = malloc(size ? size : 1);
    memcpy(pool[pool_n].data, data, size);
    pool[pool_n].size = size;
    pool_n++;
}

static void load_path(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "fuzz_driver: cannot read %s\n", path);
        exit(2);
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *e;

        while (d != NULL && (e = readdir(d)) != NULL) {
            char sub[1024];

            if (e->d_name[0] == '.') {
                continue;
            }
            snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
            load_path(sub);
        }
        if (d != NULL) {
            closedir(d);
        }
    } else {
        FILE *f = fopen(path, "rb");
        uint8_t buf[MAX_INPUT];
        size_t n;

        if (f == NULL) {
            return;
        }
        n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        pool_add(buf, n);
    }
}

static const uint32_t interesting[] = {
    0,          1,          4,          5,      8,        16,       0x7f,
    0x80,       0xff,       0x100,      10000,  10001,    0xffff,   0x3fffffff,
    0x40000000, 0x7fffffff, 0xffffffff, 196608, 80877102, 80877103, 80877104};

/* One random change to buf (of size *n, room for MAX_INPUT bytes). */
static void mutate(uint8_t *buf, size_t *n, size_t other_size, const uint8_t *other)
{
    size_t pos;

    switch (below(9)) {
    case 0: /* flip a bit */
        if (*n) {
            buf[below(*n)] ^= (uint8_t)(1u << below(8));
        }
        break;
    case 1: /* random byte */
        if (*n) {
            buf[below(*n)] = (uint8_t)rnd();
        }
        break;
    case 2: /* a byte that tends to matter: NUL, quote, backslash, newline, high bit */
        if (*n) {
            static const uint8_t special[] = {0x00, 0x27, 0x22, 0x5c, 0x0a, 0x7f,
                                              0x80, 0xc0, 0xff, 0x5b, 0x3d};

            buf[below(*n)] = special[below(sizeof special)];
        }
        break;
    case 3: { /* overwrite four bytes with a big-endian number that looks like a length or a code */
        uint32_t v = interesting[below(sizeof interesting / sizeof interesting[0])];

        if (*n >= 4) {
            pos = below(*n - 3);
            buf[pos] = (uint8_t)(v >> 24);
            buf[pos + 1] = (uint8_t)(v >> 16);
            buf[pos + 2] = (uint8_t)(v >> 8);
            buf[pos + 3] = (uint8_t)v;
        }
        break;
    }
    case 4: { /* insert a few random bytes */
        size_t k = 1 + below(8);

        if (*n + k <= MAX_INPUT) {
            pos = below(*n + 1);
            memmove(buf + pos + k, buf + pos, *n - pos);
            for (size_t i = 0; i < k; i++) {
                buf[pos + i] = (uint8_t)rnd();
            }
            *n += k;
        }
        break;
    }
    case 5: { /* delete a range */
        if (*n > 1) {
            size_t k = 1 + below(*n < 16 ? *n : 16);

            pos = below(*n - k + 1);
            memmove(buf + pos, buf + pos + k, *n - pos - k);
            *n -= k;
        }
        break;
    }
    case 6: { /* repeat a range (long inputs, long runs) */
        if (*n > 0) {
            size_t k = 1 + below(*n < 32 ? *n : 32);
            size_t times = 1 + below(64);

            pos = below(*n - k + 1);
            for (size_t t = 0; t < times && *n + k <= MAX_INPUT; t++) {
                memmove(buf + pos + k, buf + pos, *n - pos);
                *n += k;
            }
        }
        break;
    }
    case 7: { /* splice in a piece of another input */
        if (other_size > 0) {
            size_t k = 1 + below(other_size < 32 ? other_size : 32);
            size_t from = below(other_size - k + 1);

            pos = below(*n + 1);
            if (*n + k <= MAX_INPUT) {
                memmove(buf + pos + k, buf + pos, *n - pos);
                memcpy(buf + pos, other + from, k);
                *n += k;
            }
        }
        break;
    }
    default: /* change which target the input goes to */
        if (*n) {
            buf[0] = (uint8_t)below(sluice_fuzz_target_count());
        }
        break;
    }
}

static void run_one(const uint8_t *data, size_t size)
{
    FILE *f = fopen(last_input_path, "wb");

    if (f != NULL) {
        fwrite(data, 1, size, f);
        fclose(f);
    }
    LLVMFuzzerTestOneInput(data, size);
}

int main(int argc, char **argv)
{
    unsigned long long inputs = 20000;
    unsigned long long seconds = 0;
    unsigned long long done = 0;
    uint64_t seed = 1;
    time_t started = time(NULL);
    uint8_t buf[MAX_INPUT];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            inputs = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            seed = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            seconds = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            last_input_path = argv[++i];
        } else {
            load_path(argv[i]);
        }
    }
    rng_state = seed ? seed * 0x9E3779B97F4A7C15ULL : 1;

    for (size_t i = 0; i < pool_n; i++) {
        run_one(pool[i].data, pool[i].size);
    }
    printf("fuzz_driver: %zu seed inputs run as they are\n", pool_n);

    while (seconds ? (unsigned long long)(time(NULL) - started) < seconds : done < inputs) {
        size_t n;
        size_t rounds = 1 + below(4);
        const input *other = pool_n ? &pool[below(pool_n)] : NULL;

        if (pool_n) {
            const input *base = &pool[below(pool_n)];

            n = base->size;
            memcpy(buf, base->data, n);
        } else {
            n = 1 + below(64);
            for (size_t i = 0; i < n; i++) {
                buf[i] = (uint8_t)rnd();
            }
        }
        for (size_t r = 0; r < rounds; r++) {
            mutate(buf, &n, other ? other->size : 0, other ? other->data : NULL);
        }
        run_one(buf, n);
        done++;
    }
    printf("fuzz_driver: %llu mutated inputs, seed %llu, no failure\n", done,
           (unsigned long long)seed);
    remove(last_input_path);
    return 0;
}
