#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "check.h"
#include "prompt.h"

/* A pseudo-terminal pair: the prompt opens the slave as it would /dev/tty, the test is the person
 * on the master. */
typedef struct {
    int master;
    char slave[128];
} pty;

static int pty_open(pty *t)
{
    char *name;

    t->master = posix_openpt(O_RDWR | O_NOCTTY);
    if (t->master < 0 || grantpt(t->master) != 0 || unlockpt(t->master) != 0 ||
        (name = ptsname(t->master)) == NULL) {
        return -1;
    }
    snprintf(t->slave, sizeof t->slave, "%s", name);
    (void)fcntl(t->master, F_SETFL, fcntl(t->master, F_GETFL) | O_NONBLOCK);
    return 0;
}

typedef struct {
    int answers;
    int last;
    int order[8];
} replies;

static void got(void *ctx, int yes)
{
    replies *r = ctx;

    if (r->answers < 8) {
        r->order[r->answers] = yes;
    }
    r->answers++;
    r->last = yes;
}

/* Lets the prompt read what the person typed, for a short while; collects what it wrote. */
static void pump(sl_prompt *p, pty *t, char *out, size_t cap, int ms)
{
    size_t n = out[0] ? strlen(out) : 0;

    for (int waited = 0; waited < ms; waited += 10) {
        struct pollfd pfd[2];
        int count = 0;
        int fd = sl_prompt_fd(p);

        pfd[count++] = (struct pollfd){t->master, POLLIN, 0};
        if (fd >= 0) {
            pfd[count++] = (struct pollfd){fd, POLLIN, 0};
        }
        if (poll(pfd, (nfds_t)count, 10) > 0) {
            if (pfd[0].revents & POLLIN) {
                ssize_t r = read(t->master, out + n, cap - n - 1);

                if (r > 0) {
                    n += (size_t)r;
                    out[n] = '\0';
                }
            }
            if (count > 1 && (pfd[1].revents & (POLLIN | POLLHUP))) {
                sl_prompt_readable(p);
            }
        }
    }
}

static void type(pty *t, const char *s)
{
    CHECK(write(t->master, s, strlen(s)) == (ssize_t)strlen(s));
}

static void test_questions_in_turn(void)
{
    pty t;
    sl_prompt *p;
    replies r = {0};
    char out[2048] = "";

    CHECK(pty_open(&t) == 0);
    p = sl_prompt_new(t.slave);
    CHECK(p != NULL);
    CHECK(sl_prompt_fd(p) == -1); /* nothing asked: nothing to wait for */

    CHECK(sl_prompt_ask(p, &r, "first question? ", got) == 0);
    CHECK(sl_prompt_ask(p, &r, "second question? ", got) == 0);
    pump(p, &t, out, sizeof out, 100);
    CHECK(strstr(out, "first question?") != NULL);
    CHECK(strstr(out, "second question?") == NULL); /* only the first is shown */
    CHECK(sl_prompt_fd(p) >= 0);

    type(&t, "y\n");
    pump(p, &t, out, sizeof out, 200);
    CHECK(r.answers == 1 && r.last == 1);
    CHECK(strstr(out, "committing") != NULL);
    CHECK(strstr(out, "second question?") != NULL); /* its turn */

    type(&t, "n\n");
    pump(p, &t, out, sizeof out, 200);
    CHECK(r.answers == 2 && r.last == 0 && r.order[0] == 1 && r.order[1] == 0);
    CHECK(strstr(out, "rolling back") != NULL);
    CHECK(sl_prompt_fd(p) == -1);

    sl_prompt_free(p);
    close(t.master);
}

static void test_what_counts_as_yes(void)
{
    struct {
        const char *typed;
        int yes;
    } cases[] = {{"y\n", 1},   {"Y\n", 1},  {"yes\n", 1}, {"  y\n", 1},   {"\ty\n", 1},
                 {"n\n", 0},   {"\n", 0},   {"no\n", 0},  {"maybe\n", 0}, {"Yes please\n", 1},
                 {"x y\n", 0}, {"ok\n", 0}, {"1\n", 0},   {"y\r", 1}};

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        pty t;
        sl_prompt *p;
        replies r = {0};
        char out[512] = "";

        CHECK(pty_open(&t) == 0);
        p = sl_prompt_new(t.slave);
        CHECK(sl_prompt_ask(p, &r, "? ", got) == 0);
        pump(p, &t, out, sizeof out, 30);
        type(&t, cases[i].typed);
        pump(p, &t, out, sizeof out, 150);
        if (r.answers != 1 || r.last != cases[i].yes) {
            fprintf(stderr, "test_prompt.c: %zu: typed \"%s\": %d answers, last %d (want %d)\n", i,
                    cases[i].typed, r.answers, r.last, cases[i].yes);
            sl_test_failures++;
        }
        sl_prompt_free(p);
        close(t.master);
    }
}

static void test_long_line_is_a_no(void)
{
    pty t;
    sl_prompt *p;
    replies r = {0};
    char out[1024] = "";
    char junk[400];

    CHECK(pty_open(&t) == 0);
    p = sl_prompt_new(t.slave);
    CHECK(sl_prompt_ask(p, &r, "? ", got) == 0);
    pump(p, &t, out, sizeof out, 30);
    junk[0] = 'y';
    memset(junk + 1, 'a', sizeof junk - 3);
    junk[sizeof junk - 2] = '\n';
    junk[sizeof junk - 1] = '\0';
    type(&t, junk);
    pump(p, &t, out, sizeof out, 200);
    /* a line far longer than any answer starts with y, and is still not a yes */
    CHECK(r.answers <= 1 && (r.answers == 0 || r.last == 0));
    sl_prompt_free(p);
    close(t.master);
}

static void test_cancel(void)
{
    pty t;
    sl_prompt *p;
    replies a = {0};
    replies b = {0};
    char out[1024] = "";

    CHECK(pty_open(&t) == 0);
    p = sl_prompt_new(t.slave);
    CHECK(sl_prompt_ask(p, &a, "question A? ", got) == 0);
    CHECK(sl_prompt_ask(p, &b, "question B? ", got) == 0);
    pump(p, &t, out, sizeof out, 50);
    sl_prompt_cancel(p, &a); /* the one on screen is withdrawn: the next one is shown */
    pump(p, &t, out, sizeof out, 100);
    CHECK(strstr(out, "(withdrawn)") != NULL && strstr(out, "question B?") != NULL);
    type(&t, "y\n");
    pump(p, &t, out, sizeof out, 150);
    CHECK(a.answers == 0 && b.answers == 1 && b.last == 1);
    sl_prompt_cancel(p, &a); /* already gone: nothing happens */
    sl_prompt_cancel(p, &b);
    CHECK(sl_prompt_fd(p) == -1);

    /* withdrawing one that is waiting its turn */
    CHECK(sl_prompt_ask(p, &a, "A2? ", got) == 0);
    CHECK(sl_prompt_ask(p, &b, "B2? ", got) == 0);
    sl_prompt_cancel(p, &b);
    pump(p, &t, out, sizeof out, 50);
    type(&t, "n\n");
    pump(p, &t, out, sizeof out, 150);
    CHECK(a.answers == 1 && a.last == 0 && b.answers == 1);
    sl_prompt_free(p);
    close(t.master);
}

static void test_typed_before_the_question(void)
{
    pty t;
    sl_prompt *p;
    replies r = {0};
    char out[512] = "";

    CHECK(pty_open(&t) == 0);
    p = sl_prompt_new(t.slave);
    /* open the terminal first, with a question that is answered, then type ahead */
    CHECK(sl_prompt_ask(p, &r, "one? ", got) == 0);
    pump(p, &t, out, sizeof out, 30);
    type(&t, "n\n");
    pump(p, &t, out, sizeof out, 150);
    CHECK(r.answers == 1);
    type(&t, "y\n"); /* typed while nobody asks */
    pump(p, &t, out, sizeof out, 50);
    CHECK(sl_prompt_ask(p, &r, "two? ", got) == 0);
    pump(p, &t, out, sizeof out, 150);
    CHECK(r.answers == 1); /* the earlier "y" is not an answer to this question */
    type(&t, "n\n");
    pump(p, &t, out, sizeof out, 150);
    CHECK(r.answers == 2 && r.last == 0);
    sl_prompt_free(p);
    close(t.master);
}

static void test_no_terminal_and_hangup(void)
{
    sl_prompt *p = sl_prompt_new("/nonexistent/tty");
    replies r = {0};
    pty t;
    char out[512] = "";

    CHECK(sl_prompt_ask(p, &r, "? ", got) == -1); /* nothing is queued, nobody will answer */
    CHECK(sl_prompt_fd(p) == -1);
    sl_prompt_free(p);

    /* the terminal goes away while a question waits: that is a no, and nothing hangs */
    CHECK(pty_open(&t) == 0);
    p = sl_prompt_new(t.slave);
    CHECK(sl_prompt_ask(p, &r, "? ", got) == 0);
    CHECK(sl_prompt_ask(p, &r, "? ", got) == 0);
    pump(p, &t, out, sizeof out, 30);
    close(t.master);
    for (int i = 0; i < 20 && r.answers < 2; i++) {
        struct pollfd pfd = {sl_prompt_fd(p), POLLIN, 0};

        if (pfd.fd >= 0 && poll(&pfd, 1, 50) > 0) {
            sl_prompt_readable(p);
        }
    }
    CHECK(r.answers == 2 && r.order[0] == 0 && r.order[1] == 0);
    CHECK(sl_prompt_fd(p) == -1);
    sl_prompt_free(p);
}

int main(void)
{
    test_questions_in_turn();
    test_what_counts_as_yes();
    test_long_line_is_a_no();
    test_cancel();
    test_typed_before_the_question();
    test_no_terminal_and_hangup();
    return TEST_RESULT();
}
