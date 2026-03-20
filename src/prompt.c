#include "prompt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

typedef struct request {
    void *ctx;
    char *text;
    sl_prompt_reply cb;
    struct request *next;
} request;

struct sl_prompt {
    char *path;
    int fd;
    request *head;
    request *tail;
    char line[256];
    size_t line_len;
    int line_overflow; /* the line being read is too long: its end is discarded */
};

sl_prompt *sl_prompt_new(const char *tty_path)
{
    sl_prompt *p = calloc(1, sizeof *p);

    if (p == NULL) {
        return NULL;
    }
    p->path = strdup(tty_path != NULL && tty_path[0] != '\0' ? tty_path : "/dev/tty");
    p->fd = -1;
    if (p->path == NULL) {
        free(p);
        return NULL;
    }
    return p;
}

static void free_request(request *r)
{
    free(r->text);
    free(r);
}

void sl_prompt_free(sl_prompt *p)
{
    if (p == NULL) {
        return;
    }
    while (p->head != NULL) {
        request *next = p->head->next;

        free_request(p->head);
        p->head = next;
    }
    if (p->fd >= 0) {
        close(p->fd);
    }
    free(p->path);
    free(p);
}

int sl_prompt_fd(const sl_prompt *p)
{
    return p->head != NULL ? p->fd : -1;
}

static void write_all(int fd, const char *s, size_t n)
{
    size_t done = 0;
    int stalls = 0;

    while (done < n && stalls < 200) {
        ssize_t w = write(fd, s + done, n - done);

        if (w > 0) {
            done += (size_t)w;
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* a terminal that is not draining: do not wait for ever */
            nanosleep(&(struct timespec){0, 1000000}, NULL);
            stalls++;
        } else {
            return;
        }
    }
}

static void show_head(sl_prompt *p)
{
    if (p->head == NULL || p->fd < 0) {
        return;
    }
    p->line_len = 0;
    p->line_overflow = 0;
    (void)tcflush(p->fd, TCIFLUSH); /* what was typed before the question is not an answer to it */
    write_all(p->fd, p->head->text, strlen(p->head->text));
}

static void open_terminal(sl_prompt *p)
{
    if (p->fd >= 0) {
        return;
    }
    p->fd = open(p->path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
}

int sl_prompt_ask(sl_prompt *p, void *ctx, const char *text, sl_prompt_reply cb)
{
    request *r;

    open_terminal(p);
    if (p->fd < 0) {
        return -1;
    }
    r = calloc(1, sizeof *r);
    if (r == NULL) {
        return -2;
    }
    r->text = strdup(text);
    if (r->text == NULL) {
        free(r);
        return -2;
    }
    r->ctx = ctx;
    r->cb = cb;
    if (p->tail != NULL) {
        p->tail->next = r;
    } else {
        p->head = r;
    }
    p->tail = r;
    if (p->head == r) {
        show_head(p);
    }
    return 0;
}

static void pop_head(sl_prompt *p)
{
    request *r = p->head;

    p->head = r->next;
    if (p->head == NULL) {
        p->tail = NULL;
    }
    free_request(r);
}

void sl_prompt_cancel(sl_prompt *p, void *ctx)
{
    request **link = &p->head;
    request *prev = NULL;

    while (*link != NULL && (*link)->ctx != ctx) {
        prev = *link;
        link = &(*link)->next;
    }
    if (*link == NULL) {
        return;
    }
    {
        request *gone = *link;
        int was_head = gone == p->head;

        *link = gone->next;
        if (p->tail == gone) {
            p->tail = prev;
        }
        free_request(gone);
        if (was_head) {
            if (p->fd >= 0) {
                write_all(p->fd, "\n(withdrawn)\n", 13);
            }
            show_head(p);
        }
    }
}

static void answer(sl_prompt *p, int yes)
{
    request *r = p->head;
    sl_prompt_reply cb = r->cb;
    void *ctx = r->ctx;

    pop_head(p);
    if (p->fd >= 0) {
        const char *msg = yes ? "  committing\n" : "  rolling back\n";

        write_all(p->fd, msg, strlen(msg));
    }
    cb(ctx, yes);
    show_head(p);
}

void sl_prompt_readable(sl_prompt *p)
{
    char buf[128];
    ssize_t n;

    if (p->fd < 0) {
        return;
    }
    n = read(p->fd, buf, sizeof buf);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        /* the terminal is gone: nobody can answer. Whoever waits gets a no, and a later question
         * tries to open it again. */
        close(p->fd);
        p->fd = -1;
        while (p->head != NULL) {
            request *r = p->head;
            sl_prompt_reply cb = r->cb;
            void *ctx = r->ctx;

            pop_head(p);
            cb(ctx, 0);
        }
        return;
    }
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') {
            size_t k = 0;
            int yes;

            while (k < p->line_len && (p->line[k] == ' ' || p->line[k] == '\t')) {
                k++;
            }
            yes = !p->line_overflow && k < p->line_len && (p->line[k] == 'y' || p->line[k] == 'Y');
            p->line_len = 0;
            p->line_overflow = 0;
            if (p->head != NULL) {
                answer(p, yes);
            }
        } else if (p->line_len < sizeof p->line) {
            p->line[p->line_len++] = buf[i];
        } else {
            p->line_overflow = 1;
        }
    }
}
