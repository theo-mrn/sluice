#include "prompt.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "clock.h"
#include "json.h"

typedef struct request {
    void *ctx;
    char *text;
    sl_prompt_reply cb;
    struct request *next;
    char id[17];     /* admin channel: what the question is called outside */
    char *meta;      /* admin channel: JSON members that describe it, or NULL */
    int64_t created; /* admin channel: when it was asked (ms) */
} request;

struct sl_prompt {
    char *path;
    int fd;
    request *head;
    request *tail;
    char line[256];
    size_t line_len;
    int line_overflow; /* the line being read is too long: its end is discarded */
    char *command;     /* asked instead of the terminal when set */
    int admin;         /* the questions wait for an answer at the admin listener */
    pid_t child;       /* the command being run for the first question, else 0 */
};

/* A command that ends is noticed through SIGCHLD: the handler writes a byte to a pipe that sits in
 * the poll set, the only thing a signal handler can safely do for a loop like sluice's. */
static int chld_pipe[2] = {-1, -1};

static void on_sigchld(int sig)
{
    int saved = errno;
    char b = 0;

    (void)sig;
    if (chld_pipe[1] >= 0) {
        (void)!write(chld_pipe[1], &b, 1); /* a full pipe already holds a wake-up */
    }
    errno = saved;
}

static int prepare_sigchld(void)
{
    struct sigaction sa;

    if (chld_pipe[0] >= 0) {
        return 0;
    }
    if (pipe(chld_pipe) != 0) {
        chld_pipe[0] = chld_pipe[1] = -1;
        return -1;
    }
    for (int i = 0; i < 2; i++) {
        (void)fcntl(chld_pipe[i], F_SETFL, fcntl(chld_pipe[i], F_GETFL) | O_NONBLOCK);
        (void)fcntl(chld_pipe[i], F_SETFD, FD_CLOEXEC);
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    return sigaction(SIGCHLD, &sa, NULL);
}

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
    free(r->meta);
    free(r);
}

/* ---- asking a command ---- */

/* Kills the command being run, with whatever it started (it has its own process group), and waits
 * for it. */
static void stop_command(sl_prompt *p)
{
    if (p->child > 0) {
        (void)kill(-p->child, SIGKILL);
        (void)kill(p->child, SIGKILL);
        while (waitpid(p->child, NULL, 0) < 0 && errno == EINTR) {
        }
        p->child = 0;
    }
}

int sl_prompt_set_command(sl_prompt *p, const char *command)
{
    char *copy = strdup(command);

    if (copy == NULL || prepare_sigchld() != 0) {
        free(copy);
        return -1;
    }
    free(p->command);
    p->command = copy;
    return 0;
}

/* Runs the command for the question at the head of the queue. Returns 0, or -1 when it cannot be
 * started. */
static int start_command(sl_prompt *p)
{
    int in[2];
    pid_t pid;
    const char *text = p->head->text;
    size_t n = strlen(text);

    if (pipe(in) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(in[0]);
        close(in[1]);
        return -1;
    }
    if (pid == 0) {
        long maxfd = sysconf(_SC_OPEN_MAX);
        int devnull = open("/dev/null", O_WRONLY);
        struct sigaction dfl;

        (void)setpgid(0, 0);
        (void)dup2(in[0], 0);
        if (devnull >= 0) {
            (void)dup2(devnull, 1);
        }
        /* only the standard descriptors: nothing of sluice's (sockets, the terminal) is inherited
         */
        if (maxfd < 0 || maxfd > 4096) {
            maxfd = 4096;
        }
        for (int fd = 3; fd < maxfd; fd++) {
            (void)close(fd);
        }
        memset(&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        (void)sigaction(SIGCHLD, &dfl, NULL);
        (void)sigaction(SIGPIPE, &dfl, NULL); /* sluice ignores it; a command should not */
        execl("/bin/sh", "sh", "-c", p->command, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid); /* also from here, so that a kill right away finds the group */
    close(in[0]);
    (void)fcntl(in[1], F_SETFL, fcntl(in[1], F_GETFL) | O_NONBLOCK);
    /* the question is small (a pipe holds far more); a command that does not read it just does not
     */
    (void)!write(in[1], text, n);
    close(in[1]);
    p->child = pid;
    return 0;
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
    stop_command(p);
    if (p->fd >= 0) {
        close(p->fd);
    }
    free(p->command);
    free(p->path);
    free(p);
}

int sl_prompt_fd(const sl_prompt *p)
{
    if (p->head == NULL || p->admin) {
        return -1;
    }
    return p->command != NULL ? chld_pipe[0] : p->fd;
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

static void pop_head(sl_prompt *p);

int sl_prompt_ask(sl_prompt *p, void *ctx, const char *text, sl_prompt_reply cb)
{
    request *r;

    if (p->admin) {
        static const char hex[] = "0123456789abcdef";
        uint8_t rnd[8];

        r = calloc(1, sizeof *r);
        if (r == NULL) {
            return -2;
        }
        r->text = strdup(text);
        if (r->text == NULL || RAND_bytes(rnd, sizeof rnd) != 1) {
            free_request(r);
            return -2;
        }
        for (int i = 0; i < 8; i++) {
            r->id[2 * i] = hex[rnd[i] >> 4];
            r->id[2 * i + 1] = hex[rnd[i] & 15];
        }
        r->ctx = ctx;
        r->cb = cb;
        r->created = sl_now_ms();
        if (p->tail != NULL) {
            p->tail->next = r;
        } else {
            p->head = r;
        }
        p->tail = r;
        return 0; /* nothing is shown: it waits to be answered at the admin listener */
    }

    if (p->command == NULL) {
        open_terminal(p);
        if (p->fd < 0) {
            return -1;
        }
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
        if (p->command != NULL) {
            if (start_command(p) != 0) {
                pop_head(p);
                return -2;
            }
        } else {
            show_head(p);
        }
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

/* The command for the question now at the head, if any; one that cannot be started is a no. */
static void start_next_command(sl_prompt *p)
{
    while (p->head != NULL && start_command(p) != 0) {
        request *r = p->head;
        sl_prompt_reply cb = r->cb;
        void *ctx = r->ctx;

        pop_head(p);
        cb(ctx, 0);
    }
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
        if (p->admin) {
            return;
        }
        if (was_head) {
            if (p->command != NULL) {
                stop_command(p);
                start_next_command(p);
            } else {
                if (p->fd >= 0) {
                    write_all(p->fd, "\n(withdrawn)\n", 13);
                }
                show_head(p);
            }
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

/* Has the command of the question at the head ended? Its exit status is the answer. */
static void command_check(sl_prompt *p)
{
    request *r = p->head;
    sl_prompt_reply cb;
    void *ctx;
    int status = 0;
    pid_t w;

    if (r == NULL || p->child <= 0) {
        return;
    }
    do {
        w = waitpid(p->child, &status, WNOHANG);
    } while (w < 0 && errno == EINTR);
    if (w == 0) {
        return; /* still running */
    }
    cb = r->cb;
    ctx = r->ctx;
    p->child = 0;
    pop_head(p);
    cb(ctx, w > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    start_next_command(p);
}

void sl_prompt_readable(sl_prompt *p)
{
    char buf[128];
    ssize_t n;

    if (p->command != NULL) {
        while (read(chld_pipe[0], buf, sizeof buf) > 0) { /* the wake-ups are spent */
        }
        command_check(p);
        return;
    }
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

/* ---- the admin channel ---- */

int sl_prompt_set_admin(sl_prompt *p)
{
    p->admin = 1;
    return 0;
}

const char *sl_prompt_admin_id(const sl_prompt *p, const void *ctx)
{
    for (const request *r = p->head; r != NULL; r = r->next) {
        if (r->ctx == ctx) {
            return r->id;
        }
    }
    return NULL;
}

void sl_prompt_admin_meta(sl_prompt *p, const void *ctx, const char *json_members)
{
    for (request *r = p->head; r != NULL; r = r->next) {
        if (r->ctx == ctx) {
            free(r->meta);
            r->meta = strdup(json_members);
            return;
        }
    }
}

size_t sl_prompt_admin_count(const sl_prompt *p)
{
    size_t n = 0;

    for (const request *r = p->head; r != NULL; r = r->next) {
        n++;
    }
    return n;
}

int sl_prompt_admin_json(const sl_prompt *p, sl_buf *out)
{
    int64_t now = sl_now_ms();
    int rc = sl_buf_append(out, "[", 1) != 0;

    for (const request *r = p->head; r != NULL; r = r->next) {
        char head[96];

        snprintf(head, sizeof head, "%s{\"id\":\"%s\",\"age_s\":%lld", r == p->head ? "" : ",",
                 r->id, (long long)((now - r->created) / 1000));
        rc |= sl_buf_append(out, head, strlen(head)) != 0;
        if (r->meta != NULL && r->meta[0] != '\0') {
            rc |= sl_buf_append(out, ",", 1) != 0;
            rc |= sl_buf_append(out, r->meta, strlen(r->meta)) != 0;
        }
        rc |= sl_buf_append(out, "}", 1) != 0;
    }
    rc |= sl_buf_append(out, "]\n", 2) != 0;
    return rc ? -1 : 0;
}

int sl_prompt_admin_text(const sl_prompt *p, const char *id, sl_buf *out)
{
    for (const request *r = p->head; r != NULL; r = r->next) {
        if (strcmp(r->id, id) == 0) {
            return sl_buf_append(out, r->text, strlen(r->text)) == 0 ? 0 : -1;
        }
    }
    return -1;
}

int sl_prompt_admin_answer(sl_prompt *p, const char *id, int yes)
{
    for (request *r = p->head; r != NULL; r = r->next) {
        if (strcmp(r->id, id) == 0) {
            void *ctx = r->ctx;
            sl_prompt_reply cb = r->cb;

            sl_prompt_cancel(p, ctx); /* off the list first: the reply may ask or cancel again */
            cb(ctx, yes);
            return 0;
        }
    }
    return -1;
}
