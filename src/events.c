#include "events.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "metrics.h"

#define MAX_RUNNING 4
#define MAX_QUEUED 64
#define LINE_MAX_BYTES 16384
#define TIMEOUT_MS 15000

typedef struct {
    pid_t pid;
    int64_t started;
} running;

typedef struct {
    char event[64];
    char *line;
    size_t len;
} queued;

struct sl_events {
    char *command;
    char *filter; /* ",a,b,c," so that a name is found between two commas */
    running run[MAX_RUNNING];
    size_t nrun;
    queued queue[MAX_QUEUED];
    size_t head, nq;
};

sl_events *sl_events_new(const char *command, const char *filter)
{
    sl_events *e = calloc(1, sizeof *e);
    const char *f = filter != NULL && filter[0] != '\0' ? filter : SL_EVENTS_DEFAULT;

    if (e == NULL) {
        return NULL;
    }
    e->command = strdup(command);
    e->filter = malloc(strlen(f) + 3);
    if (e->command == NULL || e->filter == NULL) {
        sl_events_free(e);
        return NULL;
    }
    e->filter[0] = ',';
    strcpy(e->filter + 1, f);
    strcat(e->filter, ",");
    return e;
}

void sl_events_free(sl_events *e)
{
    if (e == NULL) {
        return;
    }
    for (size_t i = 0; i < e->nrun; i++) {
        (void)kill(-e->run[i].pid, SIGKILL);
        (void)kill(e->run[i].pid, SIGKILL);
        while (waitpid(e->run[i].pid, NULL, 0) < 0 && errno == EINTR) {
        }
    }
    for (size_t i = 0; i < e->nq; i++) {
        free(e->queue[(e->head + i) % MAX_QUEUED].line);
    }
    free(e->command);
    free(e->filter);
    free(e);
}

static int wanted(const sl_events *e, const char *event)
{
    char key[80];

    if (strlen(event) > 64) {
        return 0;
    }
    key[0] = ',';
    strcpy(key + 1, event);
    strcat(key, ",");
    return strstr(e->filter, key) != NULL;
}

static int start(sl_events *e, const queued *q, int64_t now_ms)
{
    int in[2];
    pid_t pid;

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
        if (maxfd < 0 || maxfd > 4096) {
            maxfd = 4096;
        }
        for (int fd = 3; fd < maxfd; fd++) {
            (void)close(fd); /* nothing of sluice's (sockets, files) is inherited */
        }
        memset(&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        (void)sigaction(SIGCHLD, &dfl, NULL);
        (void)sigaction(SIGPIPE, &dfl, NULL);
        (void)setenv("SLUICE_EVENT", q->event, 1);
        execl("/bin/sh", "sh", "-c", e->command, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    close(in[0]);
    (void)fcntl(in[1], F_SETFL, fcntl(in[1], F_GETFL) | O_NONBLOCK);
    /* a line is small (a pipe holds far more); a command that does not read it just does not */
    (void)!write(in[1], q->line, q->len);
    (void)!write(in[1], "\n", 1);
    close(in[1]);
    e->run[e->nrun].pid = pid;
    e->run[e->nrun].started = now_ms;
    e->nrun++;
    sl_metric_inc(SL_M_HOOKS, "started", NULL);
    return 0;
}

void sl_events_offer(sl_events *e, const char *event, const char *line, size_t len)
{
    queued *q;

    if (!wanted(e, event)) {
        return;
    }
    if (len > LINE_MAX_BYTES || e->nq >= MAX_QUEUED) {
        sl_metric_inc(SL_M_HOOKS, "dropped", NULL);
        return;
    }
    q = &e->queue[(e->head + e->nq) % MAX_QUEUED];
    q->line = malloc(len + 1);
    if (q->line == NULL) {
        sl_metric_inc(SL_M_HOOKS, "dropped", NULL);
        return;
    }
    memcpy(q->line, line, len);
    q->line[len] = '\0';
    q->len = len;
    snprintf(q->event, sizeof q->event, "%s", event);
    e->nq++;
}

void sl_events_tick(sl_events *e, int64_t now_ms)
{
    for (size_t i = 0; i < e->nrun;) {
        int status = 0;
        pid_t w = waitpid(e->run[i].pid, &status, WNOHANG);
        int ended = w == e->run[i].pid;

        if (!ended && now_ms >= e->run[i].started + TIMEOUT_MS) {
            (void)kill(-e->run[i].pid, SIGKILL);
            (void)kill(e->run[i].pid, SIGKILL);
            (void)waitpid(e->run[i].pid, NULL, 0);
            sl_metric_inc(SL_M_HOOKS, "timeout", NULL);
            ended = 2;
        } else if (ended) {
            sl_metric_inc(SL_M_HOOKS,
                          WIFEXITED(status) && WEXITSTATUS(status) == 0 ? "ok" : "failed", NULL);
        }
        if (ended) {
            e->run[i] = e->run[--e->nrun];
        } else {
            i++;
        }
    }
    while (e->nrun < MAX_RUNNING && e->nq > 0) {
        queued *q = &e->queue[e->head];

        if (start(e, q, now_ms) != 0) {
            sl_metric_inc(SL_M_HOOKS, "failed", NULL);
        }
        free(q->line);
        e->head = (e->head + 1) % MAX_QUEUED;
        e->nq--;
    }
}

size_t sl_events_busy(const sl_events *e)
{
    return e->nrun + e->nq;
}
