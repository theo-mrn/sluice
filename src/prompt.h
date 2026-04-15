#ifndef SLUICE_PROMPT_H
#define SLUICE_PROMPT_H

/* Asking a person a yes / no question on a terminal, one question at a time; or asking a command,
 * which is how an answer can come from anywhere else (a chat message, a ticket, another program).
 *
 * The terminal is /dev/tty unless another path is given (the tests give a pseudo-terminal). It is
 * never stdout: that is the JSON log. It is opened when the first question comes and kept, so that
 * a sluice with no terminal at all (a service, a container) only finds out when someone has to be
 * asked, and then the answer is "no".
 *
 * With a command (sl_prompt_set_command), nothing is shown on a terminal: for each question the
 * command is run by the shell, the question is its standard input, and its exit status is the
 * answer (0 is yes, anything else is no, and so is a command that cannot be run). Its standard
 * output is discarded (it is not sluice's: that is the JSON log) and its standard error is
 * sluice's. A command that does not end before the question times out is killed, with whatever it
 * started.
 *
 * The questions wait in a queue; the first one is shown, the others when its turn comes. The caller
 * puts sl_prompt_fd() in its poll set (it is -1 when no question is waiting) and calls
 * sl_prompt_readable() when the descriptor is readable. */

#include <stddef.h>

#include "buf.h"

typedef struct sl_prompt sl_prompt;
typedef void (*sl_prompt_reply)(void *ctx, int yes);

sl_prompt *sl_prompt_new(const char *tty_path);

/* Asks a command instead of a terminal from now on. Returns 0, or -1 when out of memory. */
int sl_prompt_set_command(sl_prompt *p, const char *command);
void sl_prompt_free(sl_prompt *p);

/* The descriptor to wait on while a question is shown (the terminal, or the pipe that closes when
 * the command is over), else -1. */
int sl_prompt_fd(const sl_prompt *p);

/* Queues a question: `text` is shown as it is when its turn comes (or given to the command), and
 * cb(ctx, yes) is called with the reply (on a terminal anything that does not start with y or Y is
 * a no). Returns 0, -1 when there is no terminal to ask on (nothing is queued), -2 when out of
 * memory or when the command cannot be started. */
int sl_prompt_ask(sl_prompt *p, void *ctx, const char *text, sl_prompt_reply cb);

/* ---- the admin channel ----
 *
 * With sl_prompt_set_admin nothing is shown and no command is run: a question waits, with an
 * identifier of its own (16 hex digits, from the random generator), until somebody answers it
 * through the admin listener (admin.h) or the caller withdraws it (it times out, or the client
 * leaves). Any number of questions wait at once. */
int sl_prompt_set_admin(sl_prompt *p);
/* The identifier of the question of ctx, or NULL. */
const char *sl_prompt_admin_id(const sl_prompt *p, const void *ctx);
/* JSON members ("user":"x","rule":"y") shown beside it in the list. They must be valid JSON. */
void sl_prompt_admin_meta(sl_prompt *p, const void *ctx, const char *json_members);
size_t sl_prompt_admin_count(const sl_prompt *p);
int sl_prompt_admin_json(const sl_prompt *p, sl_buf *out);
int sl_prompt_admin_text(const sl_prompt *p, const char *id, sl_buf *out);
/* Answers it: the reply of its caller is called. 0, or -1 when no question has that id. */
int sl_prompt_admin_answer(sl_prompt *p, const char *id, int yes);

/* Withdraws the question of ctx (the client left, or the time ran out). */
void sl_prompt_cancel(sl_prompt *p, void *ctx);

/* The terminal has something to read, or the command has ended. */
void sl_prompt_readable(sl_prompt *p);

#endif
