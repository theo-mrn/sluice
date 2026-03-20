#ifndef SLUICE_PROMPT_H
#define SLUICE_PROMPT_H

/* Asking a person a yes / no question on a terminal, one question at a time.
 *
 * The terminal is /dev/tty unless another path is given (the tests give a pseudo-terminal). It is
 * never stdout: that is the JSON log. It is opened when the first question comes and kept, so that
 * a sluice with no terminal at all (a service, a container) only finds out when someone has to be
 * asked, and then the answer is "no".
 *
 * The questions wait in a queue; the first one is shown, the others when its turn comes. The caller
 * puts sl_prompt_fd() in its poll set (it is -1 when no question is waiting) and calls
 * sl_prompt_readable() when the descriptor is readable. */

#include <stddef.h>

typedef struct sl_prompt sl_prompt;
typedef void (*sl_prompt_reply)(void *ctx, int yes);

sl_prompt *sl_prompt_new(const char *tty_path);
void sl_prompt_free(sl_prompt *p);

/* The descriptor to wait on while a question is shown, else -1. */
int sl_prompt_fd(const sl_prompt *p);

/* Queues a question: `text` is shown as it is when its turn comes, and cb(ctx, yes) is called with
 * the reply (anything that does not start with y or Y is a no). Returns 0, -1 when there is no
 * terminal to ask on (nothing is queued), -2 when out of memory. */
int sl_prompt_ask(sl_prompt *p, void *ctx, const char *text, sl_prompt_reply cb);

/* Withdraws the question of ctx (the client left, or the time ran out). */
void sl_prompt_cancel(sl_prompt *p, void *ctx);

/* The terminal has something to read. */
void sl_prompt_readable(sl_prompt *p);

#endif
