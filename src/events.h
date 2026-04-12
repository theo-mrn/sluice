#ifndef SLUICE_EVENTS_H
#define SLUICE_EVENTS_H

/* A command run for the events of the log that matter to somebody (--event-command): what turns a
 * line of the log into a message in a chat, a ticket, a pager, a webhook. For each line of an event
 * in the filter, the command is run by the shell with the line (one JSON object, the same as in the
 * log) on its standard input and the name of the event in $SLUICE_EVENT. Its output is discarded.
 *
 * sluice never waits for it: at most 4 run at once, at most 64 lines wait for their turn (a line
 * that finds the queue full is dropped and counted, rather than slowing the proxy), and a command
 * that has not ended after 15 seconds is killed with whatever it started. Its exit status is not
 * looked at beyond the count in the metrics. */

#include <stddef.h>
#include <stdint.h>

typedef struct sl_events sl_events;

/* filter: comma-separated event names; NULL or "" for the default (SL_EVENTS_DEFAULT). NULL when
 * out of memory. */
#define SL_EVENTS_DEFAULT "alert,kill,confirm_pending,admin_denied,policy_reload_failed"
sl_events *sl_events_new(const char *command, const char *filter);
void sl_events_free(sl_events *e);

/* A line of the log (without its newline). Queued when the event is in the filter. */
void sl_events_offer(sl_events *e, const char *event, const char *line, size_t len);

/* Collects the commands that ended, kills the ones that are late, starts the next ones. */
void sl_events_tick(sl_events *e, int64_t now_ms);
/* How many are running or waiting: when non-zero, the caller should tick soon. */
size_t sl_events_busy(const sl_events *e);

#endif
