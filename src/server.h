#ifndef SLUICE_SERVER_H
#define SLUICE_SERVER_H

#include "config.h"

/* Listens, accepts clients and runs the poll() loop until SIGINT or SIGTERM.
 * Returns the process exit code: 0 after a clean shutdown, 1 if it could not start. */
int sl_server_run(const sl_config *cfg);

#endif
