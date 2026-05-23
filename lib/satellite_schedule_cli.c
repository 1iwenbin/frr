// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Satellite ISL Link Schedule Engine — CLI stub
 *
 * The actual DEFUN macros and install_element calls have been moved to
 * isisd/isis_schedule.c so that vtysh's command auto-extractor can find
 * them (it only scans daemon source files, not lib/ source files).
 *
 * Copyright (C) 2026 oaemu
 */

#include <zebra.h>

#include "satellite_schedule.h"

/* CLI commands are now registered from isisd/isis_schedule.c */
void satellite_schedule_cli_init(void)
{
	/* Commands installed in isisd/isis_schedule.c — isis_schedule_cli_init() */
}
