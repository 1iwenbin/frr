// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Satellite ISL Link Schedule Engine — IS-IS CLI commands
 *
 * DEFUN + install_element are in isisd/ (not lib/) so that vtysh's
 * command auto-extractor picks them up and registers the appropriate
 * DEFSH entries in vtysh_cmd.c.
 *
 * Copyright (C) 2026 oaemu
 */

#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "satellite_schedule.h"

/* Forward declaration — also declared extern in isis_main.c */
void isis_schedule_cli_init(void);

DEFUN(sat_sched_load,
      satellite_schedule_load_cmd,
      "satellite-schedule load FILE",
      "Satellite ISL link schedule management\n"
      "Load schedule from JSON file\n"
      "Path to schedule JSON file\n")
{
	int idx_file = 2;
	const char *path = argv[idx_file]->arg;
	int count;

	count = satellite_schedule_load_file(path);
	if (count < 0) {
		vty_out(vty, "%% Failed to load schedule from %s\n", path);
		return CMD_WARNING_CONFIG_FAILED;
	}

	vty_out(vty, "Loaded %d schedule entries from %s\n", count, path);
	return CMD_SUCCESS;
}

DEFUN(sat_sched_show,
      satellite_schedule_show_cmd,
      "satellite-schedule show",
      "Satellite ISL link schedule management\n"
      "Display current schedule table\n")
{
	satellite_schedule_show(vty);
	return CMD_SUCCESS;
}

DEFUN(sat_sched_clear,
      satellite_schedule_clear_cmd,
      "satellite-schedule clear",
      "Satellite ISL link schedule management\n"
      "Clear all pending schedule entries\n")
{
	satellite_schedule_clear();
	vty_out(vty, "Schedule cleared\n");
	return CMD_SUCCESS;
}

DEFUN(sat_sched_next,
      satellite_schedule_next_cmd,
      "satellite-schedule next",
      "Satellite ISL link schedule management\n"
      "Display the next pending schedule event\n")
{
	satellite_schedule_show_next(vty);
	return CMD_SUCCESS;
}

void isis_schedule_cli_init(void)
{
	install_element(ENABLE_NODE, &satellite_schedule_load_cmd);
	install_element(ENABLE_NODE, &satellite_schedule_show_cmd);
	install_element(ENABLE_NODE, &satellite_schedule_clear_cmd);
	install_element(ENABLE_NODE, &satellite_schedule_next_cmd);
}
