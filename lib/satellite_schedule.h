// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Satellite ISL Link Schedule Engine
 * Implements RFC 9717 time-based link scheduling for predictable
 * Inter-Satellite Link (ISL) connectivity changes.
 *
 * Copyright (C) 2026 oaemu
 */

#ifndef _SATELLITE_SCHEDULE_H
#define _SATELLITE_SCHEDULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <net/if.h>

struct event_loop;
struct vty;

/* Schedule action types */
enum schedule_action {
	SCHEDULE_ACTION_NONE = 0,
	SCHEDULE_ACTION_METRIC_HIGH = 1,    /* Pre-set metric high before link down */
	SCHEDULE_ACTION_METRIC_RESTORE = 2, /* Restore original metric after link up */
	SCHEDULE_ACTION_LINK_DOWN = 3,      /* Link going down (platform executes) */
	SCHEDULE_ACTION_LINK_UP = 4,        /* Link coming up (platform executes) */
	SCHEDULE_ACTION_NODE_OVERLOAD = 5,  /* Set overload bit (RFC 9717) */
	SCHEDULE_ACTION_NODE_NORMAL = 6,    /* Clear overload bit */
};

/* Single schedule entry */
struct schedule_entry {
	uint64_t id;
	enum schedule_action action;
	char interface[IFNAMSIZ];        /* Target interface name */
	uint32_t metric_value;           /* Metric value for METRIC_HIGH */
	struct timespec execute_time;    /* Absolute wall-clock execution time */
	struct schedule_entry *next;
};

/*
 * Callback type for applying schedule actions.
 * The schedule engine calls this when an entry's execution time arrives.
 * The callback is responsible for performing the actual action
 * (metric adjustment, etc.). Set by the daemon during initialization.
 */
typedef void (*satellite_schedule_action_cb)(struct schedule_entry *entry);

/* Global callback — set by isisd during init */
extern satellite_schedule_action_cb schedule_action_hook;

/* Load schedule from JSON string */
int satellite_schedule_load_json(const char *json_str);

/* Load schedule from JSON file */
int satellite_schedule_load_file(const char *path);

/* Initialize the schedule engine with the FRR event loop */
void satellite_schedule_init(struct event_loop *master);

/* Clear all pending schedule entries */
void satellite_schedule_clear(void);

/* Display current schedule table */
void satellite_schedule_show(struct vty *vty);

/* Display the next pending event */
void satellite_schedule_show_next(struct vty *vty);

/* Register CLI commands */
void satellite_schedule_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _SATELLITE_SCHEDULE_H */
