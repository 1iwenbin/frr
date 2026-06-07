/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 oaemu contributors
 *
 * IS-IS Link Schedule Engine (RFC 9717 §6)
 *
 * Loads a JSON schedule table and executes metric adjustments
 * at predetermined times, enabling zero-packet-loss ISL handovers.
 */

#ifndef ISIS_SCHEDULE_H
#define ISIS_SCHEDULE_H

#include "lib/thread.h"

/* Forward declarations */
struct isis_area;
struct vty;

/* Schedule actions */
enum schedule_action {
	SCHED_ACTION_METRIC_HIGH = 1,
	SCHED_ACTION_METRIC_RESTORE,
	SCHED_ACTION_LINK_DOWN,
	SCHED_ACTION_LINK_UP,
	SCHED_ACTION_NODE_OVERLOAD,
	SCHED_ACTION_NODE_NORMAL,
};

/* A single schedule event */
struct schedule_event {
	TAILQ_ENTRY(schedule_event) entry; /* linked list */
	uint32_t id;			   /* event ID */
	time_t trigger_time;		   /* UTC unix timestamp */
	enum schedule_action action;	   /* what to do */
	char if_name[IFNAMSIZ];		   /* target interface, if applicable */
	int level;			   /* ISIS_LEVEL_1, ISIS_LEVEL_2, or both */
	uint32_t metric;		   /* target metric for metric_high */
	bool executed;			   /* already fired? */
};

TAILQ_HEAD(schedule_event_list, schedule_event);

/* Per-area schedule context */
struct isis_schedule_ctx {
	struct schedule_event_list events; /* sorted by trigger_time */
	struct thread *t_next;		   /* timer for next event */
	char *source_path;		   /* path of loaded JSON file */
	bool loaded;
};

/* Lifecycle */
extern struct isis_schedule_ctx *isis_schedule_ctx_new(void);
extern void isis_schedule_ctx_free(struct isis_schedule_ctx *ctx);

/* Load / clear */
extern int isis_schedule_load(struct isis_area *area, const char *filepath);
extern void isis_schedule_clear(struct isis_area *area);

/* Show */
extern void isis_schedule_show(struct vty *vty, struct isis_area *area);

#endif /* ISIS_SCHEDULE_H */
