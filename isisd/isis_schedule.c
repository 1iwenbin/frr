/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 oaemu contributors
 *
 * IS-IS Link Schedule Engine (RFC 9717 §6)
 *
 * Implementation: JSON schedule table parsing, timer-driven metric
 * pre-adjustment, and CLI support.
 */

#include <zebra.h>

#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "json.h"
#include "thread.h"

#include "isisd/isis_schedule.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_spf.h"
#include "isisd/isisd.h"
#include "isisd/isis_misc.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_SCHEDULE_CTX, "ISIS Schedule Context");
DEFINE_MTYPE_STATIC(ISISD, ISIS_SCHEDULE_EVENT, "ISIS Schedule Event");

/* ── helpers ───────────────────────────────────────────────────────────── */

static const char *schedule_action_name(enum schedule_action action)
{
	switch (action) {
	case SCHED_ACTION_METRIC_HIGH:
		return "metric_high";
	case SCHED_ACTION_METRIC_RESTORE:
		return "metric_restore";
	case SCHED_ACTION_LINK_DOWN:
		return "link_down";
	case SCHED_ACTION_LINK_UP:
		return "link_up";
	case SCHED_ACTION_NODE_OVERLOAD:
		return "node_overload";
	case SCHED_ACTION_NODE_NORMAL:
		return "node_normal";
	default:
		return "unknown";
	}
}

static enum schedule_action schedule_action_from_str(const char *s)
{
	if (!strcmp(s, "metric_high"))
		return SCHED_ACTION_METRIC_HIGH;
	if (!strcmp(s, "metric_restore"))
		return SCHED_ACTION_METRIC_RESTORE;
	if (!strcmp(s, "link_down"))
		return SCHED_ACTION_LINK_DOWN;
	if (!strcmp(s, "link_up"))
		return SCHED_ACTION_LINK_UP;
	if (!strcmp(s, "node_overload"))
		return SCHED_ACTION_NODE_OVERLOAD;
	if (!strcmp(s, "node_normal"))
		return SCHED_ACTION_NODE_NORMAL;
	return -1;
}

/*
 * Find an IS-IS circuit by interface name within an area.
 */
static struct isis_circuit *schedule_find_circuit(struct isis_area *area,
						  const char *if_name)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (circuit->interface &&
		    strcmp(circuit->interface->name, if_name) == 0)
			return circuit;
	}
	return NULL;
}

/*
 * Insert event into list, sorted by trigger_time ascending.
 */
static void schedule_event_insert(struct schedule_event_list *head,
				  struct schedule_event *ev)
{
	struct schedule_event *cur;

	TAILQ_FOREACH(cur, head, entry) {
		if (ev->trigger_time < cur->trigger_time) {
			TAILQ_INSERT_BEFORE(cur, ev, entry);
			return;
		}
	}
	TAILQ_INSERT_TAIL(head, ev, entry);
}

/* ── timer callback ────────────────────────────────────────────────────── */

static void schedule_fire(struct thread *t);

static void schedule_arm_next(struct isis_schedule_ctx *ctx,
			      struct isis_area *area)
{
	struct schedule_event *ev;
	time_t now = time(NULL);
	long delay;

	if (!ctx || !ctx->loaded)
		return;

	/* Cancel any existing timer */
	THREAD_OFF(ctx->t_next);

	/* Find the next unexecuted event */
	TAILQ_FOREACH(ev, &ctx->events, entry) {
		if (!ev->executed)
			break;
	}

	if (!ev)
		return; /* all done */

	delay = ev->trigger_time - now;
	if (delay < 0)
		delay = 0;

	thread_add_timer(master, schedule_fire, area, delay, &ctx->t_next);

	zlog_info("ISIS-SCHED: armed next event id=%u (%s) in %ld sec",
		  ev->id, schedule_action_name(ev->action), delay);
}

/*
 * Execute all events whose trigger_time has arrived.
 */
static void schedule_fire(struct thread *t)
{
	struct isis_area *area = THREAD_ARG(t);
	struct isis_schedule_ctx *ctx;
	struct schedule_event *ev;
	struct isis_circuit *circuit;
	time_t now = time(NULL);
	int levels;
	int fired = 0;

	if (!area || !area->schedule || !area->schedule->loaded)
		return;

	ctx = area->schedule;

	TAILQ_FOREACH(ev, &ctx->events, entry) {
		if (ev->executed)
			continue;
		if (difftime(ev->trigger_time, now) > 0)
			break;

		ev->executed = true;
		fired++;

		switch (ev->action) {
		case SCHED_ACTION_METRIC_HIGH:
			circuit = schedule_find_circuit(area, ev->if_name);
			if (!circuit) {
				zlog_warn("ISIS-SCHED: [%u] metric_high: "
					  "interface %s not found in area %s",
					  ev->id, ev->if_name, area->area_tag);
				break;
			}
			levels = ev->level ? ev->level : (ISIS_LEVEL1 | ISIS_LEVEL2);
			for (int lvl = ISIS_LEVEL1; lvl <= ISIS_LEVEL2; lvl++) {
				if (!(levels & lvl))
					continue;
				zlog_info("ISIS-SCHED: [%u] metric_high %s "
					  "level-%d: %d -> %u",
					  ev->id, ev->if_name, lvl,
					  circuit->metric[lvl - 1], ev->metric);
				isis_circuit_metric_set(circuit, lvl,
							(int)ev->metric);
			}
			isis_spf_schedule(area, levels);
			break;

		case SCHED_ACTION_METRIC_RESTORE:
			circuit = schedule_find_circuit(area, ev->if_name);
			if (!circuit) {
				zlog_warn("ISIS-SCHED: [%u] metric_restore: "
					  "interface %s not found",
					  ev->id, ev->if_name);
				break;
			}
			levels = ev->level ? ev->level : (ISIS_LEVEL1 | ISIS_LEVEL2);
			for (int lvl = ISIS_LEVEL1; lvl <= ISIS_LEVEL2; lvl++) {
				if (!(levels & lvl))
					continue;
				int old_m = circuit->metric[lvl - 1];
				isis_circuit_metric_set(circuit, lvl,
							circuit->te_metric[lvl - 1]);
				zlog_info("ISIS-SCHED: [%u] metric_restore %s "
					  "level-%d: %d -> %u",
					  ev->id, ev->if_name, lvl, old_m,
					  circuit->te_metric[lvl - 1]);
			}
			isis_spf_schedule(area, levels);
			break;

		case SCHED_ACTION_LINK_DOWN:
			zlog_info("ISIS-SCHED: [%u] link_down %s — "
				  "ISL disconnect window begins",
				  ev->id, ev->if_name);
			break;

		case SCHED_ACTION_LINK_UP:
			zlog_info("ISIS-SCHED: [%u] link_up %s — "
				  "ISL reconnect window begins",
				  ev->id, ev->if_name);
			break;

		case SCHED_ACTION_NODE_OVERLOAD:
			zlog_info("ISIS-SCHED: [%u] node_overload", ev->id);
			isis_area_overload_bit_set(area, true);
			break;

		case SCHED_ACTION_NODE_NORMAL:
			zlog_info("ISIS-SCHED: [%u] node_normal", ev->id);
			isis_area_overload_bit_set(area, false);
			break;
		}
	}

	if (fired)
		zlog_info("ISIS-SCHED: executed %d event(s)", fired);

	/* Arm next */
	schedule_arm_next(ctx, area);
}

/* ── JSON parsing ──────────────────────────────────────────────────────── */

static int schedule_parse_json(struct isis_area *area, const char *filepath,
			       struct schedule_event_list *events)
{
	struct json_object *root, *arr, *entry_obj;
	struct json_object *id_obj, *time_obj, *action_obj;
	struct json_object *if_obj, *level_obj, *metric_obj;
	int arr_len;
	int count = 0;

	root = json_object_from_file(filepath);
	if (!root) {
		zlog_err("ISIS-SCHED: failed to parse JSON file: %s", filepath);
		return -1;
	}

	if (!json_object_object_get_ex(root, "schedule", &arr)) {
		zlog_err("ISIS-SCHED: missing 'schedule' array in %s", filepath);
		json_object_put(root);
		return -1;
	}

	arr_len = json_object_array_length(arr);

	for (int i = 0; i < arr_len; i++) {
		entry_obj = json_object_array_get_idx(arr, i);
		struct schedule_event *ev;
		const char *time_str;
		const char *action_str;
		struct tm tm;
		int action_int;

		ev = XCALLOC(MTYPE_ISIS_SCHEDULE_EVENT, sizeof(*ev));

		/* id (mandatory) */
		if (!json_object_object_get_ex(entry_obj, "id", &id_obj)) {
			zlog_err("ISIS-SCHED: event %d missing 'id'", i);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}
		ev->id = json_object_get_int(id_obj);

		/* time (mandatory) */
		if (!json_object_object_get_ex(entry_obj, "time", &time_obj)) {
			zlog_err("ISIS-SCHED: event %u missing 'time'", ev->id);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}
		time_str = json_object_get_string(time_obj);
		memset(&tm, 0, sizeof(tm));
		/* Parse ISO 8601: "2026-06-07T10:00:00Z" */
		if (strptime(time_str, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) {
			zlog_err("ISIS-SCHED: event %u bad time format: %s "
				 "(expected ISO 8601)", ev->id, time_str);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}
		ev->trigger_time = timegm(&tm);

		/* Validate time is in the future */
		if (difftime(ev->trigger_time, time(NULL)) <= 1) {
			zlog_err("ISIS-SCHED: event %u time is in the past", ev->id);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}

		/* action (mandatory) */
		if (!json_object_object_get_ex(entry_obj, "action", &action_obj)) {
			zlog_err("ISIS-SCHED: event %u missing 'action'", ev->id);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}
		action_str = json_object_get_string(action_obj);
		action_int = schedule_action_from_str(action_str);
		if (action_int < 0) {
			zlog_err("ISIS-SCHED: event %u unknown action: %s",
				 ev->id, action_str);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}
		ev->action = (enum schedule_action)action_int;

		/* interface (mandatory for most actions) */
		if (json_object_object_get_ex(entry_obj, "interface", &if_obj))
			strlcpy(ev->if_name, json_object_get_string(if_obj),
				sizeof(ev->if_name));
		else if (ev->action != SCHED_ACTION_NODE_OVERLOAD &&
			 ev->action != SCHED_ACTION_NODE_NORMAL) {
			zlog_err("ISIS-SCHED: event %u missing 'interface'",
				 ev->id);
			XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
			json_object_put(root);
			return -1;
		}

		/* Verify interface exists (warn only) */
		if (ev->if_name[0]) {
			struct isis_circuit *c = schedule_find_circuit(area, ev->if_name);
			if (!c)
				zlog_warn("ISIS-SCHED: event %u: interface %s "
					  "not yet active in area %s "
					  "(will be resolved at fire time)",
					  ev->id, ev->if_name, area->area_tag);
		}

		/* level (optional) */
		ev->level = 0; /* default: both */
		if (json_object_object_get_ex(entry_obj, "level", &level_obj)) {
			int lvl = json_object_get_int(level_obj);
			if (lvl == 1)
				ev->level = ISIS_LEVEL1;
			else if (lvl == 2)
				ev->level = ISIS_LEVEL2;
		}

		/* metric (required for metric_high) */
		if (ev->action == SCHED_ACTION_METRIC_HIGH) {
			if (!json_object_object_get_ex(entry_obj, "metric",
						       &metric_obj)) {
				zlog_err("ISIS-SCHED: event %u metric_high "
					 "missing 'metric'", ev->id);
				XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
				json_object_put(root);
				return -1;
			}
			ev->metric = json_object_get_int(metric_obj);
		}

		schedule_event_insert(events, ev);
		count++;
	}

	json_object_put(root);

	if (count == 0) {
		zlog_err("ISIS-SCHED: no valid events in %s", filepath);
		return -1;
	}

	zlog_info("ISIS-SCHED: loaded %d event(s) from %s", count, filepath);
	return count;
}

/* ── public API ────────────────────────────────────────────────────────── */

struct isis_schedule_ctx *isis_schedule_ctx_new(void)
{
	struct isis_schedule_ctx *ctx;

	ctx = XCALLOC(MTYPE_ISIS_SCHEDULE_CTX, sizeof(*ctx));
	TAILQ_INIT(&ctx->events);
	ctx->loaded = false;
	return ctx;
}

void isis_schedule_ctx_free(struct isis_schedule_ctx *ctx)
{
	struct schedule_event *ev, *tmp;

	if (!ctx)
		return;

	THREAD_OFF(ctx->t_next);

	TAILQ_FOREACH_SAFE(ev, &ctx->events, entry, tmp) {
		TAILQ_REMOVE(&ctx->events, ev, entry);
		XFREE(MTYPE_ISIS_SCHEDULE_EVENT, ev);
	}

	XFREE(MTYPE_ISIS_SCHEDULE_CTX, ctx->source_path);
	XFREE(MTYPE_ISIS_SCHEDULE_CTX, ctx);
}

int isis_schedule_load(struct isis_area *area, const char *filepath)
{
	struct isis_schedule_ctx *ctx;
	int n;

	if (!area || !filepath)
		return -1;

	/* Clear previous schedule */
	if (area->schedule) {
		isis_schedule_ctx_free(area->schedule);
		area->schedule = NULL;
	}

	ctx = isis_schedule_ctx_new();

	n = schedule_parse_json(area, filepath, &ctx->events);
	if (n < 0) {
		isis_schedule_ctx_free(ctx);
		/* area->schedule stays NULL — no dangling pointer */
		return -1;
	}

	ctx->source_path = XSTRDUP(MTYPE_ISIS_SCHEDULE_CTX, filepath);
	ctx->loaded = true;
	area->schedule = ctx;

	/* Arm first timer */
	schedule_arm_next(ctx, area);

	return CMD_SUCCESS;
}

void isis_schedule_clear(struct isis_area *area)
{
	if (!area || !area->schedule)
		return;

	zlog_info("ISIS-SCHED: clearing schedule (was: %s)",
		  area->schedule->source_path);

	isis_schedule_ctx_free(area->schedule);
	area->schedule = NULL;
}

void isis_schedule_show(struct vty *vty, struct isis_area *area)
{
	struct isis_schedule_ctx *ctx;
	struct schedule_event *ev;
	char time_buf[32];
	int pending = 0, done = 0;

	if (!area || !area->schedule || !area->schedule->loaded) {
		vty_out(vty, "Link Schedule: not loaded\n");
		return;
	}

	ctx = area->schedule;

	TAILQ_FOREACH(ev, &ctx->events, entry) {
		if (ev->executed)
			done++;
		else
			pending++;
	}

	vty_out(vty, "Link Schedule: loaded (%d events, %d pending, %d done)\n",
		done + pending, pending, done);
	vty_out(vty, "  Source: %s\n", ctx->source_path);
	vty_out(vty, "  Events:\n");

	TAILQ_FOREACH(ev, &ctx->events, entry) {
		struct tm *gmt;

		gmt = gmtime(&ev->trigger_time);
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmt);

		vty_out(vty, "    %-4u %-26s %-16s %-12s %s\n",
			ev->id, time_buf,
			schedule_action_name(ev->action),
			ev->if_name[0] ? ev->if_name : "(global)",
			ev->executed ? "done" : "pending");
	}
}
