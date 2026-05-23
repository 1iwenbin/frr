// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Satellite ISL Link Schedule Engine — implementation
 *
 * Copyright (C) 2026 oaemu
 */

#include <zebra.h>

#include "satellite_schedule.h"
#include "json.h"
#include "frrevent.h"
#include "memory.h"
#include "vty.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, SATELLITE_SCHED_ENTRY, "Satellite Schedule Entry");

/* Global action callback — set by isisd during initialization */
satellite_schedule_action_cb schedule_action_hook;

/* Sorted linked list (ascending by execute_time) — simple priority queue */
static struct schedule_entry *schedule_list;

/* Timer for the next event */
static struct event *t_schedule_timer;

/* Pointer to the FRR event loop */
static struct event_loop *schedule_master;

/* Forward declarations */
static void satellite_schedule_timer(struct event *thread);

/* ───────────────────────────────────────────────────────────
 *  Time comparison helper
 * ─────────────────────────────────────────────────────────── */

static int timespec_cmp(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec < b->tv_sec)
		return -1;
	if (a->tv_sec > b->tv_sec)
		return 1;
	if (a->tv_nsec < b->tv_nsec)
		return -1;
	if (a->tv_nsec > b->tv_nsec)
		return 1;
	return 0;
}

static long timespec_diff_ms(const struct timespec *future,
			     const struct timespec *now)
{
	long diff;

	diff = (future->tv_sec - now->tv_sec) * 1000L;
	diff += (future->tv_nsec - now->tv_nsec) / 1000000L;
	return diff > 0 ? diff : 0;
}

/* ───────────────────────────────────────────────────────────
 *  Schedule list management (insertion-sorted by execute_time)
 * ─────────────────────────────────────────────────────────── */

static void satellite_schedule_insert(struct schedule_entry *entry)
{
	struct schedule_entry **pp = &schedule_list;

	while (*pp && timespec_cmp(&(*pp)->execute_time, &entry->execute_time) < 0)
		pp = &(*pp)->next;

	entry->next = *pp;
	*pp = entry;
}

static struct schedule_entry *satellite_schedule_pop(void)
{
	struct schedule_entry *e = schedule_list;
	if (e)
		schedule_list = e->next;
	return e;
}

/* ───────────────────────────────────────────────────────────
 *  Action execution
 * ─────────────────────────────────────────────────────────── */

static void satellite_schedule_apply(struct schedule_entry *entry)
{
	const char *action_str;

	switch (entry->action) {
	case SCHEDULE_ACTION_METRIC_HIGH:
		action_str = "METRIC_HIGH";
		break;
	case SCHEDULE_ACTION_METRIC_RESTORE:
		action_str = "METRIC_RESTORE";
		break;
	case SCHEDULE_ACTION_LINK_DOWN:
		action_str = "LINK_DOWN";
		break;
	case SCHEDULE_ACTION_LINK_UP:
		action_str = "LINK_UP";
		break;
	case SCHEDULE_ACTION_NODE_OVERLOAD:
		action_str = "NODE_OVERLOAD";
		break;
	case SCHEDULE_ACTION_NODE_NORMAL:
		action_str = "NODE_NORMAL";
		break;
	case SCHEDULE_ACTION_NONE:
		action_str = "NONE";
		break;
	default:
		action_str = "UNKNOWN";
		break;
	}

	zlog_info("Satellite-Schedule: executing id=%" PRIu64 " action=%s if=%s metric=%u",
		  entry->id, action_str, entry->interface, entry->metric_value);

	/* Call the daemon-registered callback for IS-IS specific actions */
	if (schedule_action_hook)
		schedule_action_hook(entry);
}

/* ───────────────────────────────────────────────────────────
 *  Timer callback: execute all due entries, reschedule
 * ─────────────────────────────────────────────────────────── */

static void satellite_schedule_timer(struct event *thread)
{
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	/* Execute all entries whose time has come */
	while (schedule_list &&
	       timespec_cmp(&schedule_list->execute_time, &now) <= 0) {
		struct schedule_entry *e = satellite_schedule_pop();
		satellite_schedule_apply(e);
		XFREE(MTYPE_SATELLITE_SCHED_ENTRY, e);
	}

	/* Schedule next timer if entries remain */
	if (schedule_list) {
		long delay_ms = timespec_diff_ms(&schedule_list->execute_time, &now);
		event_add_timer_msec(schedule_master,
				     satellite_schedule_timer, NULL,
				     delay_ms, &t_schedule_timer);
	}
}

/* ───────────────────────────────────────────────────────────
 *  JSON parsing
 * ─────────────────────────────────────────────────────────── */

static enum schedule_action parse_action(const char *action_str)
{
	if (!strcmp(action_str, "metric_high"))
		return SCHEDULE_ACTION_METRIC_HIGH;
	if (!strcmp(action_str, "metric_restore"))
		return SCHEDULE_ACTION_METRIC_RESTORE;
	if (!strcmp(action_str, "link_down"))
		return SCHEDULE_ACTION_LINK_DOWN;
	if (!strcmp(action_str, "link_up"))
		return SCHEDULE_ACTION_LINK_UP;
	if (!strcmp(action_str, "node_overload"))
		return SCHEDULE_ACTION_NODE_OVERLOAD;
	if (!strcmp(action_str, "node_normal"))
		return SCHEDULE_ACTION_NODE_NORMAL;
	return SCHEDULE_ACTION_NONE;
}

static bool parse_iso8601_time(const char *time_str, struct timespec *ts)
{
	struct tm tm = {};
	char *dot;

	/* Parse ISO 8601: "2026-05-24T00:05:00Z" or "2026-05-24T00:05:00.123Z" */
	dot = strptime(time_str, "%Y-%m-%dT%H:%M:%S", &tm);
	if (!dot)
		return false;

	/* Convert to time_t (UTC), then to timespec */
	ts->tv_sec = timegm(&tm);
	ts->tv_nsec = 0;

	/* Handle fractional seconds if present */
	if (*dot == '.') {
		char *end;
		long frac = strtol(dot + 1, &end, 10);
		if (end > dot + 1)
			ts->tv_nsec = frac;
	}

	return true;
}

int satellite_schedule_load_json(const char *json_str)
{
	struct json_object *root, *schedule_array, *entry_obj;
	int count = 0;

	root = json_tokener_parse(json_str);
	if (!root) {
		zlog_err("Satellite-Schedule: failed to parse JSON");
		return -1;
	}

	if (!json_object_object_get_ex(root, "schedule", &schedule_array)) {
		zlog_err("Satellite-Schedule: missing 'schedule' array in JSON");
		json_object_free(root);
		return -1;
	}

	int len = json_object_array_length(schedule_array);
	for (int i = 0; i < len; i++) {
		entry_obj = json_object_array_get_idx(schedule_array, i);

		struct schedule_entry *e = XCALLOC(MTYPE_SATELLITE_SCHED_ENTRY,
						   sizeof(*e));

		/* id */
		struct json_object *val;
		if (json_object_object_get_ex(entry_obj, "id", &val))
			e->id = json_object_get_int64(val);

		/* time */
		if (json_object_object_get_ex(entry_obj, "time", &val)) {
			const char *time_str = json_object_get_string(val);
			if (!parse_iso8601_time(time_str, &e->execute_time)) {
				zlog_err("Satellite-Schedule: invalid time '%s' in entry id=%" PRIu64,
					 time_str, e->id);
				XFREE(MTYPE_SATELLITE_SCHED_ENTRY, e);
				continue;
			}
		}

		/* action */
		if (json_object_object_get_ex(entry_obj, "action", &val)) {
			e->action = parse_action(json_object_get_string(val));
			if (e->action == SCHEDULE_ACTION_NONE) {
				zlog_err("Satellite-Schedule: unknown action '%s' in entry id=%" PRIu64,
					 json_object_get_string(val), e->id);
				XFREE(MTYPE_SATELLITE_SCHED_ENTRY, e);
				continue;
			}
		}

		/* interface */
		if (json_object_object_get_ex(entry_obj, "interface", &val))
			strlcpy(e->interface, json_object_get_string(val),
				IFNAMSIZ);

		/* metric (optional, for metric_high) */
		if (json_object_object_get_ex(entry_obj, "metric", &val))
			e->metric_value = json_object_get_int(val);

		satellite_schedule_insert(e);
		count++;
	}

	json_object_free(root);

	zlog_info("Satellite-Schedule: loaded %d entries", count);

	/* Kick the timer */
	if (schedule_master && schedule_list) {
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		long delay_ms = timespec_diff_ms(&schedule_list->execute_time, &now);
		if (t_schedule_timer)
			event_cancel(&t_schedule_timer);
		event_add_timer_msec(schedule_master,
				     satellite_schedule_timer, NULL,
				     delay_ms, &t_schedule_timer);
	}

	return count;
}

int satellite_schedule_load_file(const char *path)
{
	FILE *fp;
	long fsize;
	char *json_str;
	int ret;

	fp = fopen(path, "r");
	if (!fp) {
		zlog_err("Satellite-Schedule: cannot open file '%s': %s",
			 path, strerror(errno));
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);

	json_str = XMALLOC(MTYPE_TMP, fsize + 1);
	if (fread(json_str, 1, fsize, fp) != (size_t)fsize) {
		zlog_err("Satellite-Schedule: failed to read file '%s'", path);
		XFREE(MTYPE_TMP, json_str);
		fclose(fp);
		return -1;
	}
	json_str[fsize] = '\0';
	fclose(fp);

	ret = satellite_schedule_load_json(json_str);
	XFREE(MTYPE_TMP, json_str);
	return ret;
}

/* ───────────────────────────────────────────────────────────
 *  Lifecycle
 * ─────────────────────────────────────────────────────────── */

void satellite_schedule_init(struct event_loop *master)
{
	schedule_master = master;
}

void satellite_schedule_clear(void)
{
	struct schedule_entry *e;

	event_cancel(&t_schedule_timer);

	while ((e = satellite_schedule_pop()))
		XFREE(MTYPE_SATELLITE_SCHED_ENTRY, e);

	schedule_list = NULL;
}

/* ───────────────────────────────────────────────────────────
 *  Display
 * ─────────────────────────────────────────────────────────── */

static const char *action_to_str(enum schedule_action action)
{
	switch (action) {
	case SCHEDULE_ACTION_METRIC_HIGH:
		return "metric_high";
	case SCHEDULE_ACTION_METRIC_RESTORE:
		return "metric_restore";
	case SCHEDULE_ACTION_LINK_DOWN:
		return "link_down";
	case SCHEDULE_ACTION_LINK_UP:
		return "link_up";
	case SCHEDULE_ACTION_NODE_OVERLOAD:
		return "node_overload";
	case SCHEDULE_ACTION_NODE_NORMAL:
		return "node_normal";
	case SCHEDULE_ACTION_NONE:
		return "none";
	default:
		return "unknown";
	}
}

void satellite_schedule_show(struct vty *vty)
{
	struct schedule_entry *e;
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	if (!schedule_list) {
		vty_out(vty, "%% No scheduled events\n");
		return;
	}

	vty_out(vty, "Satellite ISL Schedule:\n");
	vty_out(vty, "%-8s %-20s %-16s %-16s %s\n",
		"ID", "Time", "Action", "Interface", "Metric");

	for (e = schedule_list; e; e = e->next) {
		char time_buf[32];
		long remain_s = e->execute_time.tv_sec - now.tv_sec;
		struct tm tm;
		time_t t = e->execute_time.tv_sec;

		gmtime_r(&t, &tm);
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm);

		vty_out(vty, "%-8" PRIu64 " %-20s %-16s %-16s",
			e->id, time_buf, action_to_str(e->action), e->interface);

		if (e->action == SCHEDULE_ACTION_METRIC_HIGH)
			vty_out(vty, " %u", e->metric_value);
		else
			vty_out(vty, " %s", "-");

		if (remain_s >= 0)
			vty_out(vty, "  (T+%lds)", remain_s);
		else
			vty_out(vty, "  (overdue)");

		vty_out(vty, "\n");
	}
}

void satellite_schedule_show_next(struct vty *vty)
{
	struct timespec now;

	if (!schedule_list) {
		vty_out(vty, "%% No scheduled events\n");
		return;
	}

	clock_gettime(CLOCK_REALTIME, &now);

	struct schedule_entry *e = schedule_list;
	char time_buf[32];
	struct tm tm;
	time_t t = e->execute_time.tv_sec;

	gmtime_r(&t, &tm);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm);

	long remain_s = e->execute_time.tv_sec - now.tv_sec;

	vty_out(vty, "Next event:\n");
	vty_out(vty, "  ID:        %" PRIu64 "\n", e->id);
	vty_out(vty, "  Time:      %s", time_buf);
	if (remain_s >= 0)
		vty_out(vty, " (in %ld seconds)\n", remain_s);
	else
		vty_out(vty, " (overdue)\n");
	vty_out(vty, "  Action:    %s\n", action_to_str(e->action));
	vty_out(vty, "  Interface: %s\n", e->interface);
	if (e->action == SCHEDULE_ACTION_METRIC_HIGH)
		vty_out(vty, "  Metric:    %u\n", e->metric_value);
}
