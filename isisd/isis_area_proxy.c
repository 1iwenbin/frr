/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 oaemu contributors
 *
 * IS-IS Area Proxy (RFC 9666) — configuration management
 */

/* oaemu: strict compiler checks — catch BUG-010 class errors at build time */
#pragma GCC diagnostic error "-Wjump-misses-init"
#pragma GCC diagnostic error "-Wuninitialized"
#pragma GCC diagnostic error "-Wreturn-type"

#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "log.h"
#include "hash.h"

#include "isisd/isisd.h"
#include "isisd/isis_area_proxy.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_AREA_PROXY_PREFIX_AGG, "ISIS Area Proxy Prefix Agg");
DEFINE_MTYPE_STATIC(ISISD, ISIS_AREA_PROXY_SYSID_SET, "ISIS Area Proxy SysID Set");
DEFINE_MTYPE_STATIC(ISISD, ISIS_AREA_PROXY_MIGRATE_CTX, "ISIS Area Proxy Migrate Ctx");

/* 8.4 compatibility macros for deprecated 10.7 list APIs */
#define iso_address_list_first(al) ((al) && listhead(*(al)))

/* Result of a leader election computation. */
struct area_proxy_election_result {
	uint8_t winner_sysid[ISIS_SYS_ID_LEN];
	uint8_t winner_priority;
	bool valid;   /* false → no candidates found */
};

/* ── Forward declarations ── */
static bool am_i_leader(struct isis_area *area);
static bool isis_area_proxy_ready(struct isis_area *area);
void isis_area_proxy_lsp_purge(struct isis_area *area);
static void isis_area_proxy_reconcile_cb(struct thread *t);
static bool area_proxy_lsp_fragment_valid(struct isis_lsp *lsp);
static struct area_proxy_election_result
area_proxy_election_compute(struct isis_area *area);

/*
 * Check if a proxy-sysid buffer is all-zero (not configured).
 * Used by set_sysid, no proxy-sysid CLI, and lsp_generate.
 */
bool isis_area_proxy_sysid_is_zero(const uint8_t *sysid)
{
	for (int i = 0; i < ISIS_SYS_ID_LEN; i++)
		if (sysid[i] != 0)
			return false;
	return true;
}

void isis_area_proxy_enable(struct isis_area *area)
{
	if (!area || area->area_proxy_enabled)
		return;

	area->area_proxy_enabled = true;
	area->proxy_lsp_dirty = true;  /* trigger initial generation */
	area->ap_pending_reasons = 0;
	area->ap_reconcile_running = false;
	area->proxy_lsp_settle_until = monotime(NULL) + area->proxy_lsp_settle_sec;
	THREAD_OFF(area->t_area_proxy_reconcile);

	zlog_info("Area Proxy: enabled on area %s (proxy-sysid: %pSY)",
		  area->area_tag, area->area_proxy_sysid);

	/*
	 * Phase 5: Mark boundary circuits.  During startup there are no
	 * adjacencies yet, so we rely on circuit type: L2-only circuits
	 * on L1L2 routers are assumed to be cross-area boundaries.
	 * The regeneration timer re-evaluates once L1 LSDB converges.
	 */
	{
		struct isis_circuit *circuit;
		struct listnode *cnode;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			/* L2-only circuits are cross-area boundaries.
			 * We do NOT gate on area->is_type here —
			 * during config load it may not be set yet.
			 * The timer re-evaluates and unmarks false positives. */
			if (circuit->is_type == IS_LEVEL_2) {
				circuit->is_area_proxy_boundary = true;
				zlog_info("Area Proxy: circuit %s marked as boundary (L2-only)",
					  circuit->interface->name);
				continue;
			}
			/* Also check existing L2 adjacencies for Outside neighbors */
			if ((circuit->is_type & IS_LEVEL_2) == 0)
				continue;
			struct listnode *node;
			struct isis_adjacency *adj;
			int lvl = ISIS_LEVEL2 - 1;
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (ALL_LIST_ELEMENTS_RO(
					     circuit->u.bc.adjdb[lvl],
					     node, adj)) {
					if (adj->adj_state == ISIS_ADJ_UP
					    && !isis_sysid_in_l1_lsdb(
						    area, adj->sysid)) {
						circuit->is_area_proxy_boundary = true;
						zlog_info("Area Proxy: circuit %s boundary (neighbor %pSY)",
							  circuit->interface->name, adj->sysid);
						break;
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor
				   && circuit->u.p2p.neighbor->adj_state == ISIS_ADJ_UP
				   && !isis_sysid_in_l1_lsdb(
					   area, circuit->u.p2p.neighbor->sysid)) {
				circuit->is_area_proxy_boundary = true;
				zlog_info("Area Proxy: circuit %s boundary (neighbor %pSY)",
					  circuit->interface->name,
					  circuit->u.p2p.neighbor->sysid);
			}
		}
	}

	/*
	 * Phase 5: Re-flood all L2 LSPs — handled in isis_adjacency.c
	 * when the first boundary circuit is detected.
	 */

	/* Schedule initial reconcile — with startup settle window.
	 * Reconciler defers all work until settle expires + jitter. */
	isis_area_proxy_schedule_reconcile(area, AP_REASON_INITIAL);

	/* L2 LSP regeneration (for Type 20 TLV) is deferred to
	 * set_sysid() — called after proxy-sysid is configured. */
}

void isis_area_proxy_disable(struct isis_area *area)
{
	if (!area)
		return;

	/* Re-entrancy: if already disabled, true no-op. */
	if (!area->area_proxy_enabled)
		return;

	area->area_proxy_enabled = false;

	/* Purge Proxy LSP BEFORE clearing sysid.
	 * isis_area_proxy_lsp_purge() reads area->area_proxy_sysid
	 * to locate the LSPs — sysid must still be the old value.
	 * The purge function itself checks own_lsp, so it is safe
	 * for GS (never originated Proxy LSPs) and non-GS alike. */
	isis_area_proxy_lsp_purge(area);

	memset(area->area_proxy_sysid, 0, ISIS_SYS_ID_LEN);
	area->area_proxy_sid = 0;
	area->proxy_lsp_dirty = false;
	area->ap_pending_reasons = 0;

	/* Cancel pending timers. */
	THREAD_OFF(area->t_area_proxy_reconcile);

	zlog_info("Area Proxy: disabled on area %s", area->area_tag);

	/* Regenerate L2 LSP to remove Type 20 Area Proxy TLV.
	 * Use lsp_regenerate_schedule() — the standard FRR path
	 * that handles sequence-number / fragment / flooding. */
	lsp_regenerate_schedule(area, ISIS_LEVEL2, 0);
}

bool isis_area_proxy_is_enabled(const struct isis_area *area)
{
	return area ? area->area_proxy_enabled : false;
}

const uint8_t *isis_area_proxy_get_sysid(const struct isis_area *area)
{
	if (!area || !area->area_proxy_enabled)
		return NULL;
	return area->area_proxy_sysid;
}

/* Forward declarations for static functions used by show */
static bool am_i_leader(struct isis_area *area);
static bool isis_area_proxy_ready(struct isis_area *area);

void isis_area_proxy_show(struct vty *vty, struct isis_area *area)
{
	if (!area) {
		vty_out(vty, "No IS-IS instance configured\n");
		return;
	}

	vty_out(vty, "Area Proxy (RFC 9666): %s\n",
		area->area_proxy_enabled ? "Enabled" : "Disabled");

	if (area->area_proxy_enabled) {
		vty_out(vty, "  Proxy System ID: %02x%02x.%02x%02x.%02x%02x\n",
			area->area_proxy_sysid[0], area->area_proxy_sysid[1],
			area->area_proxy_sysid[2], area->area_proxy_sysid[3],
			area->area_proxy_sysid[4], area->area_proxy_sysid[5]);
		if (area->area_proxy_sid) {
			vty_out(vty, "  Area SID: %u (%s)\n",
				area->area_proxy_sid,
				(area->area_sid_type == SR_SID_VALUE_TYPE_ABSOLUTE)
					? "absolute" : "index");
		}

		/* Mode */
		if (area->area_proxy_leader_election) {
			vty_out(vty, "  Mode: leader-election\n");
			bool i_am = am_i_leader(area);
			/* Verify fragment 0 is actually in LSDB, not just
			 * area->proxy_lsp pointer (may be stale after
			 * external purge).  Use lsp_search() directly;
			 * the pointer comparison is unsafe (dangling). */
			bool has_proxy = false;
			if (area->proxy_lsp[ISIS_LEVEL2 - 1]) {
				uint8_t fid[ISIS_SYS_ID_LEN + 2];
				memcpy(fid, area->area_proxy_sysid,
				       ISIS_SYS_ID_LEN);
				fid[ISIS_SYS_ID_LEN] = 0;
				struct isis_lsp *flsp = lsp_search(
					&area->lspdb[ISIS_LEVEL2 - 1], fid);
				has_proxy = (flsp != NULL &&
					     area_proxy_lsp_fragment_valid(flsp));
			}
			vty_out(vty, "  Role: %s\n", i_am ? "LEADER" : "FOLLOWER");
			vty_out(vty, "  Priority: %u\n", area->area_proxy_leader_priority);
			vty_out(vty, "  Election check interval: %us\n",
				area->area_proxy_elect_check_sec ? area->area_proxy_elect_check_sec : 30);
			if (has_proxy)
				vty_out(vty, "  Proxy LSP: present (self-generated)\n");
			else
				vty_out(vty, "  Proxy LSP: not generated (ready/debounce pending)\n");
		} else if (area->area_proxy_leader_priority == 0 &&
			   area->area_proxy_elect_check_sec == 0) {
			vty_out(vty, "  Mode: distributed (no leader-election)\n");
			if (area->proxy_lsp[ISIS_LEVEL2 - 1])
				vty_out(vty, "  Proxy LSP: present (self-generated)\n");
			else
				vty_out(vty, "  Proxy LSP: not generated\n");
		} else {
			vty_out(vty, "  Mode: unset\n");
			vty_out(vty, "  Proxy LSP: not generated\n");
		}

		vty_out(vty, "  SPF runs: L1=%llu L2=%llu\n",
			area->spf_run_count[0], area->spf_run_count[1]);

		/* ── Remote Area SIDs (RFC 9666 §4.3.2) ── */
		{
			struct isis_lsp *lsp;
			int remote_count = 0;

			vty_out(vty, "  Remote Area SIDs:\n");
			frr_each (lspdb, &area->lspdb[ISIS_LEVEL2 - 1], lsp) {
				if (!isis_lsp_is_proxy_lsp(lsp))
					continue;
				if (memcmp(lsp->hdr.lsp_id,
					   area->area_proxy_sysid,
					   ISIS_SYS_ID_LEN) == 0)
					continue; /* skip own Proxy LSP */
				if (!lsp->tlvs ||
				    !lsp->tlvs->area_proxy ||
				    !lsp->tlvs->area_proxy->has_area_sid)
					continue;

				struct isis_area_proxy_tlv *ap =
					lsp->tlvs->area_proxy;
				vty_out(vty,
					"    %pSY: SID=%u flags=0x%02x algo=%u\n",
					ap->proxy_sysid,
					ap->area_sid_value,
					ap->area_sid_flags,
					ap->area_sid_algo);
				remote_count++;
			}
			if (remote_count == 0)
				vty_out(vty, "    (none)\n");
		}
	}
}

/*
 * Show leader election details: all candidates from L2 LSDB,
 * their priorities, reachability, and the computed leader.
 */
void isis_area_proxy_show_election(struct vty *vty, struct isis_area *area)
{
	struct isis_lsp *lsp;

	if (!area || !area->area_proxy_enabled) {
		vty_out(vty, "Area Proxy not enabled\n");
		return;
	}
	if (!area->area_proxy_leader_election) {
		vty_out(vty, "Leader election not enabled (distributed mode)\n");
		return;
	}

	vty_out(vty, "Area Leader Election for Area (proxy-sysid: %02x%02x.%02x%02x.%02x%02x)\n\n",
		area->area_proxy_sysid[0], area->area_proxy_sysid[1],
		area->area_proxy_sysid[2], area->area_proxy_sysid[3],
		area->area_proxy_sysid[4], area->area_proxy_sysid[5]);

	vty_out(vty, "%-20s %-10s %-10s %-12s %s\n",
		"Candidate", "Priority", "Reachable", "Ready", "Notes");
	vty_out(vty, "%-20s %-10s %-10s %-12s %s\n",
		"--------------------", "----------", "----------", "------------", "-----");

	bool ready = isis_area_proxy_ready(area);
	int candidates = 0;

	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		char name[21];
		uint8_t priority = 0;
		bool reachable = false;
		bool is_own = false;

		if (isis_lsp_is_proxy_lsp(lsp))
			continue;
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;

		snprintf(name, sizeof(name), "%02x%02x.%02x%02x.%02x%02x",
			 lsp->hdr.lsp_id[0], lsp->hdr.lsp_id[1],
			 lsp->hdr.lsp_id[2], lsp->hdr.lsp_id[3],
			 lsp->hdr.lsp_id[4], lsp->hdr.lsp_id[5]);

		is_own = (memcmp(lsp->hdr.lsp_id, area->isis->sysid,
				 ISIS_SYS_ID_LEN) == 0);

		/* Read Type 27 priority: self uses local config, remote from LSP */
		if (is_own)
			priority = area->area_proxy_leader_priority;
		else if (lsp->tlvs && lsp->tlvs->router_cap)
			priority = lsp->tlvs->router_cap->area_leader_priority;

		/* Check L1 reachability */
		if (is_own) {
			reachable = true;
		} else {
			reachable = isis_spf_sysid_reachable(area, lsp->hdr.lsp_id);
		}

		if (priority == 0 && !is_own)
			continue;

		candidates++;

		const char *ready_str = "N/A";
		if (reachable && priority > 0) {
			ready_str = ready ? "Yes" : "No";
		} else if (reachable) {
			ready_str = "No (prio=0)";
		} else {
			ready_str = "Unreachable";
		}

		vty_out(vty, "%-20s %-10u %-10s %-12s%s%s\n",
			name, priority,
			reachable ? "Yes" : "No",
			ready_str,
			is_own ? " (self)" : "",
			area->proxy_lsp[ISIS_LEVEL2 - 1] &&
			memcmp(lsp->hdr.lsp_id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0
			? " [LEADER]" : "");
	}

	if (candidates == 0)
		vty_out(vty, "(no candidates found in L2 LSDB)\n");

	vty_out(vty, "\nArea ready: %s\n", ready ? "Yes" : "No");
	vty_out(vty, "Debounce count: %u/2\n", area->area_proxy_ready_count);

	bool is_leader = am_i_leader(area);
	/* Diagnostic: re-run election via shared compute to show winner */
	{
		struct area_proxy_election_result r =
			area_proxy_election_compute(area);
		vty_out(vty, "Election winner: ");
		if (r.valid) {
			vty_out(vty, "%02x%02x.%02x%02x.%02x%02x prio=%u (self=%s)\n",
				r.winner_sysid[0], r.winner_sysid[1],
				r.winner_sysid[2], r.winner_sysid[3],
				r.winner_sysid[4], r.winner_sysid[5],
				r.winner_priority,
				memcmp(r.winner_sysid, area->isis->sysid,
				       ISIS_SYS_ID_LEN) == 0 ? "yes" : "no");
		} else {
			vty_out(vty, "(none)\n");
		}
	}
	vty_out(vty, "Computed leader: %s\n",
		is_leader ? "this router" : "another router");
}

/*
 * Show ready-state details: which L1-reachable routers
 * are missing Area Proxy TLV (Type 27).
 */
void isis_area_proxy_show_ready(struct vty *vty, struct isis_area *area)
{
	if (!area || !area->area_proxy_enabled) {
		vty_out(vty, "Area Proxy not enabled\n");
		return;
	}

	bool ready = isis_area_proxy_ready(area);
	vty_out(vty, "Area Proxy Ready Check\n");
	vty_out(vty, "  Overall: %s\n", ready ? "READY" : "NOT READY");
	vty_out(vty, "  Debounce: %u/2\n", area->area_proxy_ready_count);

	vty_out(vty, "\nL1-reachable routers missing Area Proxy TLV:\n");
	int missing = 0;
	struct isis_lsp *lsp_l1;
	for (lsp_l1 = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp_l1;
	     lsp_l1 = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp_l1)) {
		if (lsp_l1->hdr.seqno == 0 || lsp_l1->hdr.rem_lifetime == 0)
			continue;

		bool found = false;
		struct isis_lsp *lsp_l2;
		for (lsp_l2 = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp_l2;
		     lsp_l2 = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp_l2)) {
			if (isis_lsp_is_proxy_lsp(lsp_l2))
				continue;
			if (memcmp(lsp_l2->hdr.lsp_id, lsp_l1->hdr.lsp_id,
				   ISIS_SYS_ID_LEN) != 0)
				continue;
			if (lsp_l2->hdr.seqno == 0 || lsp_l2->hdr.rem_lifetime == 0)
				continue;
			found = true;
			break;
		}
		if (!found) {
			missing++;
			vty_out(vty, "  %02x%02x.%02x%02x.%02x%02x\n",
				lsp_l1->hdr.lsp_id[0], lsp_l1->hdr.lsp_id[1],
				lsp_l1->hdr.lsp_id[2], lsp_l1->hdr.lsp_id[3],
				lsp_l1->hdr.lsp_id[4], lsp_l1->hdr.lsp_id[5]);
		}
	}
	if (missing == 0)
		vty_out(vty, "  (none)\n");
	vty_out(vty, "\nCounters: gen=%llu skip_nochange=%llu refresh=%llu leader_chg=%llu ready_chg=%llu flood_filtered=%llu flood_event=%llu rx_snp=%llu rx_lsp=%llu\n",
		area->ap_lsp_gen_count, area->ap_lsp_skip_nochange,
		area->ap_lsp_refresh_count,
		area->ap_leader_changes, area->ap_ready_changes,
		area->ap_filtered_lsp_count, area->ap_flood_event_count,
		area->ap_rx_snp_filtered, area->ap_rx_lsp_filtered);
}

/*
 * Show Proxy LSP summary: seqno, age, size, key TLVs.
 */
void isis_area_proxy_show_lsp(struct vty *vty, struct isis_area *area)
{
	if (!area || !area->area_proxy_enabled) {
		vty_out(vty, "Area Proxy not enabled\n");
		return;
	}

	struct isis_lsp *lsp;
	uint8_t lsp_id_show[ISIS_SYS_ID_LEN + 2];

	/* Use lsp_search() instead of area->proxy_lsp[L2-1] to guard
	 * against dangling pointer (P6 hardening). */
	memcpy(lsp_id_show, area->area_proxy_sysid, ISIS_SYS_ID_LEN);
	lsp_id_show[ISIS_SYS_ID_LEN] = 0;
	lsp = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1], lsp_id_show);
	if (!lsp) {
		vty_out(vty, "No Proxy LSP generated yet\n");
		return;
	}

	vty_out(vty, "Proxy LSP: %02x%02x.%02x%02x.%02x%02x.00-00\n",
		lsp->hdr.lsp_id[0], lsp->hdr.lsp_id[1],
		lsp->hdr.lsp_id[2], lsp->hdr.lsp_id[3],
		lsp->hdr.lsp_id[4], lsp->hdr.lsp_id[5]);
	vty_out(vty, "  SeqNo: 0x%08x  Checksum: 0x%04hx  Lifetime: %us\n",
		lsp->hdr.seqno, lsp->hdr.checksum, lsp->hdr.rem_lifetime);
	vty_out(vty, "  PDU Length: %u  Level: %d\n",
		lsp->hdr.pdu_len, lsp->level);
	if (area->area_proxy_last_gen_time == 0)
		vty_out(vty, "  Last generated: never\n");
	else
		vty_out(vty, "  Last generated: %llds ago\n",
			(long long)(monotime(NULL) - area->area_proxy_last_gen_time));
	vty_out(vty, "  Total generations: %llu (skipped nochange: %llu)\n",
		area->ap_lsp_gen_count, area->ap_lsp_skip_nochange);

	/* Show TLV summary */
	if (lsp->tlvs) {
		int reach_count = 0, prefix_count = 0;
		struct isis_extended_reach *r;
		for (r = (struct isis_extended_reach *)lsp->tlvs->extended_reach.head;
		     r; r = r->next)
			reach_count++;

		/* Count IP prefixes via extended_ip_reach */
		struct isis_extended_ip_reach *ip;
		for (ip = (struct isis_extended_ip_reach *)lsp->tlvs->extended_ip_reach.head;
		     ip; ip = ip->next)
			prefix_count++;

		vty_out(vty, "  IS neighbors: %d  IP prefixes: %d\n",
			reach_count, prefix_count);
	}
}

/*
 * Show misconfiguration: Proxy SysID conflicts, missing config.
 */
void isis_area_proxy_show_misconfig(struct vty *vty, struct isis_area *area)
{
	if (!area || !area->area_proxy_enabled) {
		vty_out(vty, "Area Proxy not enabled\n");
		return;
	}

	int issues = 0;
	vty_out(vty, "Area Proxy Misconfiguration Check\n");

	/* Check proxy-sysid is set */
	if (isis_area_proxy_sysid_is_zero(area->area_proxy_sysid)) {
		vty_out(vty, "  ⚠  proxy-sysid not configured\n");
		issues++;
	}

	/* Check Proxy SysID conflict: another router's real SysID */
	struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp)) {
		if (lsp->hdr.seqno == 0) continue;
		if (memcmp(lsp->hdr.lsp_id, area->area_proxy_sysid, ISIS_SYS_ID_LEN) == 0
		    && memcmp(lsp->hdr.lsp_id, area->isis->sysid, ISIS_SYS_ID_LEN) != 0) {
			vty_out(vty, "  ⚠  Proxy SysID conflict: %02x%02x.%02x%02x.%02x%02x is a real router\n",
				lsp->hdr.lsp_id[0], lsp->hdr.lsp_id[1],
				lsp->hdr.lsp_id[2], lsp->hdr.lsp_id[3],
				lsp->hdr.lsp_id[4], lsp->hdr.lsp_id[5]);
			issues++;
			break;
		}
	}

	/* Check Proxy SysID consistency across Area nodes.
	 * Each node with Area Proxy enabled advertises its proxy-sysid
	 * in the Area Proxy System Identifier Sub-TLV (Type 28) within
	 * Router Capability TLV (Type 242).  All nodes in the same
	 * Area must use the same proxy-sysid. */
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;
		if (isis_lsp_is_proxy_lsp(lsp))
			continue; /* skip Proxy LSPs */
		if (!memcmp(lsp->hdr.lsp_id, area->isis->sysid,
			    ISIS_SYS_ID_LEN))
			continue; /* skip self */
		if (!lsp->tlvs || !lsp->tlvs->router_cap)
			continue;
		if (lsp->tlvs->router_cap->area_leader_priority == 0)
			continue;

		if (!lsp->tlvs->area_proxy ||
		    !lsp->tlvs->area_proxy->has_proxy_sysid) {
			vty_out(vty, "  ⚠  Proxy SysID unknown (no Type 20 TLV): %pSY (upgrade needed)\n",
				lsp->hdr.lsp_id);
			issues++;
		} else if (memcmp(lsp->tlvs->area_proxy->proxy_sysid,
				  area->area_proxy_sysid,
				  ISIS_SYS_ID_LEN) != 0) {
			struct isis_area_proxy_tlv *ap = lsp->tlvs->area_proxy;
			vty_out(vty, "  ⚠  Proxy SysID mismatch: %pSY advertises %pSY (local expects %pSY)\n",
				lsp->hdr.lsp_id,
				ap->proxy_sysid,
				area->area_proxy_sysid);
			issues++;
		}
	}

	/* Check leader election mode */
	if (!area->area_proxy_leader_election) {
		vty_out(vty, "  ℹ  Distributed mode (no leader election)\n");
	} else {
		vty_out(vty, "  ✓ Leader election enabled, priority=%u\n",
			area->area_proxy_leader_priority);
	}

	if (issues == 0)
		vty_out(vty, "  ✓ No misconfig detected\n");
}

int isis_area_proxy_set_sysid(struct isis_area *area, const char *sysid_str)
{
	if (!area || !area->area_proxy_enabled)
		return -1;

	if (!sysid_str || strlen(sysid_str) == 0)
		return -1;

	uint8_t sysid[ISIS_SYS_ID_LEN];
	if (!sysid2buff(sysid, sysid_str)) {
		zlog_warn("Area Proxy: invalid proxy-sysid format: %s", sysid_str);
		return -1;
	}

	/* Detect whether this is a real change from a non-zero old value.
	 * First-time config (old sysid all-zero) does not trigger purge. */
	bool old_nonzero = !isis_area_proxy_sysid_is_zero(area->area_proxy_sysid);
	bool changed = old_nonzero &&
		(memcmp(area->area_proxy_sysid, sysid, ISIS_SYS_ID_LEN) != 0);

	/* Purge old Proxy LSP before updating sysid.
	 * lsp_purge() reads area->area_proxy_sysid (still old value). */
	if (changed)
		isis_area_proxy_lsp_purge(area);

	memcpy(area->area_proxy_sysid, sysid, ISIS_SYS_ID_LEN);

	zlog_info("Area Proxy: set proxy-sysid to %pSY on area %s",
		  area->area_proxy_sysid, area->area_tag);

	/* Trigger reconcile on real change so the new Proxy LSP
	 * (or leader election with new sysid) is generated. */
	if (changed) {
		area->proxy_lsp_dirty = true;
		isis_area_proxy_schedule_reconcile(area, AP_REASON_CONFIG_CHANGE);
	}

	/* Always regenerate own L2 LSP — Type 20 TLV must reflect
	 * the proxy-sysid regardless of whether it's first config
	 * (changed=false) or a cross-area migration (changed=true). */
	if (area->is_type & IS_LEVEL_2)
		lsp_generate(area, IS_LEVEL_2);

	return 0;
}

int isis_area_proxy_set_sid(struct isis_area *area, uint32_t sid)
{
	if (!area || !area->area_proxy_enabled)
		return -1;

	area->area_proxy_sid = sid;
	area->area_sid_enabled = true;
	area->area_sid_type = SR_SID_VALUE_TYPE_INDEX;  /* default: index */
	area->area_sid_flags = 0;

	zlog_info("Area Proxy: set area-sid to %u (index) on area %s",
		  sid, area->area_tag);

	/* Trigger reconcile to regenerate Proxy LSP */
	isis_area_proxy_schedule_reconcile(area, AP_REASON_CONFIG_CHANGE);

	return 0;
}

int isis_area_proxy_unset_sid(struct isis_area *area)
{
	if (!area)
		return -1;

	area->area_proxy_sid = 0;
	area->area_sid_enabled = false;
	area->area_sid_type = 0;
	area->area_sid_flags = 0;

	zlog_info("Area Proxy: unset area-sid on area %s", area->area_tag);

	lsp_regenerate_schedule(area, ISIS_LEVEL2, 0);

	return 0;
}

/* ────────────────────────────────────────────
 * Aggregation Algorithm — Step 1 ~ Step 6
 * ──────────────────────────────────────────── */

/*
 * Check if a System ID belongs to an Inside Router (exists in L1 LSDB).
 * Used by boundary filtering to identify Outside vs Inside neighbors.
 */
bool isis_sysid_in_l1_lsdb(struct isis_area *area, const uint8_t *sysid)
{
	struct isis_lsp *lsp;

	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp)) {
		if (memcmp(lsp->hdr.lsp_id, sysid, ISIS_SYS_ID_LEN) == 0)
			return true;
	}
	return false;
}

/*
 * hash_clean callbacks: XFREE with correct MTYPE for FRR memory tracking.
 */
static void hash_clean_xfree_prefix_agg(void *ptr)
{
	XFREE(MTYPE_ISIS_AREA_PROXY_PREFIX_AGG, ptr);
}

static void hash_clean_xfree_proxy_sysid(void *ptr)
{
	XFREE(MTYPE_ISIS_AREA_PROXY_SYSID_SET, ptr);
}

/*
 * BUG-011 note: do NOT filter L1+L2 nodes from prefix aggregation.
 * An earlier attempt (isis_area_proxy_lsp_l1l2_origin) excluded nodes
 * whose SysID had a non-Proxy L2 LSP, but in topologies where all
 * satellites are L1+L2 (e.g. Walker Delta MPLS SR), this removes ALL
 * IPv6 prefixes from the Proxy LSP — breaking cross-area routing.
 *
 * The correct fix is to ensure the aggregation correctly captures
 * Prefix-SID sub-TLVs (which the code already does) rather than
 * removing the duplicate L2 sources at the aggregation level.
 */

/*
 * Prefix aggregation entry: deduplicate by prefix, keep minimum metric
 * and Prefix-SID (consensus strategy: keep only if all occurrences agree).
 * Uses FRR hash table for O(1) lookup and unlimited capacity.
 */
struct prefix_agg_entry {
	struct prefix prefix;
	uint32_t min_metric;
	bool has_min;

	/* Prefix-SID (RFC 8667): consensus across all L1 nodes.
	 * Propagated through Proxy LSP only if !sid_conflict. */
	bool has_sid;
	bool sid_conflict;
	uint32_t sid_value;   /* index or absolute value */
	uint8_t sid_flags;    /* ISIS_PREFIX_SID_* flags */
};

/* Hash key: prefix itself */
struct prefix_agg_key {
	struct prefix prefix;
};

static unsigned int prefix_agg_hash_key(const void *p)
{
	const struct prefix_agg_key *key = p;
	unsigned int h = 0;
	int i;

	h = (h * 31) + key->prefix.family;
	h = (h * 31) + key->prefix.prefixlen;
	for (i = 0; i < (key->prefix.prefixlen + 7) / 8 && i < 16; i++)
		h = (h * 31) + key->prefix.u.val[i];
	return h;
}

static bool prefix_agg_hash_cmp(const void *a, const void *b)
{
	const struct prefix_agg_key *ka = a;
	const struct prefix_agg_key *kb = b;
	return prefix_same(&ka->prefix, &kb->prefix);
}

static void *prefix_agg_hash_alloc(void *arg)
{
	struct prefix_agg_key *key = arg;
	struct prefix_agg_entry *e;

	e = XCALLOC(MTYPE_ISIS_AREA_PROXY_PREFIX_AGG, sizeof(*e));
	prefix_copy(&e->prefix, &key->prefix);
	e->min_metric = UINT32_MAX;
	e->has_min = false;
	return e;
}

/*
 * Callback: collect IP prefixes from L1 LSDB.
 *
 * Collects minimum metric and Prefix-SID (consensus strategy).
 * If multiple L1 nodes advertise the same prefix with conflicting
 * Prefix-SID values, the SID is dropped (not propagated through
 * Proxy LSP) and a warning is logged.
 *
 * NOTE: isis_lsp_iterate_ip_reach() passes (struct prefix *) cast from
 * struct prefix_ipv6, whose internal layout differs from struct prefix
 * (address field at offset 4 vs offset 8).  We must normalise to a
 * real struct prefix before using prefix_same / prefix_copy, otherwise
 * IPv6 addresses are read from the wrong offset and aggregation fails.
 */
static int proxy_aggregate_ip_reach_cb(const struct prefix *prefix,
					uint32_t metric, bool external,
					struct isis_subtlvs *subtlvs,
					void *arg)
{
	struct hash *tbl = arg;
	struct prefix_agg_key key;
	struct prefix_agg_entry *e;

	/* Normalise the pointer: copy into a real struct prefix so that
	 * prefix_same() / prefix_copy() access the address at the correct
	 * offset regardless of whether the original was struct prefix_ipv4
	 * or struct prefix_ipv6. */
	prefix_copy(&key.prefix, prefix);

	e = hash_get(tbl, &key, prefix_agg_hash_alloc);

	if (!e->has_min || metric < e->min_metric) {
		e->min_metric = metric;
		e->has_min = true;
	}

	/* Collect Prefix-SID (consensus strategy). */
	zlog_debug("Area Proxy: agg prefix %pFX subtlvs=%p psids_head=%p has_sid=%d metric=%u",
		   prefix, (void *)subtlvs,
		   (subtlvs && subtlvs->prefix_sids.head)
			   ? (void *)subtlvs->prefix_sids.head
			   : NULL,
		   e->has_sid, metric);
	if (subtlvs && subtlvs->prefix_sids.head) {
		struct isis_prefix_sid *psid =
			(struct isis_prefix_sid *)subtlvs->prefix_sids.head;

		if (!e->has_sid) {
			/* First occurrence — record. */
			e->has_sid = true;
			e->sid_value = psid->value;
			e->sid_flags = psid->flags;
		} else if (!e->sid_conflict) {
			/* Subsequent occurrence — check consensus. */
			if (e->sid_value != psid->value ||
			    e->sid_flags != psid->flags) {
				e->sid_conflict = true;
				zlog_warn("Area Proxy: prefix %pFX Prefix-SID conflict: "
					  "value=%u flags=0x%02x vs value=%u flags=0x%02x, dropping",
					  prefix, e->sid_value, e->sid_flags,
					  psid->value, psid->flags);
			}
		}
	}

	return LSP_ITER_CONTINUE;
}

/*
 * Hash iterate callback: write a collected prefix to Proxy LSP TLVs.
 *
 * Prefix-SID is propagated only if all L1 nodes agree on the same
 * SID value and flags (consensus strategy).  If a conflict was
 * detected, the prefix is written without Prefix-SID to avoid
 * publishing an incorrect label mapping.
 */
struct proxy_agg_counters {
	uint32_t total_prefixes;
	uint32_t with_sid;
	uint32_t without_sid;
	uint32_t sid_conflict;
};

struct proxy_agg_write_ctx {
	struct isis_tlvs *proxy_tlvs;
	struct proxy_agg_counters cnt;
};

static void prefix_agg_write_cb(struct hash_bucket *hb, void *arg)
{
	struct prefix_agg_entry *e = hb->data;
	struct proxy_agg_write_ctx *ctx = arg;
	struct isis_tlvs *proxy_tlvs = ctx->proxy_tlvs;

	ctx->cnt.total_prefixes++;

	if (!e->has_min)
		return;

	/* Construct Prefix-SID config if consensus holds. */
	struct sr_prefix_cfg sid_cfg = {};
	struct sr_prefix_cfg *pcfg = NULL;

	if (e->has_sid && !e->sid_conflict) {
		sid_cfg.sid = e->sid_value;
		sid_cfg.n_flag_clear = false;

		zlog_debug("Area Proxy: write prefix %pFX with SID=%u flags=0x%02x",
			   &e->prefix, e->sid_value, e->sid_flags);

		/*
		 * RFC 9666 §4.4.7: R-flag (Readvertised) SHOULD
		 * be set in the Proxy LSP.
		 *
		 * P-flag (No-PHP): intentionally NOT force-reset.
		 * RFC 9666 §4.4.7 says P-flag SHOULD be reset to
		 * avoid PHP at the proxy node.  However, in
		 * satellite MPLS architectures the egress is a
		 * ground station (abundant CPU), not a satellite
		 * (constrained).  Preserving P-flag from the
		 * consensus lets the ground station pop its own
		 * label — all satellites remain pure MPLS, zero
		 * IP FIB.  For prefixes without P-flag, PHP
		 * proceeds normally.
		 */
		e->sid_flags |= ISIS_PREFIX_SID_READVERTISED;

		/* Reverse-map isis_prefix_sid flags → sr_prefix_cfg fields */
		if (e->sid_flags & ISIS_PREFIX_SID_VALUE)
			sid_cfg.sid_type = SR_SID_VALUE_TYPE_ABSOLUTE;
		else
			sid_cfg.sid_type = SR_SID_VALUE_TYPE_INDEX;

		if (e->sid_flags & ISIS_PREFIX_SID_NODE)
			sid_cfg.node_sid = true;
		else
			sid_cfg.node_sid = false;

		if ((e->sid_flags & ISIS_PREFIX_SID_NO_PHP) &&
		    (e->sid_flags & ISIS_PREFIX_SID_EXPLICIT_NULL))
			sid_cfg.last_hop_behavior =
				SR_LAST_HOP_BEHAVIOR_EXP_NULL;
		else if (e->sid_flags & ISIS_PREFIX_SID_NO_PHP)
			sid_cfg.last_hop_behavior =
				SR_LAST_HOP_BEHAVIOR_NO_PHP;
		else
			sid_cfg.last_hop_behavior =
				SR_LAST_HOP_BEHAVIOR_PHP;

		pcfg = &sid_cfg;
		ctx->cnt.with_sid++;
	} else if (e->sid_conflict) {
		ctx->cnt.sid_conflict++;
	} else {
		ctx->cnt.without_sid++;
	}

	if (e->prefix.family == AF_INET) {
		struct prefix_ipv4 *p4 = (struct prefix_ipv4 *)&e->prefix;
		isis_tlvs_add_extended_ip_reach(
			proxy_tlvs, p4, e->min_metric, false, pcfg);
	} else if (e->prefix.family == AF_INET6) {
		struct prefix_ipv6 p6 = {
			.family = AF_INET6,
			.prefixlen = e->prefix.prefixlen,
			.prefix = e->prefix.u.prefix6,
		};
		isis_tlvs_add_ipv6_reach(
			proxy_tlvs, ISIS_MT_IPV4_UNICAST,
			&p6, e->min_metric, false, pcfg);
	}
}

/*
 * Step 1~6: Aggregate L1 LSDB into a single Proxy LSP's TLVs.
 *   Step 1 — Basic TLVs (Protocols Supported, Area Addresses, Hostname)
 *   Step 2 — Boundary IS Neighbors (Inside Edge → Outside Edge only)
 *   Step 3 — IP Reachability (min metric per prefix)
 *   Step 4 — Router Capability (SR/SRv6/TE)
 *   Step 5 — Multi-Topology
 *   Step 6 — Area SID
 */
struct isis_tlvs *isis_area_proxy_aggregate_tlvs(struct isis_area *area)
{
	struct isis_tlvs *proxy_tlvs;
	struct isis_lsp *lsp;

	if (!area || !area->area_proxy_enabled)
		return NULL;

	proxy_tlvs = isis_alloc_tlvs();
	if (!proxy_tlvs)
		return NULL;

	zlog_debug("Area Proxy: aggregating TLVs for area %s", area->area_tag);

	/* KNOWN LIMITATIONS (Phase 9):
	 * - Step 4 (Router Capability: SR/SRv6/TE) not aggregated
	 * - Step 5 (Multi-Topology) not aggregated
	 * Enable when SR-TE or MT is needed.
	 */

	/* ================================================================
	 * STEP 1: Basic TLVs
	 * ================================================================ */

	/* 1a. Protocols Supported TLV (129) */
	{
		struct nlpids nlp = {};
		nlp.count = 2;
		nlp.nlpids[0] = 0xCC; /* IPv4 */
		nlp.nlpids[1] = 0x8E; /* IPv6 */
		isis_tlvs_set_protocols_supported(proxy_tlvs, &nlp);
	}

	/* 1b. Area Addresses TLV (1) — copy from area config */
	if (iso_address_list_first(&area->area_addrs))
		isis_tlvs_add_area_addresses(proxy_tlvs, area->area_addrs);

	/* 1c. Dynamic Hostname TLV (137) — use proxy-sysid suffix for uniqueness */
	{
		char hostname[256];
		snprintf(hostname, sizeof(hostname),
			 "PROXY-%02x%02x",
			 area->area_proxy_sysid[4],
			 area->area_proxy_sysid[5]);
		isis_tlvs_set_dynamic_hostname(proxy_tlvs, hostname);
	}

	/* ================================================================
	 * STEP 2: Boundary IS Neighbors
	 *
	 * Iterate L2 LSDB. For each Inside Edge Router's LSP,
	 * extract only the IS neighbors that point OUTSIDE the area
	 * (i.e., not in L1 LSDB).
	 * ================================================================ */

	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		uint8_t *src_id = lsp->hdr.lsp_id;

		/* Skip Proxy LSP itself */
		if (isis_lsp_is_proxy_lsp(lsp))
			continue;

		/* Only Inside Edge Routers have L2 LSPs */
		if (!isis_sysid_in_l1_lsdb(area, src_id))
			continue;

		/* Skip expired LSPs */
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;

		/* Iterate extended IS reachability */
		if (!lsp->tlvs)
			continue;

		struct isis_extended_reach *reach;
		for (reach = (struct isis_extended_reach *)
				lsp->tlvs->extended_reach.head;
		     reach; reach = reach->next) {
			/* Skip neighbors that are INSIDE the area */
			if (isis_sysid_in_l1_lsdb(area, reach->id))
				continue;

			/*
			 * IS neighbor aggregation strategy:
			 *
			 * [impl-opt, default] Deduplicate: one entry per
			 *   remote SysID, keeping the minimum metric across
			 *   all Inside Edge Routers.  IIH masquerading makes
			 *   multiple Edge Routers to the same area appear as
			 *   the same neighbor → natural dedup.
			 *
			 * [baseline] RFC 9666 §4.4.5 "copy each": copy every
			 *   IS neighbor entry verbatim, no dedup.  Used for
			 *   control-plane cost analysis (K-value study).
			 *   Toggle via CLI: [no] is-neighbor-baseline.
			 */
			if (area->area_proxy_rfc9666_faithful) {
				/* Baseline: copy each (RFC 9666 §4.4.5) */
				isis_tlvs_add_extended_reach(
					proxy_tlvs, ISIS_MT_IPV4_UNICAST,
					reach->id, reach->metric, NULL);
			} else {
				/* Impl-opt: dedup + min metric */
				struct isis_extended_reach *existing;
				for (existing = (struct isis_extended_reach *)
					     proxy_tlvs->extended_reach.head;
				     existing; existing = existing->next) {
					if (memcmp(existing->id, reach->id,
						   sizeof(existing->id)) == 0)
						break;
				}
				if (existing) {
					if (reach->metric < existing->metric)
						existing->metric = reach->metric;
				} else {
					isis_tlvs_add_extended_reach(
						proxy_tlvs, ISIS_MT_IPV4_UNICAST,
						reach->id, reach->metric, NULL);
				}
			}
		}
	}

	/* ================================================================
	 * STEP 3: IP Reachability
	 *
	 * Iterate L1 LSDB, collect all IPv4/IPv6 prefixes,
	 * choose the minimum metric for each.
	 * ================================================================ */

	{
		struct hash *pat = hash_create(prefix_agg_hash_key,
					       prefix_agg_hash_cmp,
					       "Proxy LSP prefix agg");

		/* Collect from L1 LSDB */
		struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp)) {
			if (lsp->hdr.seqno == 0 ||
			    lsp->hdr.rem_lifetime == 0)
				continue;

			isis_lsp_iterate_ip_reach(
				lsp, AF_INET, ISIS_MT_IPV4_UNICAST,
				proxy_aggregate_ip_reach_cb, pat);
			isis_lsp_iterate_ip_reach(
				lsp, AF_INET6, ISIS_MT_IPV4_UNICAST,
				proxy_aggregate_ip_reach_cb, pat);
		}

		/* Write collected prefixes to Proxy LSP */
		struct proxy_agg_write_ctx ctx = { .proxy_tlvs = proxy_tlvs };
		hash_iterate(pat, prefix_agg_write_cb, &ctx);
		zlog_info("Area Proxy: aggregation summary — %u prefixes: %u with SID, %u without SID, %u conflict",
			  ctx.cnt.total_prefixes, ctx.cnt.with_sid,
			  ctx.cnt.without_sid, ctx.cnt.sid_conflict);
		hash_clean(pat, hash_clean_xfree_prefix_agg);
		hash_free(pat);
	}

	/* ================================================================
	 * STEP 4: Router Capability TLV (242)
	 *
	 * Gather SR-MPLS / SRv6 capabilities from the first L1 LSP
	 * that has a router_cap TLV.  In practice all satellites in a
	 * Stripe share the same SRGB / SRv6 Locator — we use the first
	 * one found and copy it into the Proxy LSP so that Outside
	 * Routers can compute SR paths that traverse this Stripe.
	 * ================================================================ */

	{
		struct isis_lsp *lsp_rcap = NULL;

		struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp)) {
			if (lsp->hdr.seqno == 0 ||
			    lsp->hdr.rem_lifetime == 0)
				continue;
			if (!lsp->tlvs || !lsp->tlvs->router_cap)
				continue;

			lsp_rcap = lsp;
			break;
		}

		if (lsp_rcap) {
			struct isis_router_cap *src =
				lsp_rcap->tlvs->router_cap;
			struct isis_router_cap *dst =
				isis_tlvs_init_router_capability(proxy_tlvs);

			/* Copy router-id, flags, SRGB, SRLB, algorithms, MSD */
			dst->router_id = src->router_id;
			dst->flags     = src->flags;
			dst->srgb      = src->srgb;
			dst->srlb      = src->srlb;
			memcpy(dst->algo, src->algo, sizeof(src->algo));
			dst->msd       = src->msd;
#if 0 /* FAD and SRv6 not available in FRR 8.4 */
#ifndef FABRICD
			/* Copy Flex-Algo definitions */
			for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
				if (src->fads[i])
					isis_tlvs_set_router_capability_fad(
						proxy_tlvs,
						&src->fads[i]->fad,
						i, NULL);
			}
#endif
			/* Copy SRv6 capabilities */
			dst->srv6_cap = src->srv6_cap;
			dst->srv6_msd = src->srv6_msd;
#endif /* FRR 8.4 */

			zlog_debug("Area Proxy: aggregated Router Capability "
				  "from LSP %pLS", lsp_rcap->hdr.lsp_id);
		}
	}

	/* ================================================================
	 * STEP 5: Multi-Topology — skip for MVP-1
	 * ================================================================ */

	/* ================================================================
	 * STEP 6: Area SID — Type 20 Area Proxy TLV.
	 *
	 * Publishes the Area SID as a property of the Proxy Area
	 * (not of any individual prefix).  This enables external
	 * routers to address the entire Area as a single SR node
	 * for hierarchical TE and anycast entry.
	 * ================================================================ */

	if (area->area_sid_enabled) {
		struct isis_area_proxy_tlv ap_tlv = {};

		memcpy(ap_tlv.proxy_sysid, area->area_proxy_sysid,
		       ISIS_SYS_ID_LEN);
		ap_tlv.has_proxy_sysid = true;
		ap_tlv.has_area_sid = true;
		ap_tlv.area_sid_algo = SR_ALGORITHM_SPF;
		ap_tlv.area_sid_value = area->area_proxy_sid;
		ap_tlv.area_sid_flags = area->area_sid_flags;

		isis_tlvs_set_area_proxy(proxy_tlvs, &ap_tlv);
	}

	return proxy_tlvs;
}

/* ────────────────────────────────────────────
 * Leader Election (RFC 9667)
 * ──────────────────────────────────────────── */

/*
 * Determine if this router is the Area Leader.
 *
 * Reads election info (Type 27 area_leader_priority) from L2 LSDB —
 * election information is carried in Inside L2 LSPs on level-1-2 interfaces.
 *
 * Filters by L1 SPF reachability (direct SPF tree query).
 * This guarantees a single area-wide leader, not per-clique leaders.
 * Winner: highest priority, ties broken by highest System ID.
 */

/*
 * Compute the Area Leader by scanning L2 LSDB.
 *
 * Reads election info (Type 27 area_leader_priority) from L2 LSDB.
 * Filters by L1 SPF reachability (direct SPF tree query).
 * Winner: highest priority, ties broken by highest System ID.
 */
static struct area_proxy_election_result
area_proxy_election_compute(struct isis_area *area)
{
	struct area_proxy_election_result result = { .valid = false };
	struct isis_lsp *lsp;

	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		uint8_t priority = 0;
		bool is_own = (memcmp(lsp->hdr.lsp_id, area->isis->sysid,
				      ISIS_SYS_ID_LEN) == 0);

		if (isis_lsp_is_proxy_lsp(lsp))
			continue;
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;

		if (!is_own && !isis_spf_sysid_reachable(area, lsp->hdr.lsp_id))
			continue;

		if (is_own)
			priority = area->area_proxy_leader_priority;
		else if (lsp->tlvs && lsp->tlvs->router_cap)
			priority = lsp->tlvs->router_cap->area_leader_priority;
		if (priority == 0)
			continue;

		if (!result.valid ||
		    priority > result.winner_priority ||
		    (priority == result.winner_priority &&
		     memcmp(lsp->hdr.lsp_id, result.winner_sysid,
			    ISIS_SYS_ID_LEN) > 0)) {
			result.winner_priority = priority;
			memcpy(result.winner_sysid, lsp->hdr.lsp_id,
			       ISIS_SYS_ID_LEN);
			result.valid = true;
		}
	}
	return result;
}

/*
 * Determine if this router is the Area Leader.
 * Delegates to area_proxy_election_compute().
 */
static bool am_i_leader(struct isis_area *area)
{
	area_proxy_debug("Area Proxy: election started, local sysid=%pSY prio=%u",
			 area->isis->sysid, area->area_proxy_leader_priority);

	struct area_proxy_election_result r =
		area_proxy_election_compute(area);

	if (!r.valid) {
		area_proxy_debug("Area Proxy: election — no valid candidate, deferring");
		return false;
	}
	bool i_am = (memcmp(r.winner_sysid, area->isis->sysid,
			    ISIS_SYS_ID_LEN) == 0);
	area_proxy_debug("Area Proxy: election result — winner=%pSY prio=%u i_am=%s",
			 r.winner_sysid, r.winner_priority,
			 i_am ? "LEADER" : "FOLLOWER");
	return i_am;
}

/*
 * Purge our Proxy LSP and ALL its fragments (every pseudo_id).
 *
 * Called from: admin disable (no area-proxy), Leader step-down.
 *
 * Scans LSDB for every fragment matching area_proxy_sysid prefix,
 * regardless of whether they are linked via lspu.frags.  This
 * catches orphan fragments left behind when fragment count shrinks
 * (e.g. 2→1) and the old fragment was unlinked from lspu.frags
 * but not removed from LSDB.
 */
void isis_area_proxy_lsp_purge(struct isis_area *area)
{
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	int fid;
	int purged = 0;

	memcpy(lsp_id, area->area_proxy_sysid, ISIS_SYS_ID_LEN);

	for (fid = 0; fid < 255; fid++) {
		lsp_id[ISIS_SYS_ID_LEN] = fid;
		struct isis_lsp *lsp = lsp_search(
			&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
		if (!lsp)
			break;  /* sequential IDs — stop at first gap */
		/* Skip already-purged placeholders (PduLen==27, rem_lifetime==0);
		 * they will age out naturally. */
		/* Only purge own_lsp — never touch Proxy LSPs learned
		 * from other nodes (e.g. Area Leader's Proxy LSP in
		 * GS LSDB). */
		if (!lsp->own_lsp)
			continue;
		if (lsp->hdr.rem_lifetime == 0)
			continue;

		lsp->hdr.rem_lifetime = 0;
		lsp_flood(lsp, NULL);
		lsp_search_and_destroy(&area->lspdb[ISIS_LEVEL2 - 1],
				       lsp->hdr.lsp_id);
		purged++;
	}

	if (purged > 0)
		zlog_info("Area Proxy: purged %d Proxy LSP fragments "
			  "(step-down or admin disable)", purged);

	area->proxy_lsp[ISIS_LEVEL2 - 1] = NULL;
}

/*
 * Ready Check: verify all L1 SPF-reachable Inside Routers have Area
 * Proxy information in their L2 LSPs before generating the Proxy LSP.
 *
 * Uses L1 SPF reachable set (same SPF tree query as am_i_leader).
 * Dead nodes whose LSPs are still in LSDB but no longer in the L1
 * adjacency graph are correctly excluded.
 *
 * A router is "ready" if its L2 LSP fragment 0:
 *   - is not purged (seqno != 0, lifetime != 0)
 *   - carries area_leader_priority > 0 (participating in election)
 */
static bool isis_area_proxy_ready(struct isis_area *area)
{
	struct isis_lsp *lsp;

	/* Iterate L2 LSDB — check every L1-SPF-reachable candidate */
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		if (isis_lsp_is_proxy_lsp(lsp))
			continue;
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;

		bool is_own = (memcmp(lsp->hdr.lsp_id, area->isis->sysid,
				      ISIS_SYS_ID_LEN) == 0);

		/* L1 SPF reachability check */
		if (!is_own && !isis_spf_sysid_reachable(area, lsp->hdr.lsp_id))
			continue;  /* not L1-SPF-reachable — skip */

		/* Check Area Proxy TLV (Type 27) in L2 LSP.
		 * A node with area_leader_priority > 0 is a voting member
		 * and MUST have the TLV.  A node with priority == 0 is a
		 * non-voting / non-participating node (e.g. Ground Station)
		 * — skip it, but do NOT block the ready check. */
		bool has_tlv = false;
		if (is_own) {
			if (area->area_proxy_leader_priority == 0)
				continue;  /* self is non-voting */
			has_tlv = (area->area_proxy_leader_priority > 0);
		} else {
			/* TLV truly missing: router_cap absent or no
			 * area_leader_priority field at all. */
			if (!lsp->tlvs || !lsp->tlvs->router_cap) {
				zlog_info("Area Proxy: not ready — %pLS missing Router Capability TLV (L1-SPF-reachable)",
					  lsp->hdr.lsp_id);
				return false;
			}
			if (lsp->tlvs->router_cap->area_leader_priority == 0)
				continue;  /* non-voting, e.g. GS */
			has_tlv = true;
		}

		if (!has_tlv) {
			zlog_info("Area Proxy: not ready — %pLS missing Type 27 TLV (L1-SPF-reachable)",
				  lsp->hdr.lsp_id);
			return false;
		}
	}

	zlog_info("Area Proxy: ready check passed (all voting L1-SPF routers have Area Proxy capability; non-voting routers skipped)");
	return true;
}

/* ── Proxy SysID hash set: key is 6-byte System ID ── */
struct proxy_sysid_key {
	uint8_t sysid[ISIS_SYS_ID_LEN];
};

static unsigned int proxy_sysid_hash_key(const void *p)
{
	const struct proxy_sysid_key *k = p;
	return ((k->sysid[0] << 16) | (k->sysid[1] << 8) | k->sysid[2])
	     ^ ((k->sysid[3] << 16) | (k->sysid[4] << 8) | k->sysid[5]);
}

static bool proxy_sysid_hash_cmp(const void *a, const void *b)
{
	return memcmp(((const struct proxy_sysid_key *)a)->sysid,
		      ((const struct proxy_sysid_key *)b)->sysid,
		      ISIS_SYS_ID_LEN) == 0;
}

static void *proxy_sysid_hash_alloc(void *arg)
{
	struct proxy_sysid_key *src = arg;
	struct proxy_sysid_key *dst;

	dst = XCALLOC(MTYPE_ISIS_AREA_PROXY_SYSID_SET, sizeof(*dst));
	memcpy(dst->sysid, src->sysid, ISIS_SYS_ID_LEN);
	return dst;
}

/*
 * Rebuild the Proxy SysID set from L2 LSDB sub-TLV 28.
 * Called from reconciler to keep the set in sync.
 */
static void proxy_sysid_set_rebuild(struct isis_area *area)
{
	if (!area->proxy_sysid_set)
		return;

	hash_clean(area->proxy_sysid_set, hash_clean_xfree_proxy_sysid);

	struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
			continue;
		if (!lsp->tlvs || !lsp->tlvs->area_proxy ||
		    !lsp->tlvs->area_proxy->has_proxy_sysid)
			continue;

		struct proxy_sysid_key key;
		memcpy(key.sysid,
		       lsp->tlvs->area_proxy->proxy_sysid,
		       ISIS_SYS_ID_LEN);
		hash_get(area->proxy_sysid_set, &key,
			 proxy_sysid_hash_alloc);
	}
}

/* ────────────────────────────────────────────
 * Area Proxy Reconciler — single-entry state machine
 *
 * All triggers (adjacency change, LSP insert, config change) are
 * funnelled into one reconciler per area.  The reconciler:
 *   1. Defers during startup settle window (configurable, default 35s + jitter)
 *   2. Serialises execution via ap_reconcile_running guard
 *   3. Re-evaluates boundary circuits and edge-router cache
 *   4. Runs leader election (if enabled) + ready check
 *   5. Generates Proxy LSP transactionally (all-or-nothing)
 *   6. Reschedules itself periodically
 * ──────────────────────────────────────────── */

static void isis_area_proxy_reconcile_cb(struct thread *t)
{
	struct isis_area *area = THREAD_ARG(t);
	uint32_t reasons;
	bool is_leader, ready, was_leader;
	uint32_t next_interval;

	area->t_area_proxy_reconcile = NULL;
	area->ap_reconcile_fast_pending = false;

	/* ── 1. Startup settle: defer all actual work ── */
	if (monotime(NULL) < area->proxy_lsp_settle_until) {
		time_t remaining = area->proxy_lsp_settle_until - monotime(NULL);
		uint32_t jitter = (uint32_t)(random() % 15);

		if (remaining < 1)
			remaining = 1;
		zlog_debug("Area Proxy: reconcile deferred, settle %lds + %us jitter",
			  (long)remaining, jitter);
		thread_add_timer(master, isis_area_proxy_reconcile_cb,
				area, remaining + jitter,
				&area->t_area_proxy_reconcile);
		return;
	}

	/* ── 2. Reentrancy guard ── */
	if (area->ap_reconcile_running) {
		area_proxy_debug("Area Proxy: reconcile reentry — skip");
		return;
	}
	area->ap_reconcile_running = true;

	/* ── 3. Snapshot + clear pending reasons ── */
	reasons = area->ap_pending_reasons;
	area->ap_pending_reasons = 0;

	area_proxy_debug("Area Proxy: reconcile, reasons=0x%x dirty=%d",
			reasons, area->proxy_lsp_dirty);

	/* ── Rebuild Proxy SysID set (lazy init + sub-TLV 28 scan) ── */
	if (!area->proxy_sysid_set)
		area->proxy_sysid_set = hash_create(
			proxy_sysid_hash_key, proxy_sysid_hash_cmp,
			"Proxy SysID set");
	proxy_sysid_set_rebuild(area);

	/* ── 4. Re-evaluate boundary circuits ── */
	{
		struct isis_circuit *circuit;
		struct listnode *cnode;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (!circuit->is_area_proxy_boundary &&
			    (area->is_type & IS_LEVEL_1) &&
			    circuit->is_type == IS_LEVEL_2) {
				circuit->is_area_proxy_boundary = true;
				continue;
			}
			if (!circuit->is_area_proxy_boundary &&
			    (circuit->is_type & IS_LEVEL_2)) {
				if (circuit->circ_type == CIRCUIT_T_P2P
				    && circuit->u.p2p.neighbor
				    && circuit->u.p2p.neighbor->adj_state == ISIS_ADJ_UP
				    && !isis_sysid_in_l1_lsdb(area,
					    circuit->u.p2p.neighbor->sysid)) {
					circuit->is_area_proxy_boundary = true;
					continue;
				}
			}
			if (!circuit->is_area_proxy_boundary)
				continue;
			bool has_l1 = false;
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				struct listnode *node;
				struct isis_adjacency *a;
				for (ALL_LIST_ELEMENTS_RO(
					     circuit->u.bc.adjdb[ISIS_LEVEL1 - 1],
					     node, a))
					if (a->adj_state == ISIS_ADJ_UP) {
						has_l1 = true;
						break;
					}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor) {
				has_l1 = (circuit->u.p2p.neighbor->level & ISIS_LEVEL1);
			}
			if (has_l1)
				circuit->is_area_proxy_boundary = false;
		}
	}

	/* ── 5. Cache edge-router flag on Inside L2 LSPs ── */
	{
		struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
			if (isis_lsp_is_proxy_lsp(lsp))
				continue;
			if (!isis_sysid_in_l1_lsdb(area, lsp->hdr.lsp_id))
				continue;
			lsp->is_edge_router = false;
			if (lsp->tlvs) {
				struct isis_extended_reach *reach;
				for (reach = (struct isis_extended_reach *)
					     lsp->tlvs->extended_reach.head;
				     reach; reach = reach->next) {
					if (!isis_sysid_in_l1_lsdb(area,
								    reach->id)) {
						lsp->is_edge_router = true;
						break;
					}
				}
			}
		}
	}

	/* ── 6. Leader election / Distributed generation ── */
	if (area->area_proxy_leader_election) {
		was_leader = (area->proxy_lsp[ISIS_LEVEL2 - 1] != NULL);
		is_leader = am_i_leader(area);

		if (is_leader) {
			if (!was_leader) {
				zlog_info("Area Proxy: elected LEADER (priority %u)",
					  area->area_proxy_leader_priority);
				area->ap_leader_changes++;
			}

			ready = isis_area_proxy_ready(area);
			bool first_attempt = (area->proxy_lsp[ISIS_LEVEL2 - 1] == NULL);

			if (!ready && !first_attempt) {
				zlog_info("Area Proxy: not ready, deferring");
				area->area_proxy_ready_count = 0;
			} else if (first_attempt) {
				zlog_info("Area Proxy: first reconcile, generating directly");
				area->ap_reconcile_running = false;
				isis_area_proxy_lsp_generate(area);
				area->proxy_lsp_dirty = false;
				area->area_proxy_last_gen_time = monotime(NULL);
				area->area_proxy_ready_count = 0;
			} else {
				area->area_proxy_ready_count++;
				if (area->area_proxy_ready_count >= 2) {
					/* ── P1: Convergence guard (with time-based refresh) ── */
					uint8_t p1_id[ISIS_SYS_ID_LEN + 2];
					memcpy(p1_id, area->area_proxy_sysid,
					       ISIS_SYS_ID_LEN);
					p1_id[ISIS_SYS_ID_LEN] = 0;
					struct isis_lsp *existing = lsp_search(
						&area->lspdb[ISIS_LEVEL2 - 1],
						p1_id);

					/* LSP refresh threshold: same semantics as
					 * standard IS-IS lsp_refresh (default 900s).
					 * Force regenerate when Proxy LSP lifetime
					 * drops below this, even if !dirty. */
					uint16_t refresh_limit =
						area->lsp_refresh[ISIS_LEVEL2 - 1]
							? area->lsp_refresh[ISIS_LEVEL2 - 1]
							: 900;
					bool need_refresh =
						existing &&
						existing->hdr.rem_lifetime != 0 &&
						existing->hdr.seqno != 0 &&
						existing->hdr.rem_lifetime <
							refresh_limit;

					if (existing &&
					    existing->hdr.rem_lifetime != 0 &&
					    existing->hdr.seqno != 0 &&
					    !area->proxy_lsp_dirty &&
					    !need_refresh) {
						area->ap_lsp_skip_nochange++;
						zlog_info("Area Proxy: "
							  "skip generate — "
							  "valid Proxy LSP "
							  "+ !dirty "
							  "(convergence guard)");
					} else {
						if (need_refresh) {
							area->ap_lsp_refresh_count++;
							zlog_info("Area Proxy: "
								  "time-based refresh — "
								  "lifetime %us < %us",
								  existing->hdr
									.rem_lifetime,
								  refresh_limit);
						} else {
							zlog_info("Area Proxy: "
								  "ready debounced → "
								  "generate");
						}
						area->ap_reconcile_running = false;
						isis_area_proxy_lsp_generate(area);
						area->proxy_lsp_dirty = false;
						area->area_proxy_last_gen_time =
							monotime(NULL);
					}
					area->area_proxy_ready_count = 0;
				}
			}
		} else {
			area->area_proxy_ready_count = 0;
			if (was_leader) {
				zlog_info("Area Proxy: stepped down as LEADER");
				area->ap_leader_changes++;
				area->proxy_lsp[ISIS_LEVEL2 - 1] = NULL;
			}
		}
	} else {
		/* Distributed mode: always regenerate on each reconcile tick. */
		area->ap_reconcile_running = false;
		isis_area_proxy_lsp_generate(area);
		area->proxy_lsp_dirty = false;
		area->area_proxy_last_gen_time = monotime(NULL);
	}

	area->ap_reconcile_running = false;

	/* ── 7. If new reasons arrived during execution, reschedule fast ── */
	if (area->ap_pending_reasons) {
		uint32_t jitter = (uint32_t)(random() % 3);
		area->ap_reconcile_fast_pending = true;
		thread_add_timer(master, isis_area_proxy_reconcile_cb,
				area, 1 + jitter,
				&area->t_area_proxy_reconcile);
		return;
	}

	/* ── 8. Schedule next periodic round ── */
	if (area->area_proxy_leader_election)
		next_interval = area->area_proxy_elect_check_sec ?
				area->area_proxy_elect_check_sec : 30;
	else
		next_interval = area->lsp_refresh[ISIS_LEVEL2 - 1] ?
				area->lsp_refresh[ISIS_LEVEL2 - 1] : 900;

	thread_add_timer(master, isis_area_proxy_reconcile_cb,
			area, next_interval,
			&area->t_area_proxy_reconcile);
}

/*
 * Single entry point for all Area Proxy triggers.
 *
 * Sets the pending reason bitmask and schedules the reconciler.
 * If reconcile is already running, just set the flag (the callback
 * will pick it up at the end of the current cycle and reschedule).
 *
 * Timer guard semantics:
 *   - If no timer is pending, create one with delay based on reason.
 *   - If a long-period timer (e.g. 900s periodic) is pending and a
 *     high-priority event (LSP/ADJ change) arrives, cancel the old
 *     timer and reschedule with a short 3~7s delay.
 *   - If a fast debounce timer is already pending, just accumulate
 *     reasons (do not keep pushing the timer back).
 */
void isis_area_proxy_schedule_reconcile(struct isis_area *area, uint32_t reason)
{
	uint32_t delay;

	if (!area || !area->area_proxy_enabled)
		return;

	area->ap_pending_reasons |= reason;

	/* Reconcile running → flags accumulate, callback picks them up */
	if (area->ap_reconcile_running)
		return;

	/* ── Timer guard with priority-aware preemption ── */
	if (area->t_area_proxy_reconcile) {
		if ((reason & (AP_REASON_LSP_CHANGE | AP_REASON_ADJ_CHANGE))
		    && !area->ap_reconcile_fast_pending) {
			/* Preempt: cancel long-period timer, reschedule fast */
			THREAD_OFF(area->t_area_proxy_reconcile);
			area->ap_reconcile_fast_pending = true;
			/* fall through to schedule */
		} else {
			/* Already a fast timer pending, or low-priority
			 * reason → just accumulate, don't push back */
			return;
		}
	}

	/* Calculate delay based on trigger type */
	if (monotime(NULL) < area->proxy_lsp_settle_until) {
		time_t remaining = area->proxy_lsp_settle_until - monotime(NULL);
		delay = (remaining > 0 ? (uint32_t)remaining : 1)
			+ (uint32_t)(random() % 15);
	} else if (reason & (AP_REASON_ADJ_CHANGE | AP_REASON_LSP_CHANGE)) {
		delay = 3 + (uint32_t)(random() % 5);
		area->ap_reconcile_fast_pending = true;
	} else if (reason & AP_REASON_INITIAL) {
		delay = 5 + (uint32_t)(random() % 10);
	} else {
		delay = 2 + (uint32_t)(random() % 3);
	}

	thread_add_timer(master, isis_area_proxy_reconcile_cb,
			area, delay, &area->t_area_proxy_reconcile);

	area_proxy_debug("Area Proxy: reconcile scheduled, reason=0x%x delay=%us",
			reason, delay);
}

/* ── isis_lsp_is_proxy_lsp: 8.4 implementation (was in isis_lsp.c on 10.7) ── */

/*
 * Check whether an old Proxy LSP fragment is valid for content comparison.
 * Purged, expired, or empty fragments must not participate in unchanged
 * detection — they must trigger regeneration.
 */
static bool area_proxy_lsp_fragment_valid(struct isis_lsp *lsp)
{
	if (!lsp)
		return false;
	if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
		return false;
	if (lsp->hdr.pdu_len <= 27)  /* 27 = LLC(3) + common hdr(8) + LSP hdr(16): header-only, no TLV payload */
		return false;
	if (!lsp->tlvs)
		return false;
	return true;
}

/*
 * Free a fragment list produced by isis_fragment_tlvs(),
 * releasing each fragment's TLV data.
 */
static void area_proxy_fragment_list_free(struct list *fragments)
{
	struct listnode *node, *nnode;
	struct isis_tlvs *frag_tlvs;

	if (!fragments)
		return;

	for (ALL_LIST_ELEMENTS(fragments, node, nnode, frag_tlvs)) {
		isis_free_tlvs(frag_tlvs);
		list_delete_node(fragments, node);
	}
	list_delete(&fragments);
}

/*
 * Serialize a single fragment's TLVs into a fresh stream, then
 * compare with an existing LSP fragment's serialized TLV payload.
 *
 * Returns true if the TLV content is identical, false otherwise.
 * Pack failures are treated as "changed" (conservative).
 */
static bool area_proxy_fragment_tlv_equal(struct isis_area *area,
					  struct isis_tlvs *new_tlvs,
					  struct isis_lsp *old_frag)
{
	struct stream *new_s, *old_s;
	size_t new_len, old_len;
	bool result = false;
	size_t stream_size;

	if (!area_proxy_lsp_fragment_valid(old_frag))
		return false;

	/* Use area lsp_mtu with margin for serialization buffer */
	stream_size = area->lsp_mtu ? area->lsp_mtu : DEFAULT_LSP_MTU;

	new_s = stream_new(stream_size);
	old_s = stream_new(stream_size);

	/* Pack failures → conservative: treat as changed */
	if (isis_pack_tlvs(new_tlvs, new_s, (size_t)-1, false, true) != 0)
		goto out;
	if (isis_pack_tlvs(old_frag->tlvs, old_s, (size_t)-1, false, true) != 0)
		goto out;

	new_len = stream_get_endp(new_s);
	old_len = stream_get_endp(old_s);

	if (new_len == old_len)
		result = (memcmp(STREAM_DATA(new_s), STREAM_DATA(old_s),
				 new_len) == 0);

out:
	stream_free(new_s);
	stream_free(old_s);
	return result;
}

/*
 * Compare newly aggregated+ fragmented TLVs with the existing
 * Proxy LSP fragments already in the LSDB.
 *
 * Precondition: the entire existing Proxy LSP fragment set
 * must be complete and valid in the LSDB.  If fragment 0 is
 * missing or invalid, returns false immediately (force
 * regeneration) regardless of content comparison.
 *
 * Returns true if all fragments have identical TLV content
 * (no regeneration needed), false if any fragment changed,
 * missing, or invalid.
 */
static bool area_proxy_lsp_content_unchanged(struct isis_area *area,
					     struct list *new_fragments)
{
	struct isis_lsp *lsp0;
	struct listnode *node;
	struct isis_tlvs *new_frag_tlvs;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	int old_frag_count, new_frag_count;
	int idx = 0;

	/* Build base LSP ID for fragment lookup */
	memcpy(lsp_id, area->area_proxy_sysid, ISIS_SYS_ID_LEN);
	/* lsp_id[ISIS_SYS_ID_LEN]=0 and lsp_id[ISIS_SYS_ID_LEN+1]=0 already from {} */

	/* Use lsp_search() instead of area->proxy_lsp[L2-1] to guard
	 * against dangling pointer (P6 hardening).  Also validates
	 * that fragment 0 is complete and valid in LSDB. */
	lsp0 = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
	if (!lsp0 || !area_proxy_lsp_fragment_valid(lsp0))
		return false;

	/* Compare fragment count */
	new_frag_count = listcount(new_fragments);
	old_frag_count = 1;  /* fragment 0 */
	if (lsp0->lspu.frags)
		old_frag_count += listcount(lsp0->lspu.frags);

	if (new_frag_count != old_frag_count)
		return false;

	for (ALL_LIST_ELEMENTS_RO(new_fragments, node, new_frag_tlvs)) {
		struct isis_lsp *old_frag;

		if (idx == 0) {
			old_frag = lsp0;
		} else {
			lsp_id[ISIS_SYS_ID_LEN + 1] = idx;
			old_frag = lsp_search(
				&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
		}

		if (!area_proxy_fragment_tlv_equal(area, new_frag_tlvs, old_frag))
			return false;

		idx++;
	}
	return true;
}

/*
 * Generate (or regenerate) the Proxy LSP from aggregated TLVs,
 * then flood it to all L2 neighbors.
 *
 * Supports fragmentation: if aggregated TLVs exceed lsp_mtu,
 * additional fragments (00-01, 00-02, ...) are created and
 * linked via lspu.frags chain.
 */
int isis_area_proxy_lsp_generate(struct isis_area *area)
{
	struct isis_lsp *lsp0 = NULL;
	struct isis_tlvs *tlvs = NULL;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	struct list *fragments = NULL;
	struct listnode *node;
	struct isis_tlvs *frag_tlvs;
	uint32_t new_seqno = 1;
	int frag_count = 0;
	int ret = -1;
	size_t tlv_space;
	bool frag0_reused;

	if (!area || !area->area_proxy_enabled)
		return -1;

	/* P0: reentrancy guard — prevent recursive generate from
	 * reconcile_cb re-entry. */
	if (area->ap_reconcile_running) {
		area_proxy_debug("Area Proxy: generate reentry — skip");
		return 0;
	}
	area->ap_reconcile_running = true;

	/* Ensure lsp_mtu is initialized before first Proxy LSP generation.
	 * During config parsing, area->lsp_mtu may still be 0, causing
	 * lsp_adjust_stream() to create a stream too small for TLVs. */
	if (area->lsp_mtu == 0)
		area->lsp_mtu = DEFAULT_LSP_MTU;

	/* Check if proxy_sysid is configured */
	if (isis_area_proxy_sysid_is_zero(area->area_proxy_sysid)) {
		zlog_warn("Area Proxy: cannot generate Proxy LSP, "
			  "proxy-sysid is not configured");
		goto out;
	}

	/* Aggregate L1 LSDB into Proxy TLVs */
	tlvs = isis_area_proxy_aggregate_tlvs(area);
	if (!tlvs) {
		zlog_warn("Area Proxy: aggregation returned NULL TLVs");
		goto out;
	}

	/* --- Calculate available TLV space and fragment ---
	 * Must happen before seqno bump to allow content comparison. */
	tlv_space = area->lsp_mtu - 23 - 4;
	fragments = isis_fragment_tlvs(tlvs, tlv_space);
	isis_free_tlvs(tlvs);
	tlvs = NULL;
	if (!fragments) {
		zlog_warn("Area Proxy: isis_fragment_tlvs returned NULL");
		goto out;
	}

	/* --- Content-change guard ---
	 * If the aggregated content is identical to the existing
	 * Proxy LSP and the LSP set is complete in the LSDB, skip
	 * regeneration: do not bump seqno, do not flood, do not
	 * trigger L2 SPF.
	 *
	 * Exception: if rem_lifetime < lsp_refresh, allow normal
	 * regenerate to refresh the lifetime.  Proxy LSPs have no
	 * independent refresh timer.
	 *
	 * Use lsp_search() for the lifetime check to guard against
	 * dangling pointer (P6 hardening). */

	/* Build LSP ID early: needed by content guard and fragment 0 lookup */
	memcpy(lsp_id, area->area_proxy_sysid, ISIS_SYS_ID_LEN);
	lsp_id[ISIS_SYS_ID_LEN] = 0; /* pseudo ID */

	if (area_proxy_lsp_content_unchanged(area, fragments)) {
		lsp0 = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
		if (lsp0 && area_proxy_lsp_fragment_valid(lsp0) &&
		    lsp0->hdr.rem_lifetime >=
		    area->lsp_refresh[ISIS_LEVEL2 - 1]) {
			zlog_debug("Area Proxy: content unchanged, skip regenerate");
			area->proxy_lsp_dirty = false;
			area->ap_lsp_skip_nochange++;
			area->ap_lsp_last_skip_time = monotime(NULL);
			ret = 0;
			goto out;
		}
		zlog_debug("Area Proxy: content unchanged but lifetime low (%us), regenerating for refresh",
			   lsp0->hdr.rem_lifetime);
	}

	/* --- Fragment 0: reuse existing or create new ---
	 * In-place update prevents purge flood to receivers.
	 *
	 * Use lsp_search() instead of area->proxy_lsp[L2-1] to guard
	 * against dangling pointer: FRR's age_out may free the LSP
	 * externally, leaving proxy_lsp[] pointing to freed memory.
	 * lsp_search() returns a valid pointer (or NULL) from LSDB. */
	lsp0 = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
	if (lsp0 && lsp0->hdr.rem_lifetime != 0 && lsp0->hdr.seqno != 0) {
		area->proxy_lsp[ISIS_LEVEL2 - 1] = lsp0;
		lsp_inc_seqno(lsp0, 0);
		if (lsp0->tlvs) {
			isis_free_tlvs(lsp0->tlvs);
			lsp0->tlvs = NULL;
		}
		/* Reset lifetime: fragment 0 does not go through
		 * the explicit rem_lifetime reset that fragments
		 * 1+ receive below.  Without this, fragment 0's
		 * lifetime drifts toward zero across regenerations
		 * and eventually expires before fragments 1+. */
		lsp0->hdr.rem_lifetime =
			area->max_lsp_lifetime[ISIS_LEVEL2 - 1];
		lsp0->age_out = ZERO_AGE_LIFETIME;
		new_seqno = lsp0->hdr.seqno;
	} else {
		/* Search LSDB for existing Proxy LSP from previous leader;
		 * if found, reuse it in-place to continue from the right
		 * seqno.  Otherwise start fresh with seqno=1. */
		struct isis_lsp *existing = lsp_search(
			&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
		if (existing && existing->hdr.seqno != 0
		    && existing->hdr.rem_lifetime != 0) {
			lsp0 = existing;
			lsp0->own_lsp = 0;
			new_seqno = lsp0->hdr.seqno + 1;
			lsp0->hdr.seqno = new_seqno;
			if (lsp0->tlvs) {
				isis_free_tlvs(lsp0->tlvs);
				lsp0->tlvs = NULL;
			}
			lsp0->hdr.rem_lifetime =
				area->max_lsp_lifetime[ISIS_LEVEL2 - 1];
			lsp0->age_out = ZERO_AGE_LIFETIME;
		} else {
			/* Determine starting seqno.
			 * Priority: tombstone in LSDB > last generated > 1.
			 * If the tombstone was already destroyed by FRR
			 * (age_out=0), we still remember the last seqno. */
			uint32_t base_seqno = area->area_proxy_last_seqno + 1;
			struct isis_lsp *tombstone = lsp_search(
				&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
			if (tombstone) {
				if (tombstone->hdr.seqno >= base_seqno)
					base_seqno = tombstone->hdr.seqno + 1;
				lsp_search_and_destroy(
					&area->lspdb[ISIS_LEVEL2 - 1],
					tombstone->hdr.lsp_id);
			}

			new_seqno = base_seqno;
			lsp0 = lsp_new(area, lsp_id,
				       area->max_lsp_lifetime[ISIS_LEVEL2 - 1],
				       new_seqno,
				       IS_LEVEL_1_AND_2,
				       0, NULL, ISIS_LEVEL2);
			if (!lsp0) {
				goto out;
			}
			lsp0->own_lsp = 0;
		}
		area->proxy_lsp[ISIS_LEVEL2 - 1] = lsp0;
	}

	/* Safety: lsp0 must be valid before creating sub-fragments.
	 * In high-churn scenarios (100-node areas, crash-restart cycles),
	 * LSDB mutations between the fragment 0 path and here can
	 * invalidate the pointer.  Re-validate from LSDB. */
	if (!lsp0) {
		lsp0 = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1], lsp_id);
	}
	if (!lsp0) {
		zlog_err("Area Proxy: fragment 0 unavailable, abort generate");
		goto out;
	}

	/* --- Assign fragmented TLVs to LSPs, link via lspu.frags ---
	 *
	 * Fragment 0: reused if already in area->proxy_lsp[L2-1] and
	 * verified present in LSDB (not externally purged).
	 * Fragment 1+: searched in LSDB by LSP ID; reused in-place if found.
	 * Any reused fragment skips lsp_insert() to avoid lsp_destroy + UAF. */
	frag0_reused = (area->proxy_lsp[ISIS_LEVEL2 - 1] == lsp0 &&
			lsp0->tlvs == NULL);
	for (ALL_LIST_ELEMENTS_RO(fragments, node, frag_tlvs)) {
		struct isis_lsp *frag;
		bool frag_exists;

		if (frag_count == 0) {
			/* fragment 0 — use the pre-created lsp0.
			 * MUST verify it is actually in the LSDB;
			 * external purge may have removed it. */
			frag = lsp0;
			frag_exists = (frag0_reused &&
				       lsp_search(&area->lspdb[ISIS_LEVEL2 - 1],
						  lsp_id) == lsp0);
		} else {
			lsp_id[ISIS_SYS_ID_LEN + 1] = frag_count;
			/* Search LSDB for existing fragment — reuse in-place
			 * to avoid lsp_destroy → purge PDU flood. */
			frag = lsp_search(&area->lspdb[ISIS_LEVEL2 - 1],
					 lsp_id);
			if (frag) {
				frag_exists = true;
				/* All fragments share the same seqno as
				 * fragment 0.  Do NOT call lsp_inc_seqno()
				 * here — it would diverge from frag 0. */
				frag->hdr.seqno = new_seqno;
				/* Reset lifetime: reused fragment must align
				 * with fragment 0, otherwise stale holdtime
				 * causes premature expiry. */
				frag->hdr.rem_lifetime =
					area->max_lsp_lifetime[ISIS_LEVEL2 - 1];
				frag->age_out = ZERO_AGE_LIFETIME;
				if (frag->tlvs) {
					isis_free_tlvs(frag->tlvs);
					frag->tlvs = NULL;
				}
				/* Fragment may have been purged and
				 * unlinked from lspu.frags in a previous
				 * cycle (e.g. 3→2→3).  Restore parent
				 * pointer and re-link so flood/iteration
				 * sees this fragment. */
				if (frag->lspu.zero_lsp != lsp0)
					frag->lspu.zero_lsp = lsp0;
				if (!listnode_lookup(lsp0->lspu.frags, frag))
					listnode_add(lsp0->lspu.frags, frag);
			} else {
				frag_exists = false;
				frag = lsp_new(area, lsp_id,
					       area->max_lsp_lifetime[ISIS_LEVEL2 - 1],
					       new_seqno,
					       IS_LEVEL_1_AND_2,
					       0, lsp0, ISIS_LEVEL2);
				if (!frag) {
					isis_free_tlvs(frag_tlvs);
					continue;
				}
				frag->own_lsp = 0;
			}
		}

		frag->tlvs = frag_tlvs;
		lsp_pack_pdu_ext(frag);

		/* Fragment already in LSDB: skip lsp_insert() to avoid
		 * lsp_destroy on the same struct (UAF / purge flood). */
		if (frag_exists) {
			/* already in LSDB — just flood updated PDU */
		} else {
			lsp_insert(&area->lspdb[ISIS_LEVEL2 - 1], frag);
		}

		frag_count++;

		zlog_debug("Area Proxy: Proxy LSP fragment %d pdu_len=%u seqno=0x%08x",
			   frag_count - 1, frag->hdr.pdu_len, frag->hdr.seqno);
	}

	list_delete(&fragments);
	fragments = NULL;  /* items now owned by LSPs, prevent out: double-free */

	/* ── BUG-011 diagnostic: count IPv6 reach with/without sub-TLVs ── */
	{
		uint32_t ipv6_total = 0, ipv6_with_sub = 0;
		struct isis_lsp *flsp;
		struct listnode *ln;
		struct isis_ipv6_reach *r;

		for (ALL_LIST_ELEMENTS_RO(lsp0->lspu.frags, ln, flsp)) {
			if (!flsp->tlvs)
				continue;
			for (r = (struct isis_ipv6_reach *)
				 flsp->tlvs->ipv6_reach.head;
			     r; r = r->next) {
				ipv6_total++;
				if (r->subtlvs)
					ipv6_with_sub++;
			}
		}
		/* Also count fragment 0 */
		if (lsp0->tlvs) {
			for (r = (struct isis_ipv6_reach *)
				 lsp0->tlvs->ipv6_reach.head;
			     r; r = r->next) {
				ipv6_total++;
				if (r->subtlvs)
					ipv6_with_sub++;
			}
		}
		zlog_info("Area Proxy: Proxy LSP TLVs audit — %u IPv6 reach, %u with sub-TLVs, %u without",
			  ipv6_total, ipv6_with_sub,
			  ipv6_total - ipv6_with_sub);
	}

	zlog_info("Area Proxy: generated Proxy LSP %pLS, %d fragments",
		  lsp_id, frag_count);
	area->ap_lsp_gen_count++;

	/* Flood all valid fragments to L2 circuits.
	 * Old fragments from previous generations are NOT actively
	 * purged — they age out naturally via FRR's lsp_tick().
	 * The new Leader's higher seqno ensures SPF ignores stale
	 * fragments, so active purge has no routing value and only
	 * creates unnecessary purge PDU storms. */
	lsp_flood(lsp0, NULL);
	if (lsp0->lspu.frags) {
		struct listnode *lnode;
		struct isis_lsp *flsp;

		for (ALL_LIST_ELEMENTS_RO(lsp0->lspu.frags, lnode, flsp))
			lsp_flood(flsp, NULL);
	}

	/* Record last seqno to prevent regress across generations
	 * even after tombstone is cleaned up by FRR. */
	area->area_proxy_last_seqno = lsp0->hdr.seqno;

	zlog_info("Area Proxy: generated %pLS seq=0x%08x lifetime=%us age_out=%u",
		  lsp0->hdr.lsp_id, lsp0->hdr.seqno,
		  lsp0->hdr.rem_lifetime, lsp0->age_out);

	ret = 0;

out:
	area_proxy_fragment_list_free(fragments);
	area->ap_reconcile_running = false;
	return ret;
}

/* ── isis_lsp_is_proxy_lsp ──
 * Identify Proxy LSPs by TLV-driven set (sub-TLV 28), with
 * prefix-match fallback for startup before the set is populated.
 */
bool isis_lsp_is_proxy_lsp(const struct isis_lsp *lsp)
{
	if (!lsp || !lsp->area)
		return false;
	if (!lsp->area->area_proxy_enabled)
		return false;

	/* Primary: TLV-driven hash set */
	if (lsp->area->proxy_sysid_set) {
		struct proxy_sysid_key key;
		memcpy(key.sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
		if (hash_get(lsp->area->proxy_sysid_set, &key, NULL))
			return true;
	}

	/* Fallback: prefix match for startup / non-FFFF SysIDs */
	static const uint8_t proxy_prefix[] = {0xff, 0xff, 0x00, 0x00, 0x00};
	if (memcmp(lsp->hdr.lsp_id, proxy_prefix, sizeof(proxy_prefix)) == 0)
		return true;

	return false;
}

/*
 * Phase 5R: LSP classifiers for flooding decisions.
 *
 * inside_real: L2 LSP whose source SysID exists in L1 LSDB (Inside Router)
 *              and is not a Proxy LSP.
 * proxy:       L2 LSP whose source SysID matches the area's Proxy SysID.
 * outside:     L2 LSP that is neither inside_real nor proxy.
 */
bool isis_area_proxy_lsp_is_inside_real(const struct isis_lsp *lsp)
{
	if (!lsp || !lsp->area || !lsp->area->area_proxy_enabled)
		return false;
	if (lsp->level != ISIS_LEVEL2)
		return false;
	if (isis_lsp_is_proxy_lsp(lsp))
		return false;
	return isis_sysid_in_l1_lsdb(lsp->area, lsp->hdr.lsp_id);
}

/*
 * Check if an LSP ID (raw 8 bytes) matches the Proxy LSP prefix.
 */
bool isis_lsp_id_is_proxy_lsp(const uint8_t *lsp_id)
{
	static const uint8_t prefix[] = {0xff, 0xff, 0x00, 0x00, 0x00};
	return memcmp(lsp_id, prefix, sizeof(prefix)) == 0;
}

/*
 * Circuit role: outside (boundary) circuit.
 *
 * Deployment convention (SatStripe):
 *   AP inside circuit  := IS-IS Level-1-2 circuit
 *   AP outside circuit := IS-IS Level-2-only circuit
 *
 * This is an implementation/deployment convention, not a generic
 * IS-IS semantic.  The reconciler's is_area_proxy_boundary flag is
 * the primary determinant; is_type == IS_LEVEL_2 is a fallback
 * for early startup before the flag is set, and also reflects the
 * current deployment convention.
 */
bool isis_area_proxy_circuit_is_outside(const struct isis_circuit *circuit)
{
	if (!circuit || !circuit->area || !circuit->area->area_proxy_enabled)
		return false;

	if (circuit->is_area_proxy_boundary)
		return true;

	return circuit->is_type == IS_LEVEL_2;
}

/*
 * Circuit role: inside circuit.
 */
bool isis_area_proxy_circuit_is_inside(const struct isis_circuit *circuit)
{
	if (!circuit || !circuit->area || !circuit->area->area_proxy_enabled)
		return false;

	return circuit->is_type == IS_LEVEL_1_AND_2
		&& !circuit->is_area_proxy_boundary;
}

/*
 * Receive-side guard: should we drop a received non-Proxy L2 LSP
 * on a boundary circuit?
 *
 * Returns true if the LSP should be dropped:
 *   - Boundary circuit AND
 *   - Not a Proxy LSP AND
 *   - Not self-originated AND
 *   - Source SysID not in this Area's L1 LSDB (= foreign)
 *
 * Same-area real L2 LSPs are allowed to transit boundary circuits
 * within the proxy area.  Only outside-area real L2 LSPs are dropped.
 *
 * NOTE: during startup when L1 LSDB is empty, this may temporarily
 * drop legitimate same-area L2 LSPs.  A future improvement is to unify
 * with isis_area_proxy_lsp_classify() which uses area-address fallback
 * when L1 LSDB is empty.
 */
bool area_proxy_drop_rx_real_l2_on_boundary(
	struct isis_circuit *circuit, const uint8_t *lsp_id)
{
	if (!circuit || !circuit->area || !circuit->area->area_proxy_enabled)
		return false;

	if (!isis_area_proxy_circuit_is_outside(circuit))
		return false;

	if (isis_lsp_id_is_proxy_lsp(lsp_id))
		return false;

	if (!memcmp(lsp_id, circuit->isis->sysid, ISIS_SYS_ID_LEN))
		return false;

	if (isis_sysid_in_l1_lsdb(circuit->area, lsp_id))
		return false;

	return true;
}

/*
 * Three-state classification of an L2 LSP's scope relative to this Area.
 *
 * Returns one of:
 *   AP_LSP_SCOPE_PROXY       — Proxy LSP (flood everywhere)
 *   AP_LSP_SCOPE_INSIDE_REAL — real LSP from inside this Area
 *   AP_LSP_SCOPE_OUTSIDE_REAL— real LSP from another Area
 *   AP_LSP_SCOPE_UNCLASSIFIED— cannot determine (L1 LSDB empty at startup)
 *
 * Classification is based on whether the LSP's System ID appears in the
 * local L1 LSDB.  When the L1 LSDB is empty (startup window), falls back
 * to area-address matching: same area → INSIDE_REAL, different → OUTSIDE_REAL.
 */
enum area_proxy_lsp_scope
isis_area_proxy_lsp_classify(const struct isis_lsp *lsp)
{
	if (!lsp || !lsp->area || !lsp->area->area_proxy_enabled)
		return AP_LSP_SCOPE_UNCLASSIFIED;
	if (lsp->level != ISIS_LEVEL2)
		return AP_LSP_SCOPE_UNCLASSIFIED;
	if (isis_lsp_is_proxy_lsp(lsp))
		return AP_LSP_SCOPE_PROXY;

	bool l1_empty = (lspdb_first(&lsp->area->lspdb[ISIS_LEVEL1 - 1])
			== NULL);

	if (l1_empty) {
		/* Startup: use area-address matching as fallback */
		if (lsp->tlvs && isis_tlvs_area_addresses_match(
			    lsp->tlvs, lsp->area->area_addrs))
			return AP_LSP_SCOPE_INSIDE_REAL;
		return AP_LSP_SCOPE_OUTSIDE_REAL;
	}

	/* Normal path: check L1 LSDB */
	if (isis_sysid_in_l1_lsdb(lsp->area, lsp->hdr.lsp_id))
		return AP_LSP_SCOPE_INSIDE_REAL;
	return AP_LSP_SCOPE_OUTSIDE_REAL;
}

/*
 * Check whether an L2 LSP should be flooded onto a specific circuit.
 *
 * This is the single-point filtering function used by:
 *   - lsp_set_all_srmflags()  (initial flood filter)
 *   - send_lsp()              (final send gate — catches PSNP bypass etc.)
 *   - PSNP handler            (on-demand send filter)
 *
 * Area Proxy adopts a bidirectional real-LSP isolation model:
 *
 *   LSP scope          | boundary circuit | internal circuit
 *   -------------------+------------------+-----------------
 *   PROXY              | ✅ allow         | ✅ allow
 *   INSIDE_REAL        | ❌ block         | ✅ allow
 *   OUTSIDE_REAL       | ✅ allow         | ❌ block
 *   UNCLASSIFIED       | conservative     | conservative
 *     same area addr   | ❌ (as inside)   | ✅ (as inside)
 *     diff  area addr  | ✅ (as outside)  | ❌ (as outside)
 *
 * Cross-area reachability is provided exclusively by Proxy LSPs.
 * Real L2 LSPs never cross an Area boundary in either direction.
 *
 * Returns true = allow, false = filter out.
 */
bool isis_area_proxy_lsp_should_flood(const struct isis_lsp *lsp,
				      struct isis_circuit *circuit)
{
	if (!lsp || !circuit)
		return true;
	if (!lsp->area || !lsp->area->area_proxy_enabled)
		return true;
	if (lsp->level != ISIS_LEVEL2)
		return true;

	enum area_proxy_lsp_scope scope = isis_area_proxy_lsp_classify(lsp);
	bool is_boundary = isis_area_proxy_circuit_is_outside(circuit);

	switch (scope) {
	case AP_LSP_SCOPE_PROXY:
		return true;
	case AP_LSP_SCOPE_INSIDE_REAL:
		/* Block on boundary — prevent internal topology from
		 * leaking to other Areas. */
		return !is_boundary;
	case AP_LSP_SCOPE_OUTSIDE_REAL:
		/* Block on internal — prevent other Areas' real L2
		 * topology from entering this Area.  Cross-area
		 * reachability is provided by Proxy LSPs only. */
		return is_boundary;
	case AP_LSP_SCOPE_UNCLASSIFIED:
	default:
		return true;
	}
}

/*
 * RFC 9666 §5.2: Remove Inside L2 LSP entries from SNP (CSNP/PSNP)
 * entry lists on boundary circuits.
 *
 * The source address of CSNP/PSNP already uses the proxy-sysid;
 * this function filters the content — LSP summaries whose SysID
 * belongs to this Area's L1 LSDB (i.e. Inside Routers) must not
 * appear in SNP PDUs sent over boundary circuits.
 *
 * Called by send_csnp() and send_psnp() after building the entry list.
 */
void isis_area_proxy_filter_snp_entries(struct isis_area *area,
					struct isis_item_list *entries)
{
	struct isis_item *prev = NULL;
	struct isis_item *item;
	struct isis_item *next;

	if (!area || !entries)
		return;

	for (item = entries->head; item; item = next) {
		next = item->next;
		struct isis_lsp_entry *e = (struct isis_lsp_entry *)item;

		if (isis_sysid_in_l1_lsdb(area, e->id)) {
			/* Unlink from singly-linked list. */
			if (prev)
				prev->next = next;
			else
				entries->head = next;

			/* Adjust tail pointer if removing the last element.
			 * tail is struct isis_item **, pointing to the last
			 * node's ->next field (or &entries->head if empty). */
			if (&item->next == entries->tail)
				entries->tail = prev ? &prev->next
						     : &entries->head;

			XFREE(MTYPE_ISIS_TLV, e);
			entries->count--;
		} else {
			prev = item;
		}
	}
}

/* ── 8.4: Router Capability init for Area Proxy Step 4 ── */
struct isis_router_cap *isis_tlvs_init_router_capability(struct isis_tlvs *tlvs)
{
	tlvs->router_cap = XCALLOC(MTYPE_TMP, sizeof(struct isis_router_cap));
	if (tlvs->router_cap)
		tlvs->router_cap->router_id.s_addr = INADDR_ANY;
	return tlvs->router_cap;
}

/* lsp_pack_pdu_ext() is implemented in isis_lsp.c */

