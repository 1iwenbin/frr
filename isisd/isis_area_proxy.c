/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 oaemu contributors
 *
 * IS-IS Area Proxy (RFC 9666) — configuration management
 */

#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "log.h"

#include "isisd/isisd.h"
#include "isisd/isis_area_proxy.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"

/* 8.4 compatibility macros for deprecated 10.7 list APIs */
#define iso_address_list_first(al) ((al) && listhead(*(al)))

void isis_area_proxy_enable(struct isis_area *area)
{
	if (!area || area->area_proxy_enabled)
		return;

	area->area_proxy_enabled = true;

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

	/* Only schedule timer if mode has been explicitly set.
	 * Otherwise wait for leader-election / no leader-election command.
	 * This prevents premature generation before proxy-sysid/area-sid
	 * are fully configured. */
	if (area->area_proxy_mode_set)
		isis_area_proxy_lsp_regenerate_schedule(area);
}

void isis_area_proxy_disable(struct isis_area *area)
{
	if (!area || !area->area_proxy_enabled)
		return;

	area->area_proxy_enabled = false;
	memset(area->area_proxy_sysid, 0, ISIS_SYS_ID_LEN);
	area->area_proxy_sid = 0;

	zlog_info("Area Proxy: disabled on area %s", area->area_tag);

	/* Purge Proxy LSP if we are the leader */
	if (area->proxy_lsp[ISIS_LEVEL2 - 1]) {
		lsp_regenerate_schedule(area, ISIS_LEVEL2, 0);
		area->proxy_lsp[ISIS_LEVEL2 - 1] = NULL;
	}

	/* Regenerate L2 LSP to remove Area Proxy TLV */
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

void isis_area_proxy_show(struct vty *vty, const struct isis_area *area)
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
		if (area->area_proxy_sid)
			vty_out(vty, "  Area SID: %u\n",
				area->area_proxy_sid);

		/* Mode */
		if (area->area_proxy_leader_election) {
			vty_out(vty, "  Mode: leader-election\n");
			bool i_am = am_i_leader(area);
			bool has_proxy = (area->proxy_lsp[ISIS_LEVEL2 - 1] != NULL);
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
	}
}

/*

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
			struct isis_circuit *circuit;
			struct listnode *cnode;
			for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
				if ((circuit->is_type & IS_LEVEL_1) == 0)
					continue;
				struct listnode *anode;
				struct isis_adjacency *adj;
				if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
					for (ALL_LIST_ELEMENTS_RO(
						     circuit->u.bc.adjdb[ISIS_LEVEL1 - 1],
						     anode, adj)) {
						if (adj->adj_state == ISIS_ADJ_UP &&
						    memcmp(adj->sysid, lsp->hdr.lsp_id,
							   ISIS_SYS_ID_LEN) == 0) {
							reachable = true;
							break;
						}
					}
				} else if (circuit->circ_type == CIRCUIT_T_P2P &&
					   circuit->u.p2p.neighbor &&
					   circuit->u.p2p.neighbor->adj_state == ISIS_ADJ_UP &&
					   memcmp(circuit->u.p2p.neighbor->sysid,
						  lsp->hdr.lsp_id, ISIS_SYS_ID_LEN) == 0) {
					reachable = true;
				}
				if (reachable)
					break;
			}
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
	/* Diagnostic: re-run election inline to show winner */
	{
		uint8_t winner_sysid[ISIS_SYS_ID_LEN] = {};
		uint8_t winner_prio = 0;
		bool found = false;
		for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
		     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
			uint8_t p = 0;
			bool own = (memcmp(lsp->hdr.lsp_id, area->isis->sysid,
					   ISIS_SYS_ID_LEN) == 0);
			if (isis_lsp_is_proxy_lsp(lsp)) continue;
			if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0) continue;
			if (!own) {
				bool r = false;
				struct isis_circuit *c;
				struct listnode *cn;
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cn, c)) {
					if ((c->is_type & IS_LEVEL_1) == 0) continue;
					if (c->circ_type == CIRCUIT_T_P2P && c->u.p2p.neighbor &&
					    c->u.p2p.neighbor->adj_state == ISIS_ADJ_UP &&
					    memcmp(c->u.p2p.neighbor->sysid, lsp->hdr.lsp_id,
						   ISIS_SYS_ID_LEN) == 0)
					{ r = true; break; }
				}
				if (!r) continue;
			}
			if (own) p = area->area_proxy_leader_priority;
			else if (lsp->tlvs && lsp->tlvs->router_cap)
				p = lsp->tlvs->router_cap->area_leader_priority;
			if (p == 0) continue;
			if (!found || p > winner_prio ||
			    (p == winner_prio &&
			     memcmp(lsp->hdr.lsp_id, winner_sysid, ISIS_SYS_ID_LEN) > 0)) {
				winner_prio = p;
				memcpy(winner_sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
				found = true;
			}
		}
		vty_out(vty, "Election winner: %02x%02x.%02x%02x.%02x%02x prio=%u (self=%s)\n",
			winner_sysid[0], winner_sysid[1], winner_sysid[2],
			winner_sysid[3], winner_sysid[4], winner_sysid[5],
			winner_prio,
			memcmp(winner_sysid, area->isis->sysid, ISIS_SYS_ID_LEN) == 0
			? "yes" : "no");
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
	vty_out(vty, "\nCounters: gen=%llu leader_chg=%llu ready_chg=%llu filtered=%llu\n",
		area->ap_lsp_gen_count, area->ap_leader_changes,
		area->ap_ready_changes, area->ap_filtered_lsp_count);
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

	struct isis_lsp *lsp = area->proxy_lsp[ISIS_LEVEL2 - 1];
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
	vty_out(vty, "  Last generated: %llds ago\n",
		(long long)(monotime(NULL) - area->area_proxy_last_gen_time));
	vty_out(vty, "  Total generations: %llu\n", area->ap_lsp_gen_count);

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
	bool sysid_zero = true;
	for (int i = 0; i < ISIS_SYS_ID_LEN; i++) {
		if (area->area_proxy_sysid[i] != 0) { sysid_zero = false; break; }
	}
	if (sysid_zero) {
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

	memcpy(area->area_proxy_sysid, sysid, ISIS_SYS_ID_LEN);

	zlog_info("Area Proxy: set proxy-sysid to %pSY on area %s",
		  area->area_proxy_sysid, area->area_tag);

	/* Don't schedule generation — mode may not be set yet.
	 * Generation triggered by leader-election / no leader-election. */
	return 0;
}

int isis_area_proxy_set_sid(struct isis_area *area, uint32_t sid)
{
	if (!area || !area->area_proxy_enabled)
		return -1;

	area->area_proxy_sid = sid;

	zlog_info("Area Proxy: set area-sid to %u on area %s",
		  sid, area->area_tag);

	/* Regenerate Proxy LSP with updated Area SID */
	isis_area_proxy_lsp_generate(area);

	return 0;
}

int isis_area_proxy_unset_sid(struct isis_area *area)
{
	if (!area)
		return -1;

	area->area_proxy_sid = 0;

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
 * A simple entry for prefix aggregation: tracks the minimum metric
 * for each unique prefix.
 */
struct prefix_agg_entry {
	struct prefix prefix;
	uint32_t min_metric;
	bool has_min;
};

#define PREFIX_AGG_MAX 1024

struct prefix_agg_table {
	struct prefix_agg_entry entries[PREFIX_AGG_MAX];
	int count;
};

static struct prefix_agg_entry *prefix_agg_lookup(struct prefix_agg_table *tbl,
						   const struct prefix *p)
{
	for (int i = 0; i < tbl->count; i++) {
		if (prefix_same(&tbl->entries[i].prefix, p))
			return &tbl->entries[i];
	}
	return NULL;
}

static struct prefix_agg_entry *prefix_agg_add(struct prefix_agg_table *tbl,
						const struct prefix *p)
{
	if (tbl->count >= PREFIX_AGG_MAX)
		return NULL;
	struct prefix_agg_entry *e = &tbl->entries[tbl->count++];
	prefix_copy(&e->prefix, p);
	e->min_metric = UINT32_MAX;
	e->has_min = false;
	return e;
}

/*
 * Callback: collect IP prefixes from L1 LSDB.
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
	struct prefix_agg_table *tbl = arg;
	struct prefix pfx_normalised;

	/* Normalise the pointer: copy into a real struct prefix so that
	 * prefix_same() / prefix_copy() access the address at the correct
	 * offset regardless of whether the original was struct prefix_ipv4
	 * or struct prefix_ipv6. */
	prefix_copy(&pfx_normalised, prefix);

	struct prefix_agg_entry *e = prefix_agg_lookup(tbl, &pfx_normalised);
	if (!e) {
		e = prefix_agg_add(tbl, &pfx_normalised);
		if (!e)
			return LSP_ITER_STOP;
	}

	if (!e->has_min || metric < e->min_metric) {
		e->min_metric = metric;
		e->has_min = true;
	}

	return LSP_ITER_CONTINUE;
}

/*
 * Step 1~6: Aggregate L1 LSDB into a single Proxy LSP's TLVs.
 *
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

			/* This neighbor is OUTSIDE — keep it */
			isis_tlvs_add_extended_reach(
				proxy_tlvs, ISIS_MT_IPV4_UNICAST,
				reach->id, reach->metric, NULL);
		}
	}

	/* ================================================================
	 * STEP 3: IP Reachability
	 *
	 * Iterate L1 LSDB, collect all IPv4/IPv6 prefixes,
	 * choose the minimum metric for each.
	 * ================================================================ */

	{
		struct prefix_agg_table pat = {};

		/* Collect from L1 LSDB */
		struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL1 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL1 - 1], lsp)) {
			if (lsp->hdr.seqno == 0 ||
			    lsp->hdr.rem_lifetime == 0)
				continue;

			isis_lsp_iterate_ip_reach(
				lsp, AF_INET, ISIS_MT_IPV4_UNICAST,
				proxy_aggregate_ip_reach_cb, &pat);
			isis_lsp_iterate_ip_reach(
				lsp, AF_INET6, ISIS_MT_IPV4_UNICAST,
				proxy_aggregate_ip_reach_cb, &pat);
		}

		/* Write collected prefixes to Proxy LSP */
		for (int i = 0; i < pat.count; i++) {
			struct prefix_agg_entry *e = &pat.entries[i];
			if (!e->has_min)
				continue;

			if (e->prefix.family == AF_INET) {
				struct prefix_ipv4 *p4 =
					(struct prefix_ipv4 *)&e->prefix;
				isis_tlvs_add_extended_ip_reach(
					proxy_tlvs, p4, e->min_metric,
					false, NULL);
			} else if (e->prefix.family == AF_INET6) {
				/* Build a proper struct prefix_ipv6 — do not
				 * cast from struct prefix because their
				 * internal address offsets differ (8 vs 4). */
				struct prefix_ipv6 p6 = {
					.family = AF_INET6,
					.prefixlen = e->prefix.prefixlen,
					.prefix = e->prefix.u.prefix6,
				};
				isis_tlvs_add_ipv6_reach(
					proxy_tlvs, ISIS_MT_IPV4_UNICAST,
					&p6, e->min_metric, false, NULL);
			}
		}
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
	 * STEP 6: Area SID — implemented via Area Proxy TLV (Type 20).
	 * Encoded/decoded during isis_pack_tlvs/isis_unpack_tlvs.
	 * The area_sid value from area_proxy configuration is stored in
	 * the TLV and accessible to Outside Routers for SR anycast.
	 * ================================================================ */

	return proxy_tlvs;
}

/* ────────────────────────────────────────────
 * L1 SPF Reachable Set (BFS on L1 adjacency graph)
 *
 * Builds the set of sysids reachable from this router via the L1
 * adjacency graph.  This is the L1 SPF reachable set — NOT just
 * direct L1 neighbors — and is the correct basis for area-wide
 * Leader Election (RFC 9667 §4.1).
 *
 * Algorithm: BFS starting from our own sysid.
 *   - Our own L1 adjacencies provide the initial frontier.
 *   - For each remote sysid, its L1 LSP IS Reachability TLVs
 *     (both old-style and extended) provide the next frontier.
 *   - Max depth: 64 (way more than needed for any L1 area).
 * ──────────────────────────────────────────── */

#define L1_BFS_MAX_DEPTH 64

struct l1_bfs_ctx {
	struct list *visited;
	struct list *queue;
	int depth;
};

static bool l1_bfs_is_visited(struct list *visited, const uint8_t *sysid)
{
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(visited, node, node)) {
		uint8_t *v = listgetdata(node);
		if (memcmp(v, sysid, ISIS_SYS_ID_LEN) == 0)
			return true;
	}
	return false;
}

/* BFS callback: add unvisited neighbor to visited set + queue */
static int l1_bfs_cb(const uint8_t *id, uint32_t metric, bool oldmetric,
		     struct isis_ext_subtlvs *subtlvs, void *arg)
{
	struct l1_bfs_ctx *ctx = (struct l1_bfs_ctx *)arg;
	(void)metric; (void)oldmetric; (void)subtlvs;

	/* Hard stop: max 36 nodes (6×6 grid) + safety margin */
	if (ctx->depth++ > 50)
		return LSP_ITER_STOP;

	if (l1_bfs_is_visited(ctx->visited, id))
		return LSP_ITER_CONTINUE;

	uint8_t *neighbor = XMALLOC(MTYPE_TMP, ISIS_SYS_ID_LEN);
	memcpy(neighbor, id, ISIS_SYS_ID_LEN);
	listnode_add(ctx->visited, neighbor);
	listnode_add(ctx->queue, neighbor);

	return LSP_ITER_CONTINUE;
}

/*
 * Build the L1 SPF reachable set — all sysids reachable from this
 * router through the L1 adjacency graph (BFS).
 *
 * Caller must free: iterate list, XFREE each element, list_delete().
 */
static struct list *isis_l1_spf_reachable_set(struct isis_area *area)
{
	/*
	 * Two-hop BFS on L1 adjacency graph.
	 * Step 1: direct L1 neighbors → queue
	 * Step 2: each neighbor's L1 LSP IS Reachability → visited
	 *
	 * Covers R12→R22→R21 (two hops) — sufficient for 3×3 area grids.
	 * lsp_search() reads 8 bytes, pad sysid→lsp_id with \0\0.
	 */
	struct list *visited = list_new();
	struct list *queue = list_new();
	struct l1_bfs_ctx ctx = { .visited = visited, .queue = queue, .depth = 0 };

	/* Seed */
	uint8_t *self = XMALLOC(MTYPE_TMP, ISIS_SYS_ID_LEN);
	memcpy(self, area->isis->sysid, ISIS_SYS_ID_LEN);
	listnode_add(visited, self);

	/* Step 1: direct L1 adjacencies */
	if (area->circuit_list) {
		struct isis_circuit *circuit;
		struct listnode *cnode;
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if ((circuit->is_type & IS_LEVEL_1) == 0) continue;
			struct listnode *anode;
			struct isis_adjacency *adj;
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				struct list *adjdb = circuit->u.bc.adjdb[ISIS_LEVEL1 - 1];
				if (!adjdb) continue;
				for (ALL_LIST_ELEMENTS_RO(adjdb, anode, adj)) {
					if (adj->adj_state != ISIS_ADJ_UP) continue;
					if (l1_bfs_is_visited(visited, adj->sysid)) continue;
					uint8_t *n = XMALLOC(MTYPE_TMP, ISIS_SYS_ID_LEN);
					memcpy(n, adj->sysid, ISIS_SYS_ID_LEN);
					listnode_add(visited, n);
					listnode_add(queue, n);
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P && circuit->u.p2p.neighbor &&
				   circuit->u.p2p.neighbor->adj_state == ISIS_ADJ_UP) {
				const uint8_t *nsysid = circuit->u.p2p.neighbor->sysid;
				if (!l1_bfs_is_visited(visited, nsysid)) {
					uint8_t *n = XMALLOC(MTYPE_TMP, ISIS_SYS_ID_LEN);
					memcpy(n, nsysid, ISIS_SYS_ID_LEN);
					listnode_add(visited, n);
					listnode_add(queue, n);
				}
			}
		}
	}

	/* Step 2: each neighbor's L1 LSP for two-hop reachability */
	{
		struct listnode *qn;
		for (ALL_LIST_ELEMENTS_RO(queue, qn, qn)) {
			uint8_t *nsysid = listgetdata(qn);
			uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
			memcpy(lsp_id, nsysid, ISIS_SYS_ID_LEN);
			lsp_id[ISIS_SYS_ID_LEN] = 0;
			lsp_id[ISIS_SYS_ID_LEN + 1] = 0;
			struct isis_lsp *lsp = lsp_search(&area->lspdb[ISIS_LEVEL1 - 1], lsp_id);
			if (lsp && lsp->hdr.rem_lifetime && lsp->hdr.seqno && lsp->tlvs)
				isis_lsp_iterate_is_reach(lsp, ISIS_MT_IPV4_UNICAST, l1_bfs_cb, &ctx);
		}
	}

	/* Cleanup queue shell */
	while (listhead(queue)) {
		struct listnode *qn = listhead(queue);
		listnode_delete(queue, qn);
	}
	list_delete(&queue);
	return visited;
}

static void l1_spf_reachable_set_free(struct list *reachable)
{
	if (!reachable)
		return;
	struct listnode *node, *nnode;
	for (ALL_LIST_ELEMENTS(reachable, node, nnode, node)) {
		uint8_t *sysid = listgetdata(node);
		XFREE(MTYPE_TMP, sysid);
	}
	list_delete(&reachable);
}

static bool sysid_in_list(struct list *list, const uint8_t *sysid)
{
	return l1_bfs_is_visited(list, sysid);
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
 * Filters by L1 SPF reachability (BFS on L1 adjacency graph).
 * This guarantees a single area-wide leader, not per-clique leaders.
 * Winner: highest priority, ties broken by highest System ID.
 */
static bool am_i_leader(struct isis_area *area)
{
	struct isis_lsp *lsp;
	struct {
		uint8_t sysid[ISIS_SYS_ID_LEN];
		uint8_t priority;
		bool valid;
	} best = { .valid = false };

	/* Build L1 SPF reachable set once for all candidates */
	area_proxy_debug("Area Proxy: election started, local sysid=%pSY prio=%u",
			 area->isis->sysid, area->area_proxy_leader_priority);

	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp;
	     lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
		uint8_t priority = 0;
		const char *skip_reason = NULL;
		bool is_own = (memcmp(lsp->hdr.lsp_id, area->isis->sysid,
				      ISIS_SYS_ID_LEN) == 0);

		if (isis_lsp_is_proxy_lsp(lsp)) {
			skip_reason = "is proxy LSP";
			goto skip;
		}
		if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0) {
			skip_reason = "expired/purged";
			goto skip;
		}

		/* L1 SPF reachability via SPF tree */
		if (!is_own && !isis_spf_sysid_reachable(area, lsp->hdr.lsp_id)) {
			skip_reason = "L1 SPF unreachable";
			goto skip;
		}

		if (is_own)
			priority = area->area_proxy_leader_priority;
		else if (lsp->tlvs && lsp->tlvs->router_cap)
			priority = lsp->tlvs->router_cap->area_leader_priority;
		if (priority == 0) {
			skip_reason = "priority=0 (no Type 27)";
			goto skip;
		}

		if (!best.valid ||
		    priority > best.priority ||
		    (priority == best.priority &&
		     memcmp(lsp->hdr.lsp_id, best.sysid, ISIS_SYS_ID_LEN) > 0)) {
			best.priority = priority;
			memcpy(best.sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
			best.valid = true;
		}
		area_proxy_debug("Area Proxy:   candidate %pSY prio=%u reachable=yes%s",
				 lsp->hdr.lsp_id, priority,
				 is_own ? " (self)" : "");
		continue;

	skip:
		area_proxy_debug("Area Proxy:   skip    %pSY reason=%s",
				 lsp->hdr.lsp_id, skip_reason);
	}

	if (!best.valid) {
		area_proxy_debug("Area Proxy: election result — no valid candidate, default to self (LEADER)");
		return true;
	}
	bool i_am = (memcmp(best.sysid, area->isis->sysid, ISIS_SYS_ID_LEN) == 0);
	area_proxy_debug("Area Proxy: election result — winner=%pSY prio=%u i_am=%s",
			 best.sysid, best.priority, i_am ? "LEADER" : "FOLLOWER");
	return i_am;
}

/*
 * Purge our Proxy LSP (called when stepping down as leader).
 */
static void isis_area_proxy_lsp_purge(struct isis_area *area)
{
	if (!area->proxy_lsp[ISIS_LEVEL2 - 1])
		return;
	struct isis_lsp *old = area->proxy_lsp[ISIS_LEVEL2 - 1];
	zlog_info("Area Proxy: purging Proxy LSP (stepping down)");
	old->hdr.rem_lifetime = 0;
	lsp_flood(old, NULL);
	lsp_search_and_destroy(&area->lspdb[ISIS_LEVEL2 - 1],
			       old->hdr.lsp_id);
	area->proxy_lsp[ISIS_LEVEL2 - 1] = NULL;
}

/*
 * Ready Check: verify all L1 SPF-reachable Inside Routers have Area
 * Proxy information in their L2 LSPs before generating the Proxy LSP.
 *
 * Uses L1 SPF reachable set (same BFS as am_i_leader).
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

		/* Check Area Proxy TLV (Type 27) in L2 LSP */
		bool has_tlv;
		if (is_own)
			has_tlv = (area->area_proxy_leader_priority > 0);
		else
			has_tlv = (lsp->tlvs && lsp->tlvs->router_cap &&
				   lsp->tlvs->router_cap->area_leader_priority > 0);

		if (!has_tlv) {
			area_proxy_debug("Area Proxy: not ready — %pLS missing Type 27 (L1-SPF-reachable)",
					 lsp->hdr.lsp_id);
			return false;
		}
	}

	return true;
}

/* ────────────────────────────────────────────
 * Proxy LSP Generation
 * ──────────────────────────────────────────── */

/*
 * Timer callback for scheduled Proxy LSP regeneration.
 */
static void isis_area_proxy_lsp_regenerate_timer(struct thread *t)
{
	struct isis_area *area = THREAD_ARG(t);

	area->t_proxy_lsp_refresh = NULL;

	/*
	 * Re-evaluate boundary circuits: during startup, circuits may
	 * not have existed when isis_area_proxy_enable() ran, and L2
	 * adjacencies may come up before L1.  Now that the L1 LSDB has
	 * had time to converge, fix both directions.
	 */
	{
		struct isis_circuit *circuit;
		struct listnode *cnode;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			/* First: mark missed boundary circuits */
			if (!circuit->is_area_proxy_boundary &&
			    (area->is_type & IS_LEVEL_1) &&
			    circuit->is_type == IS_LEVEL_2) {
				circuit->is_area_proxy_boundary = true;
				zlog_info("Area Proxy: circuit %s marked as boundary (L2-only on L1L2 router)",
					  circuit->interface->name);
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
					zlog_info("Area Proxy: circuit %s marked as boundary",
						  circuit->interface->name);
					continue;
				}
			}
			/* Then: unmark false positives */
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
			if (has_l1) {
				circuit->is_area_proxy_boundary = false;
				zlog_info("Area Proxy: circuit %s unmarked as boundary (has L1 neighbor)",
					  circuit->interface->name);
			}
		}
	}

	/*
	 * Cache edge-router flag on Inside L2 LSPs.
	 * Rather than querying the L1 LSDB on every flood (which may
	 * be empty at startup), we compute once after convergence and
	 * store the result in lsp->is_edge_router.
	 * An Inside LSP is an edge router iff it has at least one
	 * IS neighbor NOT in the L1 LSDB (i.e., an Outside neighbor).
	 */
	{
		struct isis_lsp *lsp;
	for (lsp = lspdb_first(&area->lspdb[ISIS_LEVEL2 - 1]); lsp; lsp = lspdb_next(&area->lspdb[ISIS_LEVEL2 - 1], lsp)) {
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

	zlog_debug("Area Proxy: timer fired, area %s (leader_election=%d)",
		   area->area_tag, area->area_proxy_leader_election);
	area_proxy_debug("Area Proxy: timer fired, area %s, leader_election=%d",
			 area->area_tag, area->area_proxy_leader_election);

	/* ── Leader Election / Distributed generation ── */
	if (area->area_proxy_leader_election) {
		bool was_leader = (area->proxy_lsp[ISIS_LEVEL2 - 1] != NULL);
		bool is_leader = am_i_leader(area);

		if (is_leader) {
			if (!was_leader) {
				zlog_info("Area Proxy: elected as LEADER (priority %u)",
					  area->area_proxy_leader_priority);
				area->ap_leader_changes++;
			}

			/* Ready Check: all L1-reachable nodes have Area Proxy TLV? */
			if (!isis_area_proxy_ready(area)) {
				zlog_info("Area Proxy: not ready, deferring generation");
				area_proxy_debug("Area Proxy: NOT READY — deferring generation");
				if (area->area_proxy_ready_count > 0)
					area->ap_ready_changes++;
				area->area_proxy_ready_count = 0;
			} else {
				area->area_proxy_ready_count++;
				/* Debounce: require 2 consecutive ready checks */
				if (area->area_proxy_ready_count >= 2) {
					isis_area_proxy_lsp_generate(area);
					area->area_proxy_last_gen_time = monotime(NULL);
					area->area_proxy_ready_count = 0;
				} else {
					area_proxy_debug("Area Proxy: ready check %u/2 passed",
							 area->area_proxy_ready_count);
				}
			}
		} else {
			area->area_proxy_ready_count = 0;
			if (was_leader) {
				zlog_info("Area Proxy: stepped down as LEADER");
				area_proxy_debug("Area Proxy: stepped down as LEADER");
				area->ap_leader_changes++;
				isis_area_proxy_lsp_purge(area);
				area->area_proxy_last_gen_time = 0;
			}
		}
	} else {
		/* Distributed mode: always generate */
		isis_area_proxy_lsp_generate(area);
	}

	/* Reschedule */
	{
		uint32_t reschedule_sec;
		if (area->area_proxy_leader_election)
			reschedule_sec = area->area_proxy_elect_check_sec ?
					 area->area_proxy_elect_check_sec : 30;
		else
			reschedule_sec = area->lsp_refresh[ISIS_LEVEL2 - 1] ?
					 area->lsp_refresh[ISIS_LEVEL2 - 1] : 900;
		thread_add_timer(master, isis_area_proxy_lsp_regenerate_timer,
				 area, reschedule_sec, &area->t_proxy_lsp_refresh);
	}
}

/*
 * Generate (or regenerate) the Proxy LSP from aggregated TLVs,
 * then flood it to all L2 neighbors.
 */
int isis_area_proxy_lsp_generate(struct isis_area *area)
{
	struct isis_lsp *lsp;
	struct isis_tlvs *tlvs;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];

	if (!area || !area->area_proxy_enabled)
		return -1;

	/* Ensure lsp_mtu is initialized before first Proxy LSP generation.
	 * During config parsing, area->lsp_mtu may still be 0, causing
	 * lsp_adjust_stream() to create a stream too small for TLVs. */
	if (area->lsp_mtu == 0)
		area->lsp_mtu = DEFAULT_LSP_MTU;

	/* Check if proxy_sysid is configured */
	bool sysid_zero = true;
	for (int i = 0; i < ISIS_SYS_ID_LEN; i++) {
		if (area->area_proxy_sysid[i] != 0) {
			sysid_zero = false;
			break;
		}
	}
	if (sysid_zero) {
		zlog_warn("Area Proxy: cannot generate Proxy LSP, "
			  "proxy-sysid is not configured");
		return -1;
	}

	/* Aggregate L1 LSDB into Proxy TLVs */
	tlvs = isis_area_proxy_aggregate_tlvs(area);
	if (!tlvs) {
		zlog_warn("Area Proxy: aggregation returned NULL TLVs");
		return -1;
	}

	/* Build LSP ID: proxy_sysid + pseudo_id=0 + frag_id=0 */
	memcpy(lsp_id, area->area_proxy_sysid, ISIS_SYS_ID_LEN);
	lsp_id[ISIS_SYS_ID_LEN] = 0;     /* pseudo ID */
	lsp_id[ISIS_SYS_ID_LEN + 1] = 0; /* fragment ID */

	/* Remove old Proxy LSP from LSDB if it exists, remembering
	 * its seqno so we can increment (normal LSPs auto-increment). */
	uint32_t new_seqno = 1;
	if (area->proxy_lsp[ISIS_LEVEL2 - 1]) {
		struct isis_lsp *old = area->proxy_lsp[ISIS_LEVEL2 - 1];
		new_seqno = old->hdr.seqno + 1;
		lsp_search_and_destroy(&area->lspdb[ISIS_LEVEL2 - 1],
				       old->hdr.lsp_id);
		area->proxy_lsp[ISIS_LEVEL2 - 1] = NULL;

		zlog_debug("Area Proxy: removed old Proxy LSP from LSDB");
	}

	/* Create new Proxy LSP */
	lsp = lsp_new(area, lsp_id,
		      area->max_lsp_lifetime[ISIS_LEVEL2 - 1],
		      new_seqno,          /* increment seqno on re-gen */
		      IS_LEVEL_1_AND_2,  /* lsp_bits: L1L2-capable */
		      0,                 /* checksum (computed later) */
		      NULL,              /* lsp0 */
		      ISIS_LEVEL2);
	if (!lsp) {
		isis_free_tlvs(tlvs);
		return -1;
	}

	lsp->tlvs = tlvs;
	lsp->own_lsp = 0; /* not "our own" LSP */
	area->proxy_lsp[ISIS_LEVEL2 - 1] = lsp;

	/* Build the PDU from our aggregated TLVs BEFORE inserting into LSDB.
	 * Use lsp_pack_pdu_ext — the exact same code path that normal LSPs
	 * use, which is known to produce correct checksums. */
	lsp_pack_pdu_ext(lsp);

	/* Insert into L2 LSDB */
	lsp_insert(&area->lspdb[ISIS_LEVEL2 - 1], lsp);

	zlog_info("Area Proxy: generated/regenerated Proxy LSP %pLS, pdu_len=%u",
		  lsp_id, lsp->hdr.pdu_len);
	area_proxy_debug("Area Proxy: Proxy LSP generated, pdu_len=%u seqno=0x%08x",
			 lsp->hdr.pdu_len, lsp->hdr.seqno);
	area->ap_lsp_gen_count++;

	/* Flood to all L2 circuits */
	{
		struct isis_circuit *circuit;
		struct listnode *cnode;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (circuit->is_passive)
				continue;
			lsp_flood(lsp, circuit);
		}
	}

	return 0;
}

/*
 * Schedule a (delayed) regeneration of the Proxy LSP.
 * Should be called after L1 topology changes to batch updates.
 */
void isis_area_proxy_lsp_regenerate_schedule(struct isis_area *area)
{
	uint32_t delay;

	if (!area || !area->area_proxy_enabled)
		return;

	/* If a timer is already pending, leave it */
	if (area->t_proxy_lsp_refresh)
		return;

	/* In leader election mode, use election check interval.
	 * In distributed mode, use short delay to batch topology changes. */
	if (area->area_proxy_leader_election)
		delay = area->area_proxy_elect_check_sec ?
			area->area_proxy_elect_check_sec : 30;
	else
		delay = 2;

	thread_add_timer(master,
			isis_area_proxy_lsp_regenerate_timer,
			area, delay, &area->t_proxy_lsp_refresh);

	zlog_debug("Area Proxy: scheduled Proxy LSP regeneration (delay=%us, mode=%s)",
		   delay, area->area_proxy_leader_election ? "election" : "distributed");
}

/*
 * Event-driven election trigger. Called when L1 adjacency state changes
 * or L2 LSDB is updated. Schedules a shorter-timer re-evaluation so that
 * leader changes are detected promptly (not waiting for the next periodic
 * timer tick).
 */
void isis_area_proxy_schedule_election(struct isis_area *area, const char *reason)
{
	if (!area || !area->area_proxy_enabled || !area->area_proxy_leader_election)
		return;

	area_proxy_debug("Area Proxy: election scheduled (reason: %s)", reason);

	/* Cancel any existing timer so we can re-schedule immediately */
	if (area->t_proxy_lsp_refresh)
		THREAD_OFF(area->t_proxy_lsp_refresh);

	/* Use half the normal interval for event-driven re-eval */
	uint32_t delay = area->area_proxy_elect_check_sec ?
			 area->area_proxy_elect_check_sec / 2 : 15;
	if (delay < 5)
		delay = 5;

	thread_add_timer(master, isis_area_proxy_lsp_regenerate_timer,
			 area, delay, &area->t_proxy_lsp_refresh);
}

/* ── isis_lsp_is_proxy_lsp: 8.4 implementation (was in isis_lsp.c on 10.7) ── */
bool isis_lsp_is_proxy_lsp(const struct isis_lsp *lsp)
{
	if (!lsp || !lsp->area)
		return false;
	if (!lsp->area->area_proxy_enabled)
		return false;

	/*
	 * RFC 9666: Proxy SysIDs use the format ffff.0000.XXXX where
	 * the first 6 bytes are always 0xff 0xff 0x00 0x00 0x00.
	 * We match any Proxy LSP, not just this Area's own, so that
	 * foreign Proxy LSPs are correctly classified as PROXY (rather
	 * than OUTSIDE_REAL) and flood without restriction.
	 */
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
	bool is_boundary = circuit->is_area_proxy_boundary
			|| circuit->is_type == IS_LEVEL_2;

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

/* ── 8.4: Router Capability init for Area Proxy Step 4 ── */
struct isis_router_cap *isis_tlvs_init_router_capability(struct isis_tlvs *tlvs)
{
	tlvs->router_cap = calloc(1, sizeof(struct isis_router_cap));
	if (tlvs->router_cap)
		tlvs->router_cap->router_id.s_addr = INADDR_ANY;
	return tlvs->router_cap;
}

/* lsp_pack_pdu_ext() is implemented in isis_lsp.c */

