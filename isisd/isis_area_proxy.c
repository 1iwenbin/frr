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
			/* L2-only circuits on L1L2-capable routers are boundaries */
			if ((area->is_type & IS_LEVEL_1) &&
			    circuit->is_type == IS_LEVEL_2) {
				circuit->is_area_proxy_boundary = true;
				zlog_info("Area Proxy: circuit %s marked as boundary (L2-only on L1L2 router)",
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

	/* Generate Proxy LSP if sysid is already configured */
	bool sysid_zero = true;
	for (int i = 0; i < ISIS_SYS_ID_LEN; i++) {
		if (area->area_proxy_sysid[i] != 0) {
			sysid_zero = false;
			break;
		}
	}
	if (!sysid_zero)
		isis_area_proxy_lsp_generate(area);
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

void isis_area_proxy_show(struct vty *vty, const struct isis_area *area)
{
	if (!area) {
		vty_out(vty, "No IS-IS instance configured\n");
		return;
	}

	vty_out(vty, "Area Proxy (RFC 9666): %s\n",
		area->area_proxy_enabled ? "Enabled" : "Disabled");

	if (area->area_proxy_enabled) {
		vty_out(vty, "  Proxy System ID: %pSY\n",
			area->area_proxy_sysid);
		if (area->area_proxy_sid)
			vty_out(vty, "  Area SID: %u\n",
				area->area_proxy_sid);
		if (area->proxy_lsp[ISIS_LEVEL2 - 1])
			vty_out(vty, "  Proxy LSP: present\n");
		else
			vty_out(vty, "  Proxy LSP: not generated\n");
	}
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

	/* Generate Proxy LSP now that sysid is configured */
	isis_area_proxy_lsp_generate(area);

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
		isis_tlvs_add_area_addresses(proxy_tlvs, &area->area_addrs);

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
	 * Re-evaluate boundary circuits: during startup, L2 adjacencies
	 * may come up before L1, causing Inside circuits to be incorrectly
	 * marked as boundary.  Now that the L1 LSDB has had time to
	 * converge, unmark circuits that have L1 neighbors.
	 */
	{
		struct isis_circuit *circuit;
		struct listnode *cnode;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
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

	zlog_debug("Area Proxy: timer fired, regenerating Proxy LSP for area %s",
		   area->area_tag);

	isis_area_proxy_lsp_generate(area);
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
		lspdb_del(&area->lspdb[ISIS_LEVEL2 - 1], old);
		fabricd_lsp_free(old);
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
	if (!area || !area->area_proxy_enabled)
		return;

	/* If a timer is already pending, leave it */
	if (area->t_proxy_lsp_refresh)
		return;

	/* Schedule regeneration after a short delay (2 seconds)
	 * to batch multiple L1 topology changes */
	thread_add_timer(master,
			isis_area_proxy_lsp_regenerate_timer,
			area, 2, &area->t_proxy_lsp_refresh);

	zlog_debug("Area Proxy: scheduled Proxy LSP regeneration for area %s",
		   area->area_tag);
}

/* ── isis_lsp_is_proxy_lsp: 8.4 implementation (was in isis_lsp.c on 10.7) ── */
bool isis_lsp_is_proxy_lsp(const struct isis_lsp *lsp)
{
	if (!lsp || !lsp->area)
		return false;
	if (!lsp->area->area_proxy_enabled)
		return false;

	return (memcmp(lsp->hdr.lsp_id, lsp->area->area_proxy_sysid,
		       ISIS_SYS_ID_LEN) == 0);
}

/* ── 8.4 stub: Router Capability init not needed for core functionality ── */
void isis_tlvs_init_router_capability(struct isis_tlvs *tlvs)
{
	/* Router Capability TLV aggregation (Step 4) skipped in 8.4 */
	struct isis_router_cap *cap = &tlvs->router_cap;
	memset(cap, 0, sizeof(*cap));
	cap->router_id.s_addr = INADDR_ANY;
}

/* ── 8.4 stub: lsp_pack_pdu_ext (was in isis_lsp.c on 10.7) ── */
void lsp_pack_pdu_ext(struct isis_lsp *lsp)
{
	/* LSP PDU packing handled by lsp_generate path in 8.4 */
	if (!lsp)
		return;
	if (lsp->pdu)
		stream_free(lsp->pdu);
	lsp->pdu = NULL;
}
