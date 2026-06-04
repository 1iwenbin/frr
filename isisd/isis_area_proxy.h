/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 oaemu contributors
 *
 * IS-IS Area Proxy (RFC 9666)
 */

#ifndef ISIS_AREA_PROXY_H
#define ISIS_AREA_PROXY_H

#include "isisd/isisd.h"
#include "isisd/isis_tlvs.h"

/* Function declarations */
extern void isis_area_proxy_enable(struct isis_area *area);
extern void isis_area_proxy_disable(struct isis_area *area);
extern bool isis_area_proxy_is_enabled(const struct isis_area *area);
extern const uint8_t *isis_area_proxy_get_sysid(const struct isis_area *area);

extern int isis_area_proxy_set_sysid(struct isis_area *area,
				     const char *sysid_str);
extern int isis_area_proxy_set_sid(struct isis_area *area, uint32_t sid);
extern int isis_area_proxy_unset_sid(struct isis_area *area);

/* Aggregation and LSP generation */
extern struct isis_tlvs *isis_area_proxy_aggregate_tlvs(struct isis_area *area);
extern int isis_area_proxy_lsp_generate(struct isis_area *area);

/* Proxy LSP identification (declared in isis_lsp.h, implemented here) */
extern bool isis_lsp_is_proxy_lsp(const struct isis_lsp *lsp);
extern bool isis_area_proxy_lsp_is_inside_real(const struct isis_lsp *lsp);

/* ── Reconciler: single-entry trigger model ── */
enum area_proxy_reason {
	AP_REASON_ADJ_CHANGE    = (1 << 0),  /* L1 adjacency UP/DOWN */
	AP_REASON_LSP_CHANGE    = (1 << 1),  /* L1/L2 LSDB insert/update */
	AP_REASON_CONFIG_CHANGE = (1 << 2),  /* CLI: mode/priority/sysid change */
	AP_REASON_INITIAL       = (1 << 3),  /* area-proxy enable */
	AP_REASON_PERIODIC      = (1 << 4),  /* periodic refresh timer */
};

extern void isis_area_proxy_schedule_reconcile(struct isis_area *area,
					       uint32_t reason);

/* Three-state LSP scope classification for flooding decisions */
enum area_proxy_lsp_scope {
	AP_LSP_SCOPE_PROXY,
	AP_LSP_SCOPE_INSIDE_REAL,
	AP_LSP_SCOPE_OUTSIDE_REAL,
	AP_LSP_SCOPE_UNCLASSIFIED,
};

extern enum area_proxy_lsp_scope
isis_area_proxy_lsp_classify(const struct isis_lsp *lsp);
extern bool isis_area_proxy_lsp_should_flood(const struct isis_lsp *lsp,
					     struct isis_circuit *circuit);

/* Check if System ID belongs to an Inside Router (exists in L1 LSDB) */
extern bool isis_sysid_in_l1_lsdb(struct isis_area *area, const uint8_t *sysid);

/* Check if an LSP ID matches the Proxy LSP prefix (ffff.0000.00xx) */
extern bool isis_lsp_id_is_proxy_lsp(const uint8_t *lsp_id);

/*
 * Circuit role helpers for Area Proxy.
 *
 * Deployment convention (SatStripe):
 *   AP inside circuit  := IS-IS Level-1-2 circuit
 *   AP outside circuit := IS-IS Level-2-only circuit
 *
 * This is an implementation/deployment convention, not a generic IS-IS
 * semantic.  All code should use these helpers rather than testing
 * circuit->is_type directly.
 */
extern bool isis_area_proxy_circuit_is_outside(
	const struct isis_circuit *circuit);
extern bool isis_area_proxy_circuit_is_inside(
	const struct isis_circuit *circuit);

/* For show commands */
extern void isis_area_proxy_show(struct vty *vty, const struct isis_area *area);
extern void isis_area_proxy_show_election(struct vty *vty, struct isis_area *area);
extern void isis_area_proxy_show_ready(struct vty *vty, struct isis_area *area);
extern void isis_area_proxy_show_lsp(struct vty *vty, struct isis_area *area);
extern void isis_area_proxy_show_misconfig(struct vty *vty, struct isis_area *area);

#endif /* ISIS_AREA_PROXY_H */
