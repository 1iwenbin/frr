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

void isis_area_proxy_enable(struct isis_area *area)
{
	if (!area || area->area_proxy_enabled)
		return;

	area->area_proxy_enabled = true;

	zlog_info("Area Proxy: enabled on area %s (proxy-sysid: %pIS)",
		  area->area_tag, area->area_proxy_sysid);

	/* Schedule LSP regeneration to include Area Proxy TLV */
	lsp_regenerate_schedule(area, ISIS_LEVEL2, 0);
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
		vty_out(vty, "  Proxy System ID: %pIS\n",
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
