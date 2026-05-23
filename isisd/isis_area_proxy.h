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

/* For show commands */
extern void isis_area_proxy_show(struct vty *vty, const struct isis_area *area);

#endif /* ISIS_AREA_PROXY_H */
