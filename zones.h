/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __FW3_ZONES_H
#define __FW3_ZONES_H

#include "options.h"
#include "iptables.h"

/* 32 - sizeof("postrouting_") - sizeof("_rule") - sizeof("\0") */
#define FW3_ZONE_MAXNAMELEN 14

extern const struct fw3_option fw3_zone_opts[];

struct fw3_zone * fw3_alloc_zone(void);

void fw3_load_zones(struct fw3_state *state, struct uci_package *p);

void fw3_print_zone_chains(struct fw3_ipt_handle *handle,
                           struct fw3_state *state, bool reload);

void fw3_print_zone_rules(struct fw3_ipt_handle *handle,
                          struct fw3_state *state, bool reload);

void fw3_flush_zones(struct fw3_ipt_handle *handle, struct fw3_state *state,
                     bool reload);

void fw3_hotplug_zones(struct fw3_state *state, bool add);

struct fw3_zone * fw3_lookup_zone(struct fw3_state *state, const char *name);

struct list_head * fw3_resolve_zone_addresses(struct fw3_zone *zone);

#define fw3_free_zone(zone) \
	fw3_free_object(zone, fw3_zone_opts)

#define fw3_to_src_target(t) \
	(FW3_FLAG_SRC_ACCEPT - FW3_FLAG_ACCEPT + t)

#endif
