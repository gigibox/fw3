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

extern const struct fw3_option fw3_zone_opts[];

struct fw3_zone * fw3_alloc_zone(void);

void fw3_load_zones(struct fw3_state *state, struct uci_package *p);

void fw3_print_zone_chains(enum fw3_table table, enum fw3_family family,
                           struct fw3_state *state);

void fw3_print_zone_rules(enum fw3_table table, enum fw3_family family,
                          struct fw3_state *state);

void fw3_flush_zones(enum fw3_table table, enum fw3_family family,
                     bool pass2, struct fw3_state *state);

struct fw3_zone * fw3_lookup_zone(struct fw3_state *state, const char *name,
                                  bool running);

#define fw3_free_zone(zone) \
	fw3_free_object(zone, fw3_zone_opts)

#endif
