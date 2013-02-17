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

#ifndef __FW3_IPSETS_H
#define __FW3_IPSETS_H

#include "options.h"
#include "utils.h"

enum fw3_ipset_opts {
	FW3_IPSET_OPT_IPRANGE   = (1 << 0),
	FW3_IPSET_OPT_PORTRANGE = (1 << 1),
	FW3_IPSET_OPT_NETMASK   = (1 << 2),
	FW3_IPSET_OPT_HASHSIZE  = (1 << 3),
	FW3_IPSET_OPT_MAXELEM   = (1 << 4),
	FW3_IPSET_OPT_FAMILY    = (1 << 5),
};

struct fw3_ipset_settype {
	enum fw3_ipset_method method;
	uint32_t types;
	uint8_t required;
	uint8_t optional;
};

void fw3_load_ipsets(struct fw3_state *state, struct uci_package *p);
void fw3_create_ipsets(struct fw3_state *state);
void fw3_destroy_ipsets(struct fw3_state *state);

void fw3_free_ipset(struct fw3_ipset *ipset);

struct fw3_ipset * fw3_lookup_ipset(struct fw3_state *state, const char *name);

#endif
