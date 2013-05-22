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

#include <linux/netfilter/ipset/ip_set.h>

#include "options.h"
#include "utils.h"


extern const struct fw3_option fw3_ipset_opts[];

struct fw3_ipset * fw3_alloc_ipset(void);
void fw3_load_ipsets(struct fw3_state *state, struct uci_package *p);
void fw3_create_ipsets(struct fw3_state *state);
void fw3_destroy_ipsets(struct fw3_state *state);

struct fw3_ipset * fw3_lookup_ipset(struct fw3_state *state, const char *name);

bool fw3_check_ipset(struct fw3_ipset *set);

#define fw3_free_ipset(ipset) \
	fw3_free_object(ipset, fw3_ipset_opts)


#ifndef SO_IP_SET

#define SO_IP_SET           83
#define IPSET_MAXNAMELEN    32
#define IPSET_INVALID_ID    65535

union ip_set_name_index {
    char name[IPSET_MAXNAMELEN];
    uint16_t index;
};

#define IP_SET_OP_GET_BYNAME    0x00000006
struct ip_set_req_get_set {
    uint32_t op;
    uint32_t version;
    union ip_set_name_index set;
};

#define IP_SET_OP_VERSION       0x00000100
struct ip_set_req_version {
    uint32_t op;
    uint32_t version;
};

#endif /* SO_IP_SET */

#endif
