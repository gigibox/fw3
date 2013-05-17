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

#ifndef __FW3_IPTABLES_H
#define __FW3_IPTABLES_H

#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <xtables.h>

#include <unistd.h>
#include <getopt.h>
#include <sys/utsname.h>

#include "options.h"


extern struct xtables_match *xtables_pending_matches;
extern struct xtables_target *xtables_pending_targets;

/* libext.a interface */
void libip6t_icmp6_init(void);
void libip6t_LOG_init(void);
void libipt_DNAT_init(void);
void libipt_icmp_init(void);
void libipt_LOG_init(void);
void libipt_MASQUERADE_init(void);
void libipt_REDIRECT_init(void);
void libipt_REJECT_init(void);
void libipt_SNAT_init(void);
void libxt_comment_init(void);
void libxt_conntrack_init(void);
void libxt_CT_init(void);
void libxt_limit_init(void);
void libxt_mac_init(void);
void libxt_mark_init(void);
void libxt_MARK_init(void);
void libxt_set_init(void);
void libxt_SET_init(void);
void libxt_standard_init(void);
void libxt_TCPMSS_init(void);
void libxt_tcp_init(void);
void libxt_time_init(void);
void libxt_udp_init(void);

/* Required by certain extensions like SNAT and DNAT */
extern int kernel_version;
void get_kernel_version(void);

struct fw3_ipt_handle {
	enum fw3_family family;
	enum fw3_table table;
	struct xtc_handle *handle;
};

struct fw3_ipt_rule {
	struct fw3_ipt_handle *h;

	union {
		struct ipt_entry e;
		struct ip6t_entry e6;
	};

	struct xtables_rule_match *matches;
	struct xtables_target *target;

	int argc;
	char **argv;

	uint32_t protocol;
	bool protocol_loaded;
};

struct fw3_ipt_handle *fw3_ipt_open(enum fw3_family family,
                                    enum fw3_table table);

void fw3_ipt_set_policy(struct fw3_ipt_handle *h, const char *chain,
                        enum fw3_flag policy);

void fw3_ipt_delete_chain(struct fw3_ipt_handle *h, const char *chain);
void fw3_ipt_delete_rules(struct fw3_ipt_handle *h, const char *target);

void fw3_ipt_create_chain(struct fw3_ipt_handle *h, const char *fmt, ...);

void fw3_ipt_flush(struct fw3_ipt_handle *h);

void fw3_ipt_commit(struct fw3_ipt_handle *h);

struct fw3_ipt_rule *fw3_ipt_rule_new(struct fw3_ipt_handle *h);

void fw3_ipt_rule_proto(struct fw3_ipt_rule *r, struct fw3_protocol *proto);

void fw3_ipt_rule_in_out(struct fw3_ipt_rule *r,
                         struct fw3_device *in, struct fw3_device *out);

void fw3_ipt_rule_src_dest(struct fw3_ipt_rule *r,
                           struct fw3_address *src, struct fw3_address *dest);

void fw3_ipt_rule_sport_dport(struct fw3_ipt_rule *r,
                              struct fw3_port *sp, struct fw3_port *dp);

void fw3_ipt_rule_mac(struct fw3_ipt_rule *r, struct fw3_mac *mac);

void fw3_ipt_rule_icmptype(struct fw3_ipt_rule *r, struct fw3_icmptype *icmp);

void fw3_ipt_rule_limit(struct fw3_ipt_rule *r, struct fw3_limit *limit);

void fw3_ipt_rule_ipset(struct fw3_ipt_rule *r, struct fw3_ipset *ipset,
                        bool invert);

void fw3_ipt_rule_time(struct fw3_ipt_rule *r, struct fw3_time *time);

void fw3_ipt_rule_mark(struct fw3_ipt_rule *r, struct fw3_mark *mark);

void fw3_ipt_rule_comment(struct fw3_ipt_rule *r, const char *fmt, ...);

void fw3_ipt_rule_extra(struct fw3_ipt_rule *r, const char *extra);

void fw3_ipt_rule_addarg(struct fw3_ipt_rule *r, bool inv,
                         const char *k, const char *v);

struct fw3_ipt_rule * fw3_ipt_rule_create(struct fw3_ipt_handle *handle,
                                          struct fw3_protocol *proto,
                                          struct fw3_device *in,
                                          struct fw3_device *out,
                                          struct fw3_address *src,
                                          struct fw3_address *dest);

void fw3_ipt_rule_append(struct fw3_ipt_rule *r, const char *fmt, ...);

static inline void
fw3_ipt_rule_target(struct fw3_ipt_rule *r, const char *fmt, ...)
{
	va_list ap;
	char buf[32];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	fw3_ipt_rule_addarg(r, false, "-j", buf);
}

#endif
