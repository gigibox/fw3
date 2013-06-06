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

#include <dlfcn.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/utsname.h>

#include "options.h"

/* xtables interface */
#if (XTABLES_VERSION_CODE == 10)
# include "xtables-10.h"
#elif (XTABLES_VERSION_CODE == 5)
# include "xtables-5.h"
#else
# error "Unsupported xtables version"
#endif

/* libext.a interface */
#define FW3_IPT_MODULES			\
	__ipt_module(comment)		\
	__ipt_module(conntrack)		\
	__ipt_module(icmp)			\
	__ipt_module(icmp6)			\
	__ipt_module(limit)			\
	__ipt_module(mac)			\
	__ipt_module(mark)			\
	__ipt_module(set)			\
	__ipt_module(standard)		\
	__ipt_module(tcp)			\
	__ipt_module(time)			\
	__ipt_module(udp)			\
	__ipt_module(CT)			\
	__ipt_module(DNAT)			\
	__ipt_module(LOG)			\
	__ipt_module(MARK)			\
	__ipt_module(MASQUERADE)	\
	__ipt_module(REDIRECT)		\
	__ipt_module(REJECT)		\
	__ipt_module(SET)			\
	__ipt_module(SNAT)			\
	__ipt_module(TCPMSS)

#ifdef DISABLE_IPV6
#undef __ipt_module
#define __ipt_module(x) \
	extern void libxt_##x##_init(void) __attribute__((weak)); \
	extern void libipt_##x##_init(void) __attribute__((weak));
#else
#undef __ipt_module
#define __ipt_module(x) \
	extern void libxt_##x##_init(void) __attribute__((weak)); \
	extern void libipt_##x##_init(void) __attribute__((weak)); \
	extern void libip6t_##x##_init(void) __attribute__((weak));
#endif

FW3_IPT_MODULES


/* Required by certain extensions like SNAT and DNAT */
extern int kernel_version;
void get_kernel_version(void);

struct fw3_ipt_handle {
	enum fw3_family family;
	enum fw3_table table;
	void *handle;

	int libc;
	void **libv;
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


void fw3_ipt_flush_chain(struct fw3_ipt_handle *h, const char *chain);
void fw3_ipt_delete_chain(struct fw3_ipt_handle *h, const char *chain);

void fw3_ipt_create_chain(struct fw3_ipt_handle *h, const char *fmt, ...);

void fw3_ipt_flush(struct fw3_ipt_handle *h);

void fw3_ipt_commit(struct fw3_ipt_handle *h);

void fw3_ipt_close(struct fw3_ipt_handle *h);

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

void fw3_ipt_rule_ipset(struct fw3_ipt_rule *r, struct fw3_setmatch *match);

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

void __fw3_ipt_rule_append(struct fw3_ipt_rule *r, bool repl,
                           const char *fmt, ...);

#define fw3_ipt_rule_append(rule, ...) \
	__fw3_ipt_rule_append(rule, false, __VA_ARGS__)

#define fw3_ipt_rule_replace(rule, ...) \
	__fw3_ipt_rule_append(rule, true, __VA_ARGS__)

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
