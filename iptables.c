/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jo@mein.io>
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

#define _GNU_SOURCE /* RTLD_NEXT */

/* include userspace headers */
#include <dlfcn.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <sys/socket.h>

/* prevent indirect inclusion of kernel headers */
#define _LINUX_IF_H
#define _LINUX_IN_H
#define _LINUX_IN6_H

/* prevent libiptc from including kernel headers */
#define _FWCHAINS_KERNEL_HEADERS_H

/* finally include libiptc and xtables */
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <xtables.h>

#include <setjmp.h>

#include "options.h"

/* xtables interface */
#if (XTABLES_VERSION_CODE >= 10)
# include "xtables-10.h"
#elif (XTABLES_VERSION_CODE == 5)
# include "xtables-5.h"
#else
# error "Unsupported xtables version"
#endif

#include "iptables.h"


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

static struct option base_opts[] = {
	{ .name = "match",  .has_arg = 1, .val = 'm' },
	{ .name = "jump",   .has_arg = 1, .val = 'j' },
	{ NULL }
};


static jmp_buf fw3_ipt_error_jmp;

static __attribute__((noreturn))
void fw3_ipt_error_handler(enum xtables_exittype status,
                           const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, "     ! Exception: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	longjmp(fw3_ipt_error_jmp, status);
}

static struct xtables_globals xtg = {
	.option_offset = 0,
	.program_version = "4",
	.orig_opts = base_opts,
	.exit_err = fw3_ipt_error_handler,
#if XTABLES_VERSION_CODE > 10
	.compat_rev = xtables_compatible_revision,
#endif
};

static struct xtables_globals xtg6 = {
	.option_offset = 0,
	.program_version = "6",
	.orig_opts = base_opts,
	.exit_err = fw3_ipt_error_handler,
#if XTABLES_VERSION_CODE > 10
	.compat_rev = xtables_compatible_revision,
#endif
};

static struct {
	bool retain;
	int mcount, tcount;
	struct xtables_match **matches;
	struct xtables_target **targets;
	void (*register_match)(struct xtables_match *);
	void (*register_target)(struct xtables_target *);
} xext;


/* Required by certain extensions like SNAT and DNAT */
int kernel_version = 0;

void
get_kernel_version(void)
{
	static struct utsname uts;
	int x = 0, y = 0, z = 0;

	if (uname(&uts) == -1)
		sprintf(uts.release, "3.0.0");

	sscanf(uts.release, "%d.%d.%d", &x, &y, &z);
	kernel_version = 0x10000 * x + 0x100 * y + z;
}

static void fw3_init_extensions(void)
{
	init_extensions();
	init_extensions4();

#ifndef DISABLE_IPV6
	init_extensions6();
#endif
}

struct fw3_ipt_handle *
fw3_ipt_open(enum fw3_family family, enum fw3_table table)
{
	int i;
	struct fw3_ipt_handle *h;

	h = fw3_alloc(sizeof(*h));

	xtables_init();

	if (family == FW3_FAMILY_V6)
	{
#ifndef DISABLE_IPV6
		h->family = FW3_FAMILY_V6;
		h->table  = table;
		h->handle = ip6tc_init(fw3_flag_names[table]);

		xtables_set_params(&xtg6);
		xtables_set_nfproto(NFPROTO_IPV6);
#endif
	}
	else
	{
		h->family = FW3_FAMILY_V4;
		h->table  = table;
		h->handle = iptc_init(fw3_flag_names[table]);

		xtables_set_params(&xtg);
		xtables_set_nfproto(NFPROTO_IPV4);
	}

	if (!h->handle)
	{
		free(h);
		return NULL;
	}

	fw3_xt_reset();
	fw3_init_extensions();

	if (xext.register_match)
		for (i = 0; i < xext.mcount; i++)
			xext.register_match(xext.matches[i]);

	if (xext.register_target)
		for (i = 0; i < xext.tcount; i++)
			xext.register_target(xext.targets[i]);

	return h;
}

static void
debug(struct fw3_ipt_handle *h, const char *fmt, ...)
{
	va_list ap;

	printf("%s -t %s ", (h->family == FW3_FAMILY_V6) ? "ip6tables" : "iptables",
	                    fw3_flag_names[h->table]);

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void
fw3_ipt_set_policy(struct fw3_ipt_handle *h, const char *chain,
                   enum fw3_flag policy)
{
	if (fw3_pr_debug)
		debug(h, "-P %s %s\n", chain, fw3_flag_names[policy]);

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
		ip6tc_set_policy(chain, fw3_flag_names[policy], NULL, h->handle);
	else
#endif
		iptc_set_policy(chain, fw3_flag_names[policy], NULL, h->handle);
}

void
fw3_ipt_flush_chain(struct fw3_ipt_handle *h, const char *chain)
{
	if (fw3_pr_debug)
		debug(h, "-F %s\n", chain);

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
		ip6tc_flush_entries(chain, h->handle);
	else
#endif
		iptc_flush_entries(chain, h->handle);
}

static void
delete_rules(struct fw3_ipt_handle *h, const char *target)
{
	unsigned int num;
	const struct ipt_entry *e;
	const char *chain;
	const char *t;
	bool found;

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
	{
		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			do {
				found = false;

				const struct ip6t_entry *e6;
				for (num = 0, e6 = ip6tc_first_rule(chain, h->handle);
					 e6 != NULL;
					 num++, e6 = ip6tc_next_rule(e6, h->handle))
				{
					t = ip6tc_get_target(e6, h->handle);

					if (*t && !strcmp(t, target))
					{
						if (fw3_pr_debug)
							debug(h, "-D %s %u\n", chain, num + 1);

						ip6tc_delete_num_entry(chain, num, h->handle);
						found = true;
						break;
					}
				}
			} while (found);
		}
	}
	else
#endif
	{
		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			do {
				found = false;

				for (num = 0, e = iptc_first_rule(chain, h->handle);
				     e != NULL;
					 num++, e = iptc_next_rule(e, h->handle))
				{
					t = iptc_get_target(e, h->handle);

					if (*t && !strcmp(t, target))
					{
						if (fw3_pr_debug)
							debug(h, "-D %s %u\n", chain, num + 1);

						iptc_delete_num_entry(chain, num, h->handle);
						found = true;
						break;
					}
				}
			} while (found);
		}
	}
}

void
fw3_ipt_delete_chain(struct fw3_ipt_handle *h, const char *chain)
{
	delete_rules(h, chain);

	if (fw3_pr_debug)
		debug(h, "-X %s\n", chain);

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
		ip6tc_delete_chain(chain, h->handle);
	else
#endif
		iptc_delete_chain(chain, h->handle);
}

static bool
has_rule_tag(const void *base, unsigned int start, unsigned int end)
{
	unsigned int i;
	const struct xt_entry_match *em;

	for (i = start; i < end; i += em->u.match_size)
	{
		em = base + i;

		if (strcmp(em->u.user.name, "comment"))
			continue;

		if (!memcmp(em->data, "!fw3", 4))
			return true;
	}

	return false;
}

void
fw3_ipt_delete_id_rules(struct fw3_ipt_handle *h, const char *chain)
{
	unsigned int num;
	const struct ipt_entry *e;
	bool found;

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
	{
		if (!ip6tc_is_chain(chain, h->handle))
			return;

		do {
			found = false;

			const struct ip6t_entry *e6;
			for (num = 0, e6 = ip6tc_first_rule(chain, h->handle);
				 e6 != NULL;
				 num++, e6 = ip6tc_next_rule(e6, h->handle))
			{
				if (has_rule_tag(e6, sizeof(*e6), e6->target_offset))
				{
					if (fw3_pr_debug)
						debug(h, "-D %s %u\n", chain, num + 1);

					ip6tc_delete_num_entry(chain, num, h->handle);
					found = true;
					break;
				}
			}
		} while (found);
	}
	else
#endif
	{
		if (!iptc_is_chain(chain, h->handle))
			return;

		do {
			found = false;

			for (num = 0, e = iptc_first_rule(chain, h->handle);
				 e != NULL;
				 num++, e = iptc_next_rule(e, h->handle))
			{
				if (has_rule_tag(e, sizeof(*e), e->target_offset))
				{
					if (fw3_pr_debug)
						debug(h, "-D %s %u\n", chain, num + 1);

					iptc_delete_num_entry(chain, num, h->handle);
					found = true;
					break;
				}
			}
		} while (found);
	}
}

void
fw3_ipt_create_chain(struct fw3_ipt_handle *h, const char *fmt, ...)
{
	char buf[32];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	if (fw3_pr_debug)
		debug(h, "-N %s\n", buf);

	iptc_create_chain(buf, h->handle);
}

void
fw3_ipt_flush(struct fw3_ipt_handle *h)
{
	const char *chain;

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
	{
		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			ip6tc_flush_entries(chain, h->handle);
		}

		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			ip6tc_delete_chain(chain, h->handle);
		}
	}
	else
#endif
	{
		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			iptc_flush_entries(chain, h->handle);
		}

		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			iptc_delete_chain(chain, h->handle);
		}
	}
}

static bool
chain_is_empty(struct fw3_ipt_handle *h, const char *chain)
{
#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
		return (!ip6tc_builtin(chain, h->handle) &&
		        !ip6tc_first_rule(chain, h->handle));
#endif

	return (!iptc_builtin(chain, h->handle) &&
	        !iptc_first_rule(chain, h->handle));
}

void
fw3_ipt_gc(struct fw3_ipt_handle *h)
{
	const char *chain;
	bool found;

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
	{
		do {
			found = false;

			for (chain = ip6tc_first_chain(h->handle);
				 chain != NULL;
				 chain = ip6tc_next_chain(h->handle))
			{
				if (!chain_is_empty(h, chain))
					continue;

				fw3_ipt_delete_chain(h, chain);
				found = true;
				break;
			}
		} while(found);
	}
	else
#endif
	{
		do {
			found = false;

			for (chain = iptc_first_chain(h->handle);
				 chain != NULL;
				 chain = iptc_next_chain(h->handle))
			{
				warn("C=%s\n", chain);

				if (!chain_is_empty(h, chain))
					continue;

				warn("D=%s\n", chain);

				fw3_ipt_delete_chain(h, chain);
				found = true;
				break;
			}
		} while (found);
	}
}

void
fw3_ipt_commit(struct fw3_ipt_handle *h)
{
	int rv;

#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
	{
		rv = ip6tc_commit(h->handle);
		if (!rv)
			warn("ip6tc_commit(): %s", ip6tc_strerror(errno));
	}
	else
#endif
	{
		rv = iptc_commit(h->handle);
		if (!rv)
			warn("iptc_commit(): %s", iptc_strerror(errno));
	}
}

void
fw3_ipt_close(struct fw3_ipt_handle *h)
{
	free(h);
}

struct fw3_ipt_rule *
fw3_ipt_rule_new(struct fw3_ipt_handle *h)
{
	struct fw3_ipt_rule *r;

	r = fw3_alloc(sizeof(*r));

	r->h = h;
	r->argv = fw3_alloc(sizeof(char *));
	r->argv[r->argc++] = "fw3";

	return r;
}


static bool
is_chain(struct fw3_ipt_handle *h, const char *name)
{
#ifndef DISABLE_IPV6
	if (h->family == FW3_FAMILY_V6)
		return ip6tc_is_chain(name, h->handle);
	else
#endif
		return iptc_is_chain(name, h->handle);
}

static char *
get_protoname(struct fw3_ipt_rule *r)
{
	const struct xtables_pprot *pp;

	if (r->protocol)
		for (pp = xtables_chain_protos; pp->name; pp++)
			if (pp->num == r->protocol)
				return (char *)pp->name;

	return NULL;
}

static struct xtables_match *
find_match(struct fw3_ipt_rule *r, const char *name)
{
	struct xtables_match *m;

	xext.retain = true;
	m = xtables_find_match(name, XTF_TRY_LOAD, &r->matches);
	xext.retain = false;

	return m;
}

static void
init_match(struct fw3_ipt_rule *r, struct xtables_match *m, bool no_clone)
{
	size_t s;
	struct xtables_globals *g;

	if (!m)
		return;

	s = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;

	m->m = fw3_alloc(s);

	fw3_xt_set_match_name(m);

	m->m->u.user.revision = m->revision;
	m->m->u.match_size = s;

	/* free previous userspace data */
	fw3_xt_free_match_udata(m);

	if (m->init)
		m->init(m->m);

	/* don't merge options if no_clone is set and this match is a clone */
	if (no_clone && (m == m->next))
		return;

	/* merge option table */
	g = (r->h->family == FW3_FAMILY_V6) ? &xtg6 : &xtg;
	fw3_xt_merge_match_options(g, m);
}

static bool
need_protomatch(struct fw3_ipt_rule *r, const char *pname)
{
	if (!pname)
		return false;

	if (!xtables_find_match(pname, XTF_DONT_LOAD, NULL))
		return true;

	return !r->protocol_loaded;
}

static struct xtables_match *
load_protomatch(struct fw3_ipt_rule *r)
{
	const char *pname = get_protoname(r);

	if (!need_protomatch(r, pname))
		return NULL;

	return find_match(r, pname);
}

static struct xtables_target *
find_target(struct fw3_ipt_rule *r, const char *name)
{
	struct xtables_target *t;

	xext.retain = true;

	if (is_chain(r->h, name))
		t = xtables_find_target(XT_STANDARD_TARGET, XTF_TRY_LOAD);
	else
		t = xtables_find_target(name, XTF_TRY_LOAD);

	xext.retain = false;

	return t;
}

static struct xtables_target *
get_target(struct fw3_ipt_rule *r, const char *name)
{
	size_t s;
	struct xtables_target *t;
	struct xtables_globals *g;

	t = find_target(r, name);

	if (!t)
		return NULL;

	s = XT_ALIGN(sizeof(struct xt_entry_target)) + t->size;
	t->t = fw3_alloc(s);

	fw3_xt_set_target_name(t, name);

	t->t->u.user.revision = t->revision;
	t->t->u.target_size = s;

	/* free previous userspace data */
	fw3_xt_free_target_udata(t);

	if (t->init)
		t->init(t->t);

	/* merge option table */
	g = (r->h->family == FW3_FAMILY_V6) ? &xtg6 : &xtg;
	fw3_xt_merge_target_options(g, t);

	r->target = t;

	return t;
}

void
fw3_ipt_rule_proto(struct fw3_ipt_rule *r, struct fw3_protocol *proto)
{
	uint32_t pr;

	if (!proto || proto->any)
		return;

	pr = proto->protocol;

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		if (pr == 1)
			pr = 58;

		r->e6.ipv6.proto = pr;
		r->e6.ipv6.flags |= IP6T_F_PROTO;

		if (proto->invert)
			r->e6.ipv6.invflags |= XT_INV_PROTO;
	}
	else
#endif
	{
		r->e.ip.proto = pr;

		if (proto->invert)
			r->e.ip.invflags |= XT_INV_PROTO;
	}

	r->protocol = pr;
}

void
fw3_ipt_rule_in_out(struct fw3_ipt_rule *r,
                    struct fw3_device *in, struct fw3_device *out)
{
#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		if (in && !in->any)
		{
			xtables_parse_interface(in->name, r->e6.ipv6.iniface,
			                                  r->e6.ipv6.iniface_mask);

			if (in->invert)
				r->e6.ipv6.invflags |= IP6T_INV_VIA_IN;
		}

		if (out && !out->any)
		{
			xtables_parse_interface(out->name, r->e6.ipv6.outiface,
			                                   r->e6.ipv6.outiface_mask);

			if (out->invert)
				r->e6.ipv6.invflags |= IP6T_INV_VIA_OUT;
		}
	}
	else
#endif
	{
		if (in && !in->any)
		{
			xtables_parse_interface(in->name, r->e.ip.iniface,
			                                  r->e.ip.iniface_mask);

			if (in->invert)
				r->e.ip.invflags |= IPT_INV_VIA_IN;
		}

		if (out && !out->any)
		{
			xtables_parse_interface(out->name, r->e.ip.outiface,
			                                   r->e.ip.outiface_mask);

			if (out->invert)
				r->e.ip.invflags |= IPT_INV_VIA_OUT;
		}
	}
}


void
fw3_ipt_rule_src_dest(struct fw3_ipt_rule *r,
                      struct fw3_address *src, struct fw3_address *dest)
{
	if ((src && src->range) || (dest && dest->range))
	{
		fw3_ipt_rule_addarg(r, false, "-m", "iprange");
	}

	if (src && src->set)
	{
		if (src->range)
		{
			fw3_ipt_rule_addarg(r, src->invert, "--src-range",
			                    fw3_address_to_string(src, false, false));
		}
#ifndef DISABLE_IPV6
		else if (r->h->family == FW3_FAMILY_V6)
		{
			r->e6.ipv6.src = src->address.v6;
			r->e6.ipv6.smsk = src->mask.v6;

			int i;
			for (i = 0; i < 4; i++)
				r->e6.ipv6.src.s6_addr32[i] &= r->e6.ipv6.smsk.s6_addr32[i];

			if (src->invert)
				r->e6.ipv6.invflags |= IP6T_INV_SRCIP;
		}
#endif
		else
		{
			r->e.ip.src = src->address.v4;
			r->e.ip.smsk = src->mask.v4;

			r->e.ip.src.s_addr &= r->e.ip.smsk.s_addr;

			if (src->invert)
				r->e.ip.invflags |= IPT_INV_SRCIP;
		}
	}

	if (dest && dest->set)
	{
		if (dest->range)
		{
			fw3_ipt_rule_addarg(r, dest->invert, "--dst-range",
			                    fw3_address_to_string(dest, false, false));
		}
#ifndef DISABLE_IPV6
		else if (r->h->family == FW3_FAMILY_V6)
		{
			r->e6.ipv6.dst = dest->address.v6;
			r->e6.ipv6.dmsk = dest->mask.v6;

			int i;
			for (i = 0; i < 4; i++)
				r->e6.ipv6.dst.s6_addr32[i] &= r->e6.ipv6.dmsk.s6_addr32[i];

			if (dest->invert)
				r->e6.ipv6.invflags |= IP6T_INV_DSTIP;
		}
#endif
		else
		{
			r->e.ip.dst = dest->address.v4;
			r->e.ip.dmsk = dest->mask.v4;

			r->e.ip.dst.s_addr &= r->e.ip.dmsk.s_addr;

			if (dest->invert)
				r->e.ip.invflags |= IPT_INV_DSTIP;
		}
	}
}

void
fw3_ipt_rule_sport_dport(struct fw3_ipt_rule *r,
                         struct fw3_port *sp, struct fw3_port *dp)
{
	char buf[sizeof("65535:65535\0")];

	if ((!sp || !sp->set) && (!dp || !dp->set))
		return;

	if (!get_protoname(r))
		return;

	if (sp && sp->set)
	{
		if (sp->port_min == sp->port_max)
			sprintf(buf, "%u", sp->port_min);
		else
			sprintf(buf, "%u:%u", sp->port_min, sp->port_max);

		fw3_ipt_rule_addarg(r, sp->invert, "--sport", buf);
	}

	if (dp && dp->set)
	{
		if (dp->port_min == dp->port_max)
			sprintf(buf, "%u", dp->port_min);
		else
			sprintf(buf, "%u:%u", dp->port_min, dp->port_max);

		fw3_ipt_rule_addarg(r, dp->invert, "--dport", buf);
	}
}

void
fw3_ipt_rule_device(struct fw3_ipt_rule *r, const char *device, bool out)
{
	if (device) {
		struct fw3_device dev = { .any = false };
		strncpy(dev.name, device, sizeof(dev.name) - 1);
		fw3_ipt_rule_in_out(r, (out) ? NULL : &dev, (out) ? &dev : NULL);
	}
}

void
fw3_ipt_rule_mac(struct fw3_ipt_rule *r, struct fw3_mac *mac)
{
	char buf[sizeof("ff:ff:ff:ff:ff:ff\0")];
	uint8_t *addr = mac->mac.ether_addr_octet;

	if (!mac)
		return;

	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	fw3_ipt_rule_addarg(r, false, "-m", "mac");
	fw3_ipt_rule_addarg(r, mac->invert, "--mac-source", buf);
}

void
fw3_ipt_rule_icmptype(struct fw3_ipt_rule *r, struct fw3_icmptype *icmp)
{
	char buf[sizeof("255/255\0")];

	if (!icmp)
		return;

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		if (icmp->code6_min == 0 && icmp->code6_max == 0xFF)
			sprintf(buf, "%u", icmp->type6);
		else
			sprintf(buf, "%u/%u", icmp->type6, icmp->code6_min);

		fw3_ipt_rule_addarg(r, icmp->invert, "--icmpv6-type", buf);
	}
	else
#endif
	{
		if (icmp->code_min == 0 && icmp->code_max == 0xFF)
			sprintf(buf, "%u", icmp->type);
		else
			sprintf(buf, "%u/%u", icmp->type, icmp->code_min);

		fw3_ipt_rule_addarg(r, icmp->invert, "--icmp-type", buf);
	}
}

void
fw3_ipt_rule_limit(struct fw3_ipt_rule *r, struct fw3_limit *limit)
{
	char buf[sizeof("-4294967296/second\0")];

	if (!limit || limit->rate <= 0)
		return;

	fw3_ipt_rule_addarg(r, false, "-m", "limit");

	sprintf(buf, "%u/%s", limit->rate, fw3_limit_units[limit->unit]);
	fw3_ipt_rule_addarg(r, limit->invert, "--limit", buf);

	if (limit->burst > 0)
	{
		sprintf(buf, "%u", limit->burst);
		fw3_ipt_rule_addarg(r, limit->invert, "--limit-burst", buf);
	}
}

void
fw3_ipt_rule_ipset(struct fw3_ipt_rule *r, struct fw3_setmatch *match)
{
	char buf[sizeof("dst,dst,dst\0")];
	char *p = buf;
	int i = 0;

	struct fw3_ipset *set;
	struct fw3_ipset_datatype *type;

	if (!match || !match->set || !match->ptr)
		return;

	set = match->ptr;
	list_for_each_entry(type, &set->datatypes, list)
	{
		if (i >= 3)
			break;

		if (p > buf)
			*p++ = ',';

		p += sprintf(p, "%s", match->dir[i] ? match->dir[i] : type->dir);
		i++;
	}

	fw3_ipt_rule_addarg(r, false, "-m", "set");

	fw3_ipt_rule_addarg(r, match->invert, "--match-set",
	                    set->external ? set->external : set->name);

	fw3_ipt_rule_addarg(r, false, buf, NULL);
}

void
fw3_ipt_rule_time(struct fw3_ipt_rule *r, struct fw3_time *time)
{
	int i;
	struct tm empty = { 0 };

	char buf[84]; /* sizeof("1,2,3,...,30,31\0") */
	char *p;

	bool d1 = memcmp(&time->datestart, &empty, sizeof(empty));
	bool d2 = memcmp(&time->datestop, &empty, sizeof(empty));

	if (!d1 && !d2 && !time->timestart && !time->timestop &&
	    !(time->monthdays & 0xFFFFFFFE) && !(time->weekdays & 0xFE))
	{
		return;
	}

	fw3_ipt_rule_addarg(r, false, "-m", "time");

	if (!time->utc)
		fw3_ipt_rule_addarg(r, false, "--kerneltz", NULL);

	if (d1)
	{
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &time->datestart);
		fw3_ipt_rule_addarg(r, false, "--datestart", buf);
	}

	if (d2)
	{
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &time->datestop);
		fw3_ipt_rule_addarg(r, false, "--datestop", buf);
	}

	if (time->timestart)
	{
		sprintf(buf, "%02d:%02d:%02d",
		        time->timestart / 3600,
		        time->timestart % 3600 / 60,
		        time->timestart % 60);

		fw3_ipt_rule_addarg(r, false, "--timestart", buf);
	}

	if (time->timestop)
	{
		sprintf(buf, "%02d:%02d:%02d",
		        time->timestop / 3600,
		        time->timestop % 3600 / 60,
		        time->timestop % 60);

		fw3_ipt_rule_addarg(r, false, "--timestop", buf);
	}

	if (time->monthdays & 0xFFFFFFFE)
	{
		for (i = 1, p = buf; i < 32; i++)
		{
			if (fw3_hasbit(time->monthdays, i))
			{
				if (p > buf)
					*p++ = ',';

				p += sprintf(p, "%u", i);
			}
		}

		fw3_ipt_rule_addarg(r, fw3_hasbit(time->monthdays, 0), "--monthdays", buf);
	}

	if (time->weekdays & 0xFE)
	{
		for (i = 1, p = buf; i < 8; i++)
		{
			if (fw3_hasbit(time->weekdays, i))
			{
				if (p > buf)
					*p++ = ',';

				p += sprintf(p, "%u", i);
			}
		}

		fw3_ipt_rule_addarg(r, fw3_hasbit(time->weekdays, 0), "--weekdays", buf);
	}
}

void
fw3_ipt_rule_mark(struct fw3_ipt_rule *r, struct fw3_mark *mark)
{
	char buf[sizeof("0xFFFFFFFF/0xFFFFFFFF\0")];

	if (!mark || !mark->set)
		return;

	if (mark->mask < 0xFFFFFFFF)
		sprintf(buf, "0x%x/0x%x", mark->mark, mark->mask);
	else
		sprintf(buf, "0x%x", mark->mark);

	fw3_ipt_rule_addarg(r, false, "-m", "mark");
	fw3_ipt_rule_addarg(r, mark->invert, "--mark", buf);
}

void
fw3_ipt_rule_comment(struct fw3_ipt_rule *r, const char *fmt, ...)
{
	va_list ap;
	char buf[256];

	if (!fmt || !*fmt)
		return;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	fw3_ipt_rule_addarg(r, false, "-m", "comment");
	fw3_ipt_rule_addarg(r, false, "--comment", buf);
}

void
fw3_ipt_rule_extra(struct fw3_ipt_rule *r, const char *extra)
{
	char *p, **tmp, *s;

	if (!extra || !*extra)
		return;

	s = fw3_strdup(extra);

	for (p = strtok(s, " \t"); p; p = strtok(NULL, " \t"))
	{
		tmp = realloc(r->argv, (r->argc + 1) * sizeof(*r->argv));

		if (!tmp)
			break;

		r->argv = tmp;
		r->argv[r->argc++] = fw3_strdup(p);
	}

	free(s);
}

#ifndef DISABLE_IPV6
static void
rule_print6(struct ip6t_entry *e)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	char *pname;

	if (e->ipv6.flags & IP6T_F_PROTO)
	{
		if (e->ipv6.invflags & XT_INV_PROTO)
			printf(" !");

		pname = get_protoname(container_of(e, struct fw3_ipt_rule, e6));

		if (pname)
			printf(" -p %s", pname);
		else
			printf(" -p %u", e->ipv6.proto);
	}

	if (e->ipv6.iniface[0])
	{
		if (e->ipv6.invflags & IP6T_INV_VIA_IN)
			printf(" !");

		printf(" -i %s", e->ipv6.iniface);
	}

	if (e->ipv6.outiface[0])
	{
		if (e->ipv6.invflags & IP6T_INV_VIA_OUT)
			printf(" !");

		printf(" -o %s", e->ipv6.outiface);
	}

	if (memcmp(&e->ipv6.src, &in6addr_any, sizeof(struct in6_addr)))
	{
		if (e->ipv6.invflags & IP6T_INV_SRCIP)
			printf(" !");

		printf(" -s %s/%s",
		       inet_ntop(AF_INET6, &e->ipv6.src, buf1, sizeof(buf1)),
		       inet_ntop(AF_INET6, &e->ipv6.smsk, buf2, sizeof(buf2)));
	}

	if (memcmp(&e->ipv6.dst, &in6addr_any, sizeof(struct in6_addr)))
	{
		if (e->ipv6.invflags & IP6T_INV_DSTIP)
			printf(" !");

		printf(" -d %s/%s",
		       inet_ntop(AF_INET6, &e->ipv6.dst, buf1, sizeof(buf1)),
		       inet_ntop(AF_INET6, &e->ipv6.dmsk, buf2, sizeof(buf2)));
	}
}
#endif

static void
rule_print4(struct ipt_entry *e)
{
	struct in_addr in_zero = { 0 };
	char buf1[sizeof("255.255.255.255\0")], buf2[sizeof("255.255.255.255\0")];
	char *pname;

	if (e->ip.proto)
	{
		if (e->ip.invflags & XT_INV_PROTO)
			printf(" !");

		pname = get_protoname(container_of(e, struct fw3_ipt_rule, e));

		if (pname)
			printf(" -p %s", pname);
		else
			printf(" -p %u", e->ip.proto);
	}

	if (e->ip.iniface[0])
	{
		if (e->ip.invflags & IPT_INV_VIA_IN)
			printf(" !");

		printf(" -i %s", e->ip.iniface);
	}

	if (e->ip.outiface[0])
	{
		if (e->ip.invflags & IPT_INV_VIA_OUT)
			printf(" !");

		printf(" -o %s", e->ip.outiface);
	}

	if (memcmp(&e->ip.src, &in_zero, sizeof(struct in_addr)))
	{
		if (e->ip.invflags & IPT_INV_SRCIP)
			printf(" !");

		printf(" -s %s/%s",
		       inet_ntop(AF_INET, &e->ip.src, buf1, sizeof(buf1)),
		       inet_ntop(AF_INET, &e->ip.smsk, buf2, sizeof(buf2)));
	}

	if (memcmp(&e->ip.dst, &in_zero, sizeof(struct in_addr)))
	{
		if (e->ip.invflags & IPT_INV_DSTIP)
			printf(" !");

		printf(" -d %s/%s",
		       inet_ntop(AF_INET, &e->ip.dst, buf1, sizeof(buf1)),
		       inet_ntop(AF_INET, &e->ip.dmsk, buf2, sizeof(buf2)));
	}
}

static void
rule_print(struct fw3_ipt_rule *r, const char *prefix, const char *chain)
{
	debug(r->h, "%s %s", prefix, chain);

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
		rule_print6(&r->e6);
	else
#endif
		rule_print4(&r->e);

	fw3_xt_print_matches(&r->e.ip, r->matches);
	fw3_xt_print_target(&r->e.ip, r->target);

	printf("\n");
}

static bool
parse_option(struct fw3_ipt_rule *r, int optc, bool inv)
{
	struct xtables_rule_match *m;
	struct xtables_match *em;

	/* is a target option */
	if (r->target && fw3_xt_has_target_parse(r->target) &&
		optc >= r->target->option_offset &&
		optc < (r->target->option_offset + 256))
	{
		xtables_option_tpcall(optc, r->argv, inv, r->target, &r->e);
		return false;
	}

	/* try to dispatch argument to one of the match parsers */
	for (m = r->matches; m; m = m->next)
	{
		em = m->match;

		if (m->completed || !fw3_xt_has_match_parse(em))
			continue;

		if (optc < em->option_offset ||
			optc >= (em->option_offset + 256))
			continue;

		xtables_option_mpcall(optc, r->argv, inv, em, &r->e);
		return false;
	}

	/* unhandled option, might belong to a protocol match */
	if ((em = load_protomatch(r)) != NULL)
	{
		init_match(r, em, false);

		r->protocol_loaded = true;
		optind--;

		return true;
	}

	if (optc == ':')
		warn("parse_option(): option '%s' needs argument", r->argv[optind-1]);

	if (optc == '?')
		warn("parse_option(): unknown option '%s'", r->argv[optind-1]);

	return false;
}

void
fw3_ipt_rule_addarg(struct fw3_ipt_rule *r, bool inv,
                    const char *k, const char *v)
{
	int n;
	char **tmp;

	if (!k)
		return;

	n = inv + !!k + !!v;
	tmp = realloc(r->argv, (r->argc + n) * sizeof(*tmp));

	if (!tmp)
		return;

	r->argv = tmp;

	if (inv)
		r->argv[r->argc++] = fw3_strdup("!");

	r->argv[r->argc++] = fw3_strdup(k);

	if (v)
		r->argv[r->argc++] = fw3_strdup(v);
}

static unsigned char *
rule_mask(struct fw3_ipt_rule *r)
{
	size_t s;
	unsigned char *p, *mask = NULL;
	struct xtables_rule_match *m;

#define SZ(x) XT_ALIGN(sizeof(struct x))

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		s = SZ(ip6t_entry);

		for (m = r->matches; m; m = m->next)
			s += SZ(ip6t_entry_match) + m->match->size;

		s += SZ(ip6t_entry_target);
		if (r->target)
			s += r->target->size;

		mask = fw3_alloc(s);
		memset(mask, 0xFF, SZ(ip6t_entry));
		p = mask + SZ(ip6t_entry);

		for (m = r->matches; m; m = m->next)
		{
			memset(p, 0xFF, SZ(ip6t_entry_match) + m->match->userspacesize);
			p += SZ(ip6t_entry_match) + m->match->size;
		}

		memset(p, 0xFF, SZ(ip6t_entry_target) + (r->target) ? r->target->userspacesize : 0);
	}
	else
#endif
	{
		s = SZ(ipt_entry);

		for (m = r->matches; m; m = m->next)
			s += SZ(ipt_entry_match) + m->match->size;

		s += SZ(ipt_entry_target);
		if (r->target)
			s += r->target->size;

		mask = fw3_alloc(s);
		memset(mask, 0xFF, SZ(ipt_entry));
		p = mask + SZ(ipt_entry);

		for (m = r->matches; m; m = m->next)
		{
			memset(p, 0xFF, SZ(ipt_entry_match) + m->match->userspacesize);
			p += SZ(ipt_entry_match) + m->match->size;
		}

		memset(p, 0xFF, SZ(ipt_entry_target) + (r->target) ? r->target->userspacesize : 0);
	}

	return mask;
}

static void *
rule_build(struct fw3_ipt_rule *r)
{
	size_t s, target_size = (r->target) ? r->target->t->u.target_size : 0;
	struct xtables_rule_match *m;

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		struct ip6t_entry *e6;

		s = XT_ALIGN(sizeof(struct ip6t_entry));

		for (m = r->matches; m; m = m->next)
			s += m->match->m->u.match_size;

		e6 = fw3_alloc(s + target_size);

		memcpy(e6, &r->e6, sizeof(struct ip6t_entry));

		e6->target_offset = s;
		e6->next_offset = s + target_size;

		s = 0;

		for (m = r->matches; m; m = m->next)
		{
			memcpy(e6->elems + s, m->match->m, m->match->m->u.match_size);
			s += m->match->m->u.match_size;
		}

		if (target_size)
			memcpy(e6->elems + s, r->target->t, target_size);

		return e6;
	}
	else
#endif
	{
		struct ipt_entry *e;

		s = XT_ALIGN(sizeof(struct ipt_entry));

		for (m = r->matches; m; m = m->next)
			s += m->match->m->u.match_size;

		e = fw3_alloc(s + target_size);

		memcpy(e, &r->e, sizeof(struct ipt_entry));

		e->target_offset = s;
		e->next_offset = s + target_size;

		s = 0;

		for (m = r->matches; m; m = m->next)
		{
			memcpy(e->elems + s, m->match->m, m->match->m->u.match_size);
			s += m->match->m->u.match_size;
		}

		if (target_size)
			memcpy(e->elems + s, r->target->t, target_size);

		return e;
	}
}

static void
set_rule_tag(struct fw3_ipt_rule *r)
{
	int i;
	char *p, **tmp;
	const char *tag = "!fw3";

	for (i = 0; i < r->argc; i++)
		if (!strcmp(r->argv[i], "--comment") && (i + 1) < r->argc)
			if (asprintf(&p, "%s: %s", tag, r->argv[i + 1]) > 0)
			{
				free(r->argv[i + 1]);
				r->argv[i + 1] = p;
				return;
			}

	tmp = realloc(r->argv, (r->argc + 4) * sizeof(*r->argv));

	if (tmp)
	{
		r->argv = tmp;
		r->argv[r->argc++] = fw3_strdup("-m");
		r->argv[r->argc++] = fw3_strdup("comment");
		r->argv[r->argc++] = fw3_strdup("--comment");
		r->argv[r->argc++] = fw3_strdup(tag);
	}
}

void
__fw3_ipt_rule_append(struct fw3_ipt_rule *r, bool repl, const char *fmt, ...)
{
	void *rule;
	unsigned char *mask;

	struct xtables_rule_match *m;
	struct xtables_match *em;
	struct xtables_target *et;
	struct xtables_globals *g;

	enum xtables_exittype status;

	int i, optc;
	bool inv = false;
	char buf[32];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	g = (r->h->family == FW3_FAMILY_V6) ? &xtg6 : &xtg;
	g->opts = g->orig_opts;

	optind = 0;
	opterr = 0;

	status = setjmp(fw3_ipt_error_jmp);

	if (status > 0)
	{
		info("     ! Skipping due to previous exception (code %u)", status);
		goto free;
	}

	set_rule_tag(r);

	while ((optc = getopt_long(r->argc, r->argv, "-:m:j:", g->opts,
	                           NULL)) != -1)
	{
		switch (optc)
		{
		case 'm':
			em = find_match(r, optarg);

			if (!em)
			{
				warn("fw3_ipt_rule_append(): Can't find match '%s'", optarg);
				goto free;
			}

			init_match(r, em, true);
			break;

		case 'j':
			et = get_target(r, optarg);

			if (!et)
			{
				warn("fw3_ipt_rule_append(): Can't find target '%s'", optarg);
				goto free;
			}

			break;

		case 1:
			if ((optarg[0] == '!') && (optarg[1] == '\0'))
			{
				optarg[0] = '\0';
				inv = true;
				continue;
			}

			warn("fw3_ipt_rule_append(): Bad argument '%s'", optarg);
			goto free;

		default:
			if (parse_option(r, optc, inv))
				continue;
			break;
		}

		inv = false;
	}

	for (m = r->matches; m; m = m->next)
		xtables_option_mfcall(m->match);

	if (r->target)
		xtables_option_tfcall(r->target);

	rule = rule_build(r);

#ifndef DISABLE_IPV6
	if (r->h->family == FW3_FAMILY_V6)
	{
		if (repl)
		{
			mask = rule_mask(r);

			while (ip6tc_delete_entry(buf, rule, mask, r->h->handle))
				if (fw3_pr_debug)
					rule_print(r, "-D", buf);

			free(mask);
		}

		if (fw3_pr_debug)
			rule_print(r, "-A", buf);

		if (!ip6tc_append_entry(buf, rule, r->h->handle))
			warn("ip6tc_append_entry(): %s", ip6tc_strerror(errno));
	}
	else
#endif
	{
		if (repl)
		{
			mask = rule_mask(r);

			while (iptc_delete_entry(buf, rule, mask, r->h->handle))
				if (fw3_pr_debug)
					rule_print(r, "-D", buf);

			free(mask);
		}

		if (fw3_pr_debug)
			rule_print(r, "-A", buf);

		if (!iptc_append_entry(buf, rule, r->h->handle))
			warn("iptc_append_entry(): %s\n", iptc_strerror(errno));
	}

	free(rule);

free:
	for (i = 1; i < r->argc; i++)
		free(r->argv[i]);

	free(r->argv);

	xtables_rule_matches_free(&r->matches);

	if (r->target)
		free(r->target->t);

	free(r);

	/* reset all targets and matches */
	for (em = xtables_matches; em; em = em->next)
		em->mflags = 0;

	for (et = xtables_targets; et; et = et->next)
	{
		et->tflags = 0;
		et->used = 0;
	}

	xtables_free_opts(1);
}

struct fw3_ipt_rule *
fw3_ipt_rule_create(struct fw3_ipt_handle *handle, struct fw3_protocol *proto,
                    struct fw3_device *in, struct fw3_device *out,
                    struct fw3_address *src, struct fw3_address *dest)
{
	struct fw3_ipt_rule *r;

	r = fw3_ipt_rule_new(handle);

	fw3_ipt_rule_proto(r, proto);
	fw3_ipt_rule_in_out(r, in, out);
	fw3_ipt_rule_src_dest(r, src, dest);

	return r;
}

void
xtables_register_match(struct xtables_match *me)
{
	int i;
	static struct xtables_match **tmp;

	if (!xext.register_match)
		xext.register_match = dlsym(RTLD_NEXT, "xtables_register_match");

	if (!xext.register_match)
		return;

	xext.register_match(me);

	if (xext.retain)
	{
		for (i = 0; i < xext.mcount; i++)
			if (xext.matches[i] == me)
				return;

		tmp = realloc(xext.matches, sizeof(me) * (xext.mcount + 1));

		if (!tmp)
			return;

		xext.matches = tmp;
		xext.matches[xext.mcount++] = me;
	}
}

void
xtables_register_target(struct xtables_target *me)
{
	int i;
	static struct xtables_target **tmp;

	if (!xext.register_target)
		xext.register_target = dlsym(RTLD_NEXT, "xtables_register_target");

	if (!xext.register_target)
		return;

	xext.register_target(me);

	if (xext.retain)
	{
		for (i = 0; i < xext.tcount; i++)
			if (xext.targets[i] == me)
				return;

		tmp = realloc(xext.targets, sizeof(me) * (xext.tcount + 1));

		if (!tmp)
			return;

		xext.targets = tmp;
		xext.targets[xext.tcount++] = me;
	}
}
