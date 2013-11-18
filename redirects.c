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

#include "redirects.h"


const struct fw3_option fw3_redirect_opts[] = {
	FW3_OPT("enabled",             bool,      redirect,     enabled),

	FW3_OPT("name",                string,    redirect,     name),
	FW3_OPT("family",              family,    redirect,     family),

	FW3_OPT("src",                 device,    redirect,     src),
	FW3_OPT("dest",                device,    redirect,     dest),

	FW3_OPT("ipset",               setmatch,  redirect,     ipset),

	FW3_LIST("proto",              protocol,  redirect,     proto),

	FW3_OPT("src_ip",              network,   redirect,     ip_src),
	FW3_LIST("src_mac",            mac,       redirect,     mac_src),
	FW3_OPT("src_port",            port,      redirect,     port_src),

	FW3_OPT("src_dip",             network,   redirect,     ip_dest),
	FW3_OPT("src_dport",           port,      redirect,     port_dest),

	FW3_OPT("dest_ip",             network,   redirect,     ip_redir),
	FW3_OPT("dest_port",           port,      redirect,     port_redir),

	FW3_OPT("extra",               string,    redirect,     extra),

	FW3_OPT("limit",               limit,     redirect,     limit),
	FW3_OPT("limit_burst",         int,       redirect,     limit.burst),

	FW3_OPT("utc_time",            bool,      redirect,     time.utc),
	FW3_OPT("start_date",          date,      redirect,     time.datestart),
	FW3_OPT("stop_date",           date,      redirect,     time.datestop),
	FW3_OPT("start_time",          time,      redirect,     time.timestart),
	FW3_OPT("stop_time",           time,      redirect,     time.timestop),
	FW3_OPT("weekdays",            weekdays,  redirect,     time.weekdays),
	FW3_OPT("monthdays",           monthdays, redirect,     time.monthdays),

	FW3_OPT("mark",                mark,      redirect,     mark),

	FW3_OPT("reflection",          bool,      redirect,     reflection),
	FW3_OPT("reflection_src",      reflection_source,
	                                          redirect,     reflection_src),

	FW3_OPT("target",              target,    redirect,     target),

	{ }
};


static bool
check_families(struct uci_element *e, struct fw3_redirect *r)
{
	if (r->family == FW3_FAMILY_ANY)
		return true;

	if (r->_src && r->_src->family && r->_src->family != r->family)
	{
		warn_elem(e, "refers to source zone with different family");
		return false;
	}

	if (r->_dest && r->_dest->family && r->_dest->family != r->family)
	{
		warn_elem(e, "refers to destination zone with different family");
		return false;
	}

	if (r->ipset.ptr && r->ipset.ptr->family &&
	    r->ipset.ptr->family != r->family)
	{
		warn_elem(e, "refers to ipset with different family");
		return false;
	}

	if (r->ip_src.family && r->ip_src.family != r->family)
	{
		warn_elem(e, "uses source ip with different family");
		return false;
	}

	if (r->ip_dest.family && r->ip_dest.family != r->family)
	{
		warn_elem(e, "uses destination ip with different family");
		return false;
	}

	if (r->ip_redir.family && r->ip_redir.family != r->family)
	{
		warn_elem(e, "uses redirect ip with different family");
		return false;
	}

	return true;
}

static bool
compare_addr(struct fw3_address *a, struct fw3_address *b)
{
	uint32_t mask;

	if (a->family != FW3_FAMILY_V4 || b->family != FW3_FAMILY_V4)
		return false;

	mask = htonl(~((1 << (32 - a->mask)) - 1));

	return ((a->address.v4.s_addr & mask) == (b->address.v4.s_addr & mask));
}

static bool
resolve_dest(struct uci_element *e, struct fw3_redirect *redir,
             struct fw3_state *state)
{
	struct fw3_zone *zone;
	struct fw3_address *addr;
	struct list_head *addrs;

	if (!redir->ip_redir.set)
		return false;

	list_for_each_entry(zone, &state->zones, list)
	{
		addrs = fw3_resolve_zone_addresses(zone);

		if (!addrs)
			continue;

		list_for_each_entry(addr, addrs, list)
		{
			if (!compare_addr(addr, &redir->ip_redir))
				continue;

			strncpy(redir->dest.name, zone->name, sizeof(redir->dest.name));
			redir->dest.set = true;
			redir->_dest = zone;

			break;
		}

		fw3_free_list(addrs);

		if (redir->_dest)
			return true;
	}

	return false;
}

static bool
check_local(struct uci_element *e, struct fw3_redirect *redir,
            struct fw3_state *state)
{
	struct fw3_zone *zone;
	struct fw3_device *net;
	struct fw3_address *addr;
	struct list_head *addrs;

	if (redir->target != FW3_FLAG_DNAT)
		return false;

	if (!redir->ip_redir.set)
		redir->local = true;

	if (redir->local)
		return true;

	list_for_each_entry(zone, &state->zones, list)
	{
		list_for_each_entry(net, &zone->networks, list)
		{
			addrs = fw3_ubus_address(net->name);

			if (!addrs)
				continue;

			list_for_each_entry(addr, addrs, list)
			{
				if (!compare_addr(&redir->ip_redir, addr))
					continue;

				warn_elem(e, "refers to a destination address on this router, "
				             "assuming port redirection");

				redir->local = true;
				break;
			}

			fw3_free_list(addrs);

			if (redir->local)
				return true;
		}
	}

	return false;
}

void
fw3_load_redirects(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_redirect *redir;

	bool valid;

	INIT_LIST_HEAD(&state->redirects);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "redirect"))
			continue;

		redir = malloc(sizeof(*redir));

		if (!redir)
			continue;

		memset(redir, 0, sizeof(*redir));

		INIT_LIST_HEAD(&redir->proto);
		INIT_LIST_HEAD(&redir->mac_src);

		redir->enabled = true;
		redir->reflection = true;

		valid = false;

		if (!fw3_parse_options(redir, fw3_redirect_opts, s))
		{
			warn_elem(e, "skipped due to invalid options");
			fw3_free_redirect(redir);
			continue;
		}

		if (!redir->enabled)
		{
			fw3_free_redirect(redir);
			continue;
		}

		if (redir->src.invert)
		{
			warn_elem(e, "must not have an inverted source");
			fw3_free_redirect(redir);
			continue;
		}
		else if (redir->src.set && !redir->src.any &&
		         !(redir->_src = fw3_lookup_zone(state, redir->src.name)))
		{
			warn_elem(e, "refers to not existing zone '%s'", redir->src.name);
			fw3_free_redirect(redir);
			continue;
		}
		else if (redir->dest.set && !redir->dest.any &&
		         !(redir->_dest = fw3_lookup_zone(state, redir->dest.name)))
		{
			warn_elem(e, "refers to not existing zone '%s'", redir->dest.name);
			fw3_free_redirect(redir);
			continue;
		}
		else if (redir->ipset.set && state->disable_ipsets)
		{
			warn_elem(e, "skipped due to disabled ipset support");
			fw3_free_redirect(redir);
			continue;
		}
		else if (redir->ipset.set &&
		         !(redir->ipset.ptr = fw3_lookup_ipset(state, redir->ipset.name)))
		{
			warn_elem(e, "refers to unknown ipset '%s'", redir->ipset.name);
			fw3_free_redirect(redir);
			continue;
		}

		if (!check_families(e, redir))
		{
			fw3_free_redirect(redir);
			continue;
		}

		if (redir->target == FW3_FLAG_UNSPEC)
		{
			warn_elem(e, "has no target specified, defaulting to DNAT");
			redir->target = FW3_FLAG_DNAT;
		}
		else if (redir->target < FW3_FLAG_DNAT)
		{
			warn_elem(e, "has invalid target specified, defaulting to DNAT");
			redir->target = FW3_FLAG_DNAT;
		}

		if (redir->target == FW3_FLAG_DNAT)
		{
			if (redir->src.any)
				warn_elem(e, "must not have source '*' for DNAT target");
			else if (!redir->_src)
				warn_elem(e, "has no source specified");
			else
			{
				set(redir->_src->flags, FW3_FAMILY_V4, redir->target);
				redir->_src->conntrack = true;
				valid = true;
			}

			if (!check_local(e, redir, state) && !redir->dest.set &&
			    resolve_dest(e, redir, state))
			{
				warn_elem(e, "does not specify a destination, assuming '%s'",
				          redir->dest.name);
			}

			if (redir->reflection && redir->_dest && redir->_src->masq)
			{
				set(redir->_dest->flags, FW3_FAMILY_V4, FW3_FLAG_ACCEPT);
				set(redir->_dest->flags, FW3_FAMILY_V4, FW3_FLAG_DNAT);
				set(redir->_dest->flags, FW3_FAMILY_V4, FW3_FLAG_SNAT);
			}
		}
		else
		{
			if (redir->dest.any)
				warn_elem(e, "must not have destination '*' for SNAT target");
			else if (!redir->_dest)
				warn_elem(e, "has no destination specified");
			else if (!redir->ip_dest.set)
				warn_elem(e, "has no src_dip option specified");
			else if (!list_empty(&redir->mac_src))
				warn_elem(e, "must not use 'src_mac' option for SNAT target");
			else
			{
				set(redir->_dest->flags, FW3_FAMILY_V4, redir->target);
				redir->_dest->conntrack = true;
				valid = true;
			}
		}

		if (list_empty(&redir->proto))
		{
			warn_elem(e, "does not specify a protocol, assuming TCP+UDP");
			fw3_parse_protocol(&redir->proto, "tcpudp", true);
		}

		if (!valid)
		{
			fw3_free_redirect(redir);
			continue;
		}

		if (!redir->port_redir.set)
			redir->port_redir = redir->port_dest;

		list_add_tail(&redir->list, &state->redirects);
	}
}

static void
append_chain_nat(struct fw3_ipt_rule *r, struct fw3_redirect *redir)
{
	if (redir->target == FW3_FLAG_DNAT)
		fw3_ipt_rule_append(r, "zone_%s_prerouting", redir->src.name);
	else
		fw3_ipt_rule_append(r, "zone_%s_postrouting", redir->dest.name);
}

static void
set_snat_dnat(struct fw3_ipt_rule *r, enum fw3_flag target,
              struct fw3_address *addr, struct fw3_port *port)
{
	char buf[sizeof("255.255.255.255:65535-65535\0")];

	buf[0] = '\0';

	if (addr && addr->set)
	{
		inet_ntop(AF_INET, &addr->address.v4, buf, sizeof(buf));
	}

	if (port && port->set)
	{
		if (port->port_min == port->port_max)
			sprintf(buf + strlen(buf), ":%u", port->port_min);
		else
			sprintf(buf + strlen(buf), ":%u-%u",
			        port->port_min, port->port_max);
	}

	if (target == FW3_FLAG_DNAT)
	{
		fw3_ipt_rule_target(r, "DNAT");
		fw3_ipt_rule_addarg(r, false, "--to-destination", buf);
	}
	else
	{
		fw3_ipt_rule_target(r, "SNAT");
		fw3_ipt_rule_addarg(r, false, "--to-source", buf);
	}
}

static void
set_target_nat(struct fw3_ipt_rule *r, struct fw3_redirect *redir)
{
	if (redir->target == FW3_FLAG_DNAT)
		set_snat_dnat(r, redir->target, &redir->ip_redir, &redir->port_redir);
	else
		set_snat_dnat(r, redir->target, &redir->ip_dest, &redir->port_dest);
}

static void
set_comment(struct fw3_ipt_rule *r, const char *name, int num, bool ref)
{
	if (name)
	{
		if (ref)
			fw3_ipt_rule_comment(r, "%s (reflection)", name);
		else
			fw3_ipt_rule_comment(r, name);
	}
	else
	{
		if (ref)
			fw3_ipt_rule_comment(r, "@redirect[%u] (reflection)", num);
		else
			fw3_ipt_rule_comment(r, "@redirect[%u]", num);
	}
}

static void
print_redirect(struct fw3_ipt_handle *h, struct fw3_state *state,
               struct fw3_redirect *redir, int num,
               struct fw3_protocol *proto, struct fw3_mac *mac)
{
	struct fw3_ipt_rule *r;
	struct fw3_address *src, *dst;
	struct fw3_port *spt, *dpt;

	switch (h->table)
	{
	case FW3_TABLE_NAT:
		src = &redir->ip_src;
		dst = &redir->ip_dest;
		spt = &redir->port_src;
		dpt = &redir->port_dest;

		if (redir->target == FW3_FLAG_SNAT)
		{
			dst = &redir->ip_redir;
			dpt = &redir->port_redir;
		}

		r = fw3_ipt_rule_create(h, proto, NULL, NULL, src, dst);
		fw3_ipt_rule_sport_dport(r, spt, dpt);
		fw3_ipt_rule_mac(r, mac);
		fw3_ipt_rule_ipset(r, &redir->ipset);
		fw3_ipt_rule_limit(r, &redir->limit);
		fw3_ipt_rule_time(r, &redir->time);
		fw3_ipt_rule_mark(r, &redir->mark);
		set_target_nat(r, redir);
		fw3_ipt_rule_extra(r, redir->extra);
		set_comment(r, redir->name, num, false);
		append_chain_nat(r, redir);
		break;

	default:
		break;
	}
}

static void
print_reflection(struct fw3_ipt_handle *h, struct fw3_state *state,
                 struct fw3_redirect *redir, int num,
                 struct fw3_protocol *proto, struct fw3_address *ra,
                 struct fw3_address *ia, struct fw3_address *ea)
{
	struct fw3_ipt_rule *r;

	switch (h->table)
	{
	case FW3_TABLE_NAT:
		r = fw3_ipt_rule_create(h, proto, NULL, NULL, ia, ea);
		fw3_ipt_rule_sport_dport(r, NULL, &redir->port_dest);
		fw3_ipt_rule_limit(r, &redir->limit);
		fw3_ipt_rule_time(r, &redir->time);
		set_comment(r, redir->name, num, true);
		set_snat_dnat(r, FW3_FLAG_DNAT, &redir->ip_redir, &redir->port_redir);
		fw3_ipt_rule_replace(r, "zone_%s_prerouting", redir->dest.name);

		r = fw3_ipt_rule_create(h, proto, NULL, NULL, ia, &redir->ip_redir);
		fw3_ipt_rule_sport_dport(r, NULL, &redir->port_redir);
		fw3_ipt_rule_limit(r, &redir->limit);
		fw3_ipt_rule_time(r, &redir->time);
		set_comment(r, redir->name, num, true);
		set_snat_dnat(r, FW3_FLAG_SNAT, ra, NULL);
		fw3_ipt_rule_replace(r, "zone_%s_postrouting", redir->dest.name);
		break;

	default:
		break;
	}
}

static void
expand_redirect(struct fw3_ipt_handle *handle, struct fw3_state *state,
                struct fw3_redirect *redir, int num)
{
	struct list_head *ext_addrs, *int_addrs;
	struct fw3_address *ext_addr, *int_addr, ref_addr;
	struct fw3_protocol *proto;
	struct fw3_mac *mac;

	if (redir->name)
		info("   * Redirect '%s'", redir->name);
	else
		info("   * Redirect #%u", num);

	if (!fw3_is_family(redir->_src, handle->family) ||
		!fw3_is_family(redir->_dest, handle->family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	if (!fw3_is_family(&redir->ip_src, handle->family) ||
	    !fw3_is_family(&redir->ip_dest, handle->family) ||
		!fw3_is_family(&redir->ip_redir, handle->family))
	{
		if (!redir->ip_src.resolved ||
		    !redir->ip_dest.resolved ||
		    !redir->ip_redir.resolved)
			info("     ! Skipping due to different family of ip address");

		return;
	}

	if (redir->ipset.ptr)
	{
		if (!fw3_is_family(redir->ipset.ptr, handle->family))
		{
			info("     ! Skipping due to different family in ipset");
			return;
		}

		if (!fw3_check_ipset(redir->ipset.ptr))
		{
			info("     ! Skipping due to missing ipset '%s'",
			     redir->ipset.ptr->external ?
					redir->ipset.ptr->external : redir->ipset.ptr->name);
			return;
		}

		set(redir->ipset.ptr->flags, handle->family, handle->family);
	}

	fw3_foreach(proto, &redir->proto)
	fw3_foreach(mac, &redir->mac_src)
		print_redirect(handle, state, redir, num, proto, mac);

	/* reflection rules */
	if (redir->target != FW3_FLAG_DNAT || !redir->reflection)
		return;

	if (!redir->_dest || !redir->_src->masq)
		return;

	ext_addrs = fw3_resolve_zone_addresses(redir->_src);
	int_addrs = fw3_resolve_zone_addresses(redir->_dest);

	if (!ext_addrs || !int_addrs)
		goto out;

	list_for_each_entry(ext_addr, ext_addrs, list)
	{
		if (!fw3_is_family(ext_addr, handle->family))
			continue;

		list_for_each_entry(int_addr, int_addrs, list)
		{
			if (!fw3_is_family(int_addr, handle->family))
				continue;

			fw3_foreach(proto, &redir->proto)
			{
				if (!proto)
					continue;

				if (redir->reflection_src == FW3_REFLECTION_INTERNAL)
					ref_addr = *int_addr;
				else
					ref_addr = *ext_addr;

				ref_addr.mask = 32;
				ext_addr->mask = 32;

				print_reflection(handle, state, redir, num, proto,
								 &ref_addr, int_addr, ext_addr);
			}
		}
	}

out:
	fw3_free_list(ext_addrs);
	fw3_free_list(int_addrs);
}

void
fw3_print_redirects(struct fw3_ipt_handle *handle, struct fw3_state *state)
{
	int num = 0;
	struct fw3_redirect *redir;

	if (handle->family == FW3_FAMILY_V6)
		return;

	if (handle->table != FW3_TABLE_FILTER && handle->table != FW3_TABLE_NAT)
		return;

	list_for_each_entry(redir, &state->redirects, list)
		expand_redirect(handle, state, redir, num++);
}
