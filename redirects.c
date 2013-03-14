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

	FW3_OPT("ipset",               device,    redirect,     ipset),

	FW3_LIST("proto",              protocol,  redirect,     proto),

	FW3_OPT("src_ip",              address,   redirect,     ip_src),
	FW3_LIST("src_mac",            mac,       redirect,     mac_src),
	FW3_OPT("src_port",            port,      redirect,     port_src),

	FW3_OPT("src_dip",             address,   redirect,     ip_dest),
	FW3_OPT("src_dport",           port,      redirect,     port_dest),

	FW3_OPT("dest_ip",             address,   redirect,     ip_redir),
	FW3_OPT("dest_port",           port,      redirect,     port_redir),

	FW3_OPT("extra",               string,    redirect,     extra),

	FW3_OPT("utc_time",            bool,      redirect,     time.utc),
	FW3_OPT("start_date",          date,      redirect,     time.datestart),
	FW3_OPT("stop_date",           date,      redirect,     time.datestop),
	FW3_OPT("start_time",          time,      redirect,     time.timestart),
	FW3_OPT("stop_time",           time,      redirect,     time.timestop),
	FW3_OPT("weekdays",            weekdays,  redirect,     time.weekdays),
	FW3_OPT("monthdays",           monthdays, redirect,     time.monthdays),

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

	if (r->_ipset && r->_ipset->family && r->_ipset->family != r->family)
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

void
fw3_load_redirects(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_redirect *redir;

	bool valid = false;

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

		fw3_parse_options(redir, fw3_redirect_opts, s);

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
		         !(redir->_src = fw3_lookup_zone(state, redir->src.name, false)))
		{
			warn_elem(e, "refers to not existing zone '%s'", redir->src.name);
			fw3_free_redirect(redir);
			continue;
		}
		else if (redir->dest.set && !redir->dest.any &&
		         !(redir->_dest = fw3_lookup_zone(state, redir->dest.name, false)))
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
		else if (redir->ipset.set && !redir->ipset.any &&
		         !(redir->_ipset = fw3_lookup_ipset(state, redir->ipset.name, false)))
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
			else
			{
				set(redir->_dest->flags, FW3_FAMILY_V4, redir->target);
				redir->_dest->conntrack = true;
				valid = true;
			}
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
print_chain_nat(struct fw3_redirect *redir)
{
	if (redir->target == FW3_FLAG_DNAT)
		fw3_pr("-A zone_%s_prerouting", redir->src.name);
	else
		fw3_pr("-A zone_%s_postrouting", redir->dest.name);
}

static void
print_snat_dnat(enum fw3_flag target,
                struct fw3_address *addr, struct fw3_port *port)
{
	const char *t;
	char s[sizeof("255.255.255.255 ")];

	if (target == FW3_FLAG_DNAT)
		t = "DNAT --to-destination";
	else
		t = "SNAT --to-source";

	inet_ntop(AF_INET, &addr->address.v4, s, sizeof(s));

	fw3_pr(" -j %s %s", t, s);

	if (port && port->set)
	{
		if (port->port_min == port->port_max)
			fw3_pr(":%u", port->port_min);
		else
			fw3_pr(":%u-%u", port->port_min, port->port_max);
	}

	fw3_pr("\n");
}

static void
print_target_nat(struct fw3_redirect *redir)
{
	if (redir->target == FW3_FLAG_DNAT)
		print_snat_dnat(redir->target, &redir->ip_redir, &redir->port_redir);
	else
		print_snat_dnat(redir->target, &redir->ip_dest, &redir->port_dest);
}

static void
print_chain_filter(struct fw3_redirect *redir)
{
	if (redir->target == FW3_FLAG_DNAT)
	{
		/* XXX: check for local ip */
		if (!redir->ip_redir.set)
			fw3_pr("-A zone_%s_input", redir->src.name);
		else
			fw3_pr("-A zone_%s_forward", redir->src.name);
	}
	else
	{
		if (redir->src.set && !redir->src.any)
			fw3_pr("-A zone_%s_forward", redir->src.name);
		else
			fw3_pr("-A delegate_forward");
	}
}

static void
print_target_filter(struct fw3_redirect *redir)
{
	/* XXX: check for local ip */
	if (redir->target == FW3_FLAG_DNAT && !redir->ip_redir.set)
		fw3_pr(" -m conntrack --ctstate DNAT -j ACCEPT\n");
	else
		fw3_pr(" -j ACCEPT\n");
}

static void
print_redirect(struct fw3_state *state, enum fw3_family family,
               enum fw3_table table, struct fw3_redirect *redir, int num)
{
	struct list_head *ext_addrs, *int_addrs;
	struct fw3_address *ext_addr, *int_addr, ref_addr;
	struct fw3_device *ext_net, *int_net;
	struct fw3_protocol *proto;
	struct fw3_mac *mac;

	if (redir->name)
		info("   * Redirect '%s'", redir->name);
	else
		info("   * Redirect #%u", num);

	if (!fw3_is_family(redir->_src, family) ||
		!fw3_is_family(redir->_dest, family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	if (!fw3_is_family(&redir->ip_src, family) ||
	    !fw3_is_family(&redir->ip_dest, family) ||
		!fw3_is_family(&redir->ip_redir, family))
	{
		info("     ! Skipping due to different family of ip address");
		return;
	}

	if (redir->_ipset)
	{
		if (!fw3_is_family(redir->_ipset, family))
		{
			info("     ! Skipping due to different family in ipset");
			return;
		}

		set(redir->_ipset->flags, family, family);
	}

	fw3_foreach(proto, &redir->proto)
	fw3_foreach(mac, &redir->mac_src)
	{
		if (table == FW3_TABLE_NAT)
		{
			print_chain_nat(redir);
			fw3_format_ipset(redir->_ipset, redir->ipset.invert);
			fw3_format_protocol(proto, family);

			if (redir->target == FW3_FLAG_DNAT)
			{
				fw3_format_src_dest(&redir->ip_src, &redir->ip_dest);
				fw3_format_sport_dport(&redir->port_src, &redir->port_dest);
			}
			else
			{
				fw3_format_src_dest(&redir->ip_src, &redir->ip_redir);
				fw3_format_sport_dport(&redir->port_src, &redir->port_redir);
			}

			fw3_format_mac(mac);
			fw3_format_time(&redir->time);
			fw3_format_extra(redir->extra);
			fw3_format_comment(redir->name);
			print_target_nat(redir);
		}
		else if (table == FW3_TABLE_FILTER)
		{
			print_chain_filter(redir);
			fw3_format_ipset(redir->_ipset, redir->ipset.invert);
			fw3_format_protocol(proto, family);
			fw3_format_src_dest(&redir->ip_src, &redir->ip_redir);
			fw3_format_sport_dport(&redir->port_src, &redir->port_redir);
			fw3_format_mac(mac);
			fw3_format_time(&redir->time);
			fw3_format_extra(redir->extra);
			fw3_format_comment(redir->name);
			print_target_filter(redir);
		}
	}

	/* reflection rules */
	if (redir->target != FW3_FLAG_DNAT || !redir->reflection)
		return;

	if (!redir->_dest || !redir->_src->masq)
		return;

	list_for_each_entry(ext_net, &redir->_src->networks, list)
	{
		ext_addrs = fw3_ubus_address(ext_net->name);

		if (!ext_addrs || list_empty(ext_addrs))
			continue;

		list_for_each_entry(int_net, &redir->_dest->networks, list)
		{
			int_addrs = fw3_ubus_address(int_net->name);

			if (!int_addrs || list_empty(int_addrs))
				continue;

			fw3_foreach(ext_addr, ext_addrs)
			fw3_foreach(int_addr, int_addrs)
			fw3_foreach(proto, &redir->proto)
			{
				if (!fw3_is_family(int_addr, family) ||
				    !fw3_is_family(ext_addr, family))
					continue;

				if (!proto || (proto->protocol != 6 && proto->protocol != 17))
					continue;

				if (redir->reflection_src == FW3_REFLECTION_INTERNAL)
					ref_addr = *int_addr;
				else
					ref_addr = *ext_addr;

				ref_addr.mask = 32;
				ext_addr->mask = 32;

				if (table == FW3_TABLE_NAT)
				{
					fw3_pr("-A zone_%s_prerouting", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, ext_addr);
					fw3_format_sport_dport(NULL, &redir->port_dest);
					fw3_format_time(&redir->time);
					fw3_format_comment(redir->name, " (reflection)");
					print_snat_dnat(FW3_FLAG_DNAT,
					                &redir->ip_redir, &redir->port_redir);

					fw3_pr("-A zone_%s_postrouting", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, &redir->ip_redir);
					fw3_format_sport_dport(NULL, &redir->port_redir);
					fw3_format_time(&redir->time);
					fw3_format_comment(redir->name, " (reflection)");
					print_snat_dnat(FW3_FLAG_SNAT, &ref_addr, NULL);
				}
				else if (table == FW3_TABLE_FILTER)
				{
					fw3_pr("-A zone_%s_forward", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, &redir->ip_redir);
					fw3_format_sport_dport(NULL, &redir->port_redir);
					fw3_format_time(&redir->time);
					fw3_format_comment(redir->name, " (reflection)");
					fw3_pr(" -j zone_%s_dest_ACCEPT\n", redir->dest.name);
				}
			}

			fw3_ubus_address_free(int_addrs);
		}

		fw3_ubus_address_free(ext_addrs);
	}
}

void
fw3_print_redirects(struct fw3_state *state, enum fw3_family family,
                    enum fw3_table table)
{
	int num = 0;
	struct fw3_redirect *redir;

	if (family == FW3_FAMILY_V6)
		return;

	if (table != FW3_TABLE_FILTER && table != FW3_TABLE_NAT)
		return;

	list_for_each_entry(redir, &state->redirects, list)
		print_redirect(state, family, table, redir, num++);
}
