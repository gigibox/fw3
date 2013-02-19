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


static struct fw3_option redirect_opts[] = {
	FW3_OPT("name",                string,   redirect,     name),
	FW3_OPT("family",              family,   redirect,     family),

	FW3_OPT("src",                 device,   redirect,     src),
	FW3_OPT("dest",                device,   redirect,     dest),

	FW3_OPT("ipset",               device,   redirect,     ipset),

	FW3_LIST("proto",              protocol, redirect,     proto),

	FW3_OPT("src_ip",              address,  redirect,     ip_src),
	FW3_LIST("src_mac",            mac,      redirect,     mac_src),
	FW3_OPT("src_port",            port,     redirect,     port_src),

	FW3_OPT("src_dip",             address,  redirect,     ip_dest),
	FW3_OPT("src_dport",           port,     redirect,     port_dest),

	FW3_OPT("dest_ip",             address,  redirect,     ip_redir),
	FW3_OPT("dest_port",           port,     redirect,     port_redir),

	FW3_OPT("extra",               string,   redirect,     extra),

	FW3_OPT("reflection",          bool,     redirect,     reflection),

	FW3_OPT("target",              target,   redirect,     target),
};


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

		redir->reflection = true;

		fw3_parse_options(redir, redirect_opts, ARRAY_SIZE(redirect_opts), s);

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
		else if (redir->ipset.set && !redir->ipset.any &&
		         !(redir->_ipset = fw3_lookup_ipset(state, redir->ipset.name)))
		{
			warn_elem(e, "refers to not declared ipset '%s'", redir->ipset.name);
			fw3_free_redirect(redir);
			continue;
		}

		if (redir->target == FW3_TARGET_UNSPEC)
		{
			warn_elem(e, "has no target specified, defaulting to DNAT");
			redir->target = FW3_TARGET_DNAT;
		}
		else if (redir->target < FW3_TARGET_DNAT)
		{
			warn_elem(e, "has invalid target specified, defaulting to DNAT");
			redir->target = FW3_TARGET_DNAT;
		}

		if (redir->target == FW3_TARGET_DNAT)
		{
			if (redir->src.any)
				warn_elem(e, "must not have source '*' for DNAT target");
			else if (!redir->_src)
				warn_elem(e, "has no source specified");
			else
			{
				setbit(redir->_src->has_dest_target, redir->target);
				redir->_src->conntrack = true;
				valid = true;
			}

			if (redir->reflection && redir->_dest && redir->_src->masq)
			{
				setbit(redir->_dest->has_dest_target, FW3_TARGET_ACCEPT);
				setbit(redir->_dest->has_dest_target, FW3_TARGET_DNAT);
				setbit(redir->_dest->has_dest_target, FW3_TARGET_SNAT);
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
				setbit(redir->_dest->has_dest_target, redir->target);
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
	if (redir->target == FW3_TARGET_DNAT)
		fw3_pr("-A zone_%s_prerouting", redir->src.name);
	else
		fw3_pr("-A zone_%s_postrouting", redir->dest.name);
}

static void
print_snat_dnat(enum fw3_target target,
                struct fw3_address *addr, struct fw3_port *port)
{
	const char *t;
	char s[sizeof("255.255.255.255 ")];

	if (target == FW3_TARGET_DNAT)
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
	if (redir->target == FW3_TARGET_DNAT)
		print_snat_dnat(redir->target, &redir->ip_redir, &redir->port_redir);
	else
		print_snat_dnat(redir->target, &redir->ip_dest, &redir->port_dest);
}

static void
print_chain_filter(struct fw3_redirect *redir)
{
	if (redir->target == FW3_TARGET_DNAT)
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
	if (redir->target == FW3_TARGET_DNAT && !redir->ip_redir.set)
		fw3_pr(" -m conntrack --ctstate DNAT -j ACCEPT\n");
	else
		fw3_pr(" -j ACCEPT\n");
}

static void
print_redirect(enum fw3_table table, enum fw3_family family,
               struct fw3_redirect *redir, int num)
{
	struct list_head *ext_addrs, *int_addrs;
	struct fw3_address *ext_addr, *int_addr;
	struct fw3_device *ext_net, *int_net;
	struct fw3_protocol *proto;
	struct fw3_mac *mac;

	fw3_foreach(proto, &redir->proto)
	fw3_foreach(mac, &redir->mac_src)
	{
		if (table == FW3_TABLE_NAT)
		{
			if (redir->name)
				info("   * Redirect '%s'", redir->name);
			else
				info("   * Redirect #%u", num);

			print_chain_nat(redir);
			fw3_format_ipset(redir->_ipset, redir->ipset.invert);
			fw3_format_protocol(proto, family);

			if (redir->target == FW3_TARGET_DNAT)
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
			fw3_format_extra(redir->extra);
			fw3_format_comment(redir->name);
			print_target_nat(redir);
		}
		else if (table == FW3_TABLE_FILTER)
		{
			if (redir->name)
				info("   * Redirect '%s'", redir->name);
			else
				info("   * Redirect #%u", num);

			print_chain_filter(redir);
			fw3_format_ipset(redir->_ipset, redir->ipset.invert);
			fw3_format_protocol(proto, family);
			fw3_format_src_dest(&redir->ip_src, &redir->ip_redir);
			fw3_format_sport_dport(&redir->port_src, &redir->port_redir);
			fw3_format_mac(mac);
			fw3_format_extra(redir->extra);
			fw3_format_comment(redir->name);
			print_target_filter(redir);
		}
	}

	/* reflection rules */
	if (redir->target != FW3_TARGET_DNAT || !redir->reflection)
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

				ext_addr->mask = 32;

				if (table == FW3_TABLE_NAT)
				{
					fw3_pr("-A zone_%s_prerouting", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, ext_addr);
					fw3_format_sport_dport(NULL, &redir->port_dest);
					fw3_format_comment(redir->name, " (reflection)");
					print_snat_dnat(FW3_TARGET_DNAT,
					                &redir->ip_redir, &redir->port_redir);

					fw3_pr("-A zone_%s_postrouting", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, &redir->ip_redir);
					fw3_format_sport_dport(NULL, &redir->port_redir);
					fw3_format_comment(redir->name, " (reflection)");
					print_snat_dnat(FW3_TARGET_SNAT, ext_addr, NULL);
				}
				else if (table == FW3_TABLE_FILTER)
				{
					fw3_pr("-A zone_%s_forward", redir->dest.name);
					fw3_format_protocol(proto, family);
					fw3_format_src_dest(int_addr, &redir->ip_redir);
					fw3_format_sport_dport(NULL, &redir->port_redir);
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
fw3_print_redirects(enum fw3_table table, enum fw3_family family,
                    struct fw3_state *state)
{
	int num = 0;
	struct fw3_redirect *redir;

	if (family == FW3_FAMILY_V6)
		return;

	list_for_each_entry(redir, &state->redirects, list)
		print_redirect(table, family, redir, num++);
}

void
fw3_free_redirect(struct fw3_redirect *redir)
{
	fw3_free_list(&redir->proto);
	fw3_free_list(&redir->mac_src);
	free(redir);
}
