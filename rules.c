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

#include "rules.h"


static struct fw3_option rule_opts[] = {
	FW3_OPT("name",                string,   rule,     name),
	FW3_OPT("family",              family,   rule,     family),

	FW3_OPT("src",                 device,   rule,     src),
	FW3_OPT("dest",                device,   rule,     dest),

	FW3_OPT("ipset",               device,   rule,     ipset),

	FW3_LIST("proto",              protocol, rule,     proto),

	FW3_LIST("src_ip",             address,  rule,     ip_src),
	FW3_LIST("src_mac",            mac,      rule,     mac_src),
	FW3_LIST("src_port",           port,     rule,     port_src),

	FW3_LIST("dest_ip",            address,  rule,     ip_dest),
	FW3_LIST("dest_port",          port,     rule,     port_dest),

	FW3_LIST("icmp_type",          icmptype, rule,     icmp_type),
	FW3_OPT("extra",               string,   rule,     extra),

	FW3_OPT("limit",               limit,    rule,     limit),
	FW3_OPT("limit_burst",         int,      rule,     limit.burst),

	FW3_OPT("target",              target,   rule,     target),
};


void
fw3_load_rules(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_rule *rule;

	INIT_LIST_HEAD(&state->rules);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "rule"))
			continue;

		rule = malloc(sizeof(*rule));

		if (!rule)
			continue;

		memset(rule, 0, sizeof(*rule));

		INIT_LIST_HEAD(&rule->proto);

		INIT_LIST_HEAD(&rule->ip_src);
		INIT_LIST_HEAD(&rule->mac_src);
		INIT_LIST_HEAD(&rule->port_src);

		INIT_LIST_HEAD(&rule->ip_dest);
		INIT_LIST_HEAD(&rule->port_dest);

		INIT_LIST_HEAD(&rule->icmp_type);

		fw3_parse_options(rule, rule_opts, ARRAY_SIZE(rule_opts), s);

		if (rule->src.invert || rule->dest.invert)
		{
			warn_elem(e, "must not have inverted 'src' or 'dest' options");
			fw3_free_rule(rule);
			continue;
		}
		else if (rule->src.set && !rule->src.any &&
		         !(rule->_src = fw3_lookup_zone(state, rule->src.name)))
		{
			warn_elem(e, "refers to not existing zone '%s'", rule->src.name);
			fw3_free_rule(rule);
			continue;
		}
		else if (rule->dest.set && !rule->dest.any &&
		         !(rule->_dest = fw3_lookup_zone(state, rule->dest.name)))
		{
			warn_elem(e, "refers to not existing zone '%s'", rule->dest.name);
			fw3_free_rule(rule);
			continue;
		}
		else if (rule->ipset.set && state->disable_ipsets)
		{
			warn_elem(e, "skipped due to disabled ipset support");
			fw3_free_rule(rule);
			continue;
		}
		else if (rule->ipset.set && !rule->ipset.any &&
		         !(rule->_ipset = fw3_lookup_ipset(state, rule->ipset.name)))
		{
			warn_elem(e, "refers to not declared ipset '%s'", rule->ipset.name);
			fw3_free_rule(rule);
			continue;
		}

		if (!rule->_src && rule->target == FW3_TARGET_NOTRACK)
		{
			warn_elem(e, "is set to target NOTRACK but has no source assigned");
			fw3_free_rule(rule);
			continue;
		}

		if (!rule->_src && !rule->_dest && !rule->src.any && !rule->dest.any)
		{
			warn_elem(e, "has neither a source nor a destination zone assigned "
			             "- assuming an output rule");
		}

		if (rule->target == FW3_TARGET_UNSPEC)
		{
			warn_elem(e, "has no target specified, defaulting to REJECT");
			rule->target = FW3_TARGET_REJECT;
		}
		else if (rule->target > FW3_TARGET_NOTRACK)
		{
			warn_elem(e, "has invalid target specified, defaulting to REJECT");
			rule->target = FW3_TARGET_REJECT;
		}

		if (rule->_dest)
			setbit(rule->_dest->dst_flags, rule->target);

		list_add_tail(&rule->list, &state->rules);
		continue;
	}
}


static void
print_chain(struct fw3_rule *rule)
{
	char chain[256];

	sprintf(chain, "delegate_output");

	if (rule->target == FW3_TARGET_NOTRACK)
	{
		sprintf(chain, "zone_%s_notrack", rule->src.name);
	}
	else
	{
		if (rule->src.set)
		{
			if (!rule->src.any)
			{
				if (rule->dest.set)
					sprintf(chain, "zone_%s_forward", rule->src.name);
				else
					sprintf(chain, "zone_%s_input", rule->src.name);
			}
			else
			{
				if (rule->dest.set)
					sprintf(chain, "delegate_forward");
				else
					sprintf(chain, "delegate_input");
			}
		}

		if (rule->dest.set && !rule->src.set)
			sprintf(chain, "zone_%s_output", rule->dest.name);
	}

	fw3_pr("-A %s", chain);
}

static void print_target(struct fw3_rule *rule)
{
	char target[256];

	switch(rule->target)
	{
	case FW3_TARGET_ACCEPT:
		sprintf(target, "ACCEPT");
		break;

	case FW3_TARGET_DROP:
		sprintf(target, "DROP");
		break;

	case FW3_TARGET_NOTRACK:
		sprintf(target, "NOTRACK");
		break;

	default:
		sprintf(target, "REJECT");
		break;
	}

	if (rule->dest.set && !rule->dest.any)
		fw3_pr(" -j zone_%s_dest_%s\n", rule->dest.name, target);
	else if (!strcmp(target, "REJECT"))
		fw3_pr(" -j reject\n");
	else
		fw3_pr(" -j %s\n", target);
}

static void
print_rule(enum fw3_table table, enum fw3_family family,
           struct fw3_rule *rule, struct fw3_protocol *proto,
           struct fw3_address *sip, struct fw3_address *dip,
           struct fw3_port *sport, struct fw3_port *dport,
           struct fw3_mac *mac, struct fw3_icmptype *icmptype)
{
	if (!fw3_is_family(sip, family) || !fw3_is_family(dip, family))
		return;

	if (proto->protocol == 58 && family == FW3_FAMILY_V4)
		return;

	print_chain(rule);
	fw3_format_ipset(rule->_ipset, rule->ipset.invert);
	fw3_format_protocol(proto, family);
	fw3_format_src_dest(sip, dip);
	fw3_format_sport_dport(sport, dport);
	fw3_format_icmptype(icmptype, family);
	fw3_format_mac(mac);
	fw3_format_limit(&rule->limit);
	fw3_format_extra(rule->extra);
	fw3_format_comment(rule->name);
	print_target(rule);
}

static void
expand_rule(enum fw3_table table, enum fw3_family family,
            struct fw3_rule *rule, int num)
{
	struct fw3_protocol *proto;
	struct fw3_address *sip;
	struct fw3_address *dip;
	struct fw3_port *sport;
	struct fw3_port *dport;
	struct fw3_mac *mac;
	struct fw3_icmptype *icmptype;

	struct list_head *sports = NULL;
	struct list_head *dports = NULL;
	struct list_head *icmptypes = NULL;

	struct list_head empty;
	INIT_LIST_HEAD(&empty);

	if (!fw3_is_family(rule, family))
		return;

	if ((table == FW3_TABLE_RAW && rule->target != FW3_TARGET_NOTRACK) ||
	    (table != FW3_TABLE_FILTER))
		return;

	if (rule->name)
		info("   * Rule '%s'", rule->name);
	else
		info("   * Rule #%u", num);

	list_for_each_entry(proto, &rule->proto, list)
	{
		/* icmp / ipv6-icmp */
		if (proto->protocol == 1 || proto->protocol == 58)
		{
			sports = &empty;
			dports = &empty;
			icmptypes = &rule->icmp_type;
		}
		else
		{
			sports = &rule->port_src;
			dports = &rule->port_dest;
			icmptypes = &empty;
		}

		fw3_foreach(sip, &rule->ip_src)
		fw3_foreach(dip, &rule->ip_dest)
		fw3_foreach(sport, sports)
		fw3_foreach(dport, dports)
		fw3_foreach(mac, &rule->mac_src)
		fw3_foreach(icmptype, icmptypes)
			print_rule(table, family, rule, proto, sip, dip, sport, dport,
			           mac, icmptype);
	}
}

void
fw3_print_rules(enum fw3_table table, enum fw3_family family,
                struct fw3_state *state)
{
	int num = 0;
	struct fw3_rule *rule;

	list_for_each_entry(rule, &state->rules, list)
		expand_rule(table, family, rule, num++);
}

void
fw3_free_rule(struct fw3_rule *rule)
{
	fw3_free_list(&rule->proto);

	fw3_free_list(&rule->ip_src);
	fw3_free_list(&rule->mac_src);
	fw3_free_list(&rule->port_dest);

	fw3_free_list(&rule->ip_dest);
	fw3_free_list(&rule->port_dest);

	fw3_free_list(&rule->icmp_type);

	free(rule);
}
