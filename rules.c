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

#include "rules.h"


const struct fw3_option fw3_rule_opts[] = {
	FW3_OPT("enabled",             bool,      rule,     enabled),

	FW3_OPT("name",                string,    rule,     name),
	FW3_OPT("family",              family,    rule,     family),

	FW3_OPT("src",                 device,    rule,     src),
	FW3_OPT("dest",                device,    rule,     dest),

	FW3_OPT("device",              string,    rule,     device),
	FW3_OPT("direction",           direction, rule,     direction_out),

	FW3_OPT("ipset",               setmatch,  rule,     ipset),

	FW3_LIST("proto",              protocol,  rule,     proto),

	FW3_LIST("src_ip",             network,   rule,     ip_src),
	FW3_LIST("src_mac",            mac,       rule,     mac_src),
	FW3_LIST("src_port",           port,      rule,     port_src),

	FW3_LIST("dest_ip",            network,   rule,     ip_dest),
	FW3_LIST("dest_port",          port,      rule,     port_dest),

	FW3_LIST("icmp_type",          icmptype,  rule,     icmp_type),
	FW3_OPT("extra",               string,    rule,     extra),

	FW3_OPT("limit",               limit,     rule,     limit),
	FW3_OPT("limit_burst",         int,       rule,     limit.burst),

	FW3_OPT("utc_time",            bool,      rule,     time.utc),
	FW3_OPT("start_date",          date,      rule,     time.datestart),
	FW3_OPT("stop_date",           date,      rule,     time.datestop),
	FW3_OPT("start_time",          time,      rule,     time.timestart),
	FW3_OPT("stop_time",           time,      rule,     time.timestop),
	FW3_OPT("weekdays",            weekdays,  rule,     time.weekdays),
	FW3_OPT("monthdays",           monthdays, rule,     time.monthdays),

	FW3_OPT("mark",                mark,      rule,     mark),
	FW3_OPT("set_mark",            mark,      rule,     set_mark),
	FW3_OPT("set_xmark",           mark,      rule,     set_xmark),

	FW3_OPT("target",              target,    rule,     target),

	{ }
};


static bool
need_src_action_chain(struct fw3_rule *r)
{
	return (r->_src && r->_src->log && (r->target > FW3_FLAG_ACCEPT));
}

static struct fw3_rule*
alloc_rule(struct fw3_state *state)
{
	struct fw3_rule *rule = calloc(1, sizeof(*rule));

	if (rule) {
		INIT_LIST_HEAD(&rule->proto);

		INIT_LIST_HEAD(&rule->ip_src);
		INIT_LIST_HEAD(&rule->mac_src);
		INIT_LIST_HEAD(&rule->port_src);

		INIT_LIST_HEAD(&rule->ip_dest);
		INIT_LIST_HEAD(&rule->port_dest);

		INIT_LIST_HEAD(&rule->icmp_type);

		list_add_tail(&rule->list, &state->rules);
		rule->enabled = true;
	}

	return rule;
}

static bool
check_rule(struct fw3_state *state, struct fw3_rule *r, struct uci_element *e)
{
	if (!r->enabled)
		return false;

	if (r->src.invert || r->dest.invert)
	{
		warn_section("rule", r, e, "must not have inverted 'src' or 'dest' options");
		return false;
	}
	else if (r->src.set && !r->src.any &&
	         !(r->_src = fw3_lookup_zone(state, r->src.name)))
	{
		warn_section("rule", r, e, "refers to not existing zone '%s'", r->src.name);
		return false;
	}
	else if (r->dest.set && !r->dest.any &&
	         !(r->_dest = fw3_lookup_zone(state, r->dest.name)))
	{
		warn_section("rule", r, e, "refers to not existing zone '%s'", r->dest.name);
		return false;
	}
	else if (r->ipset.set && state->disable_ipsets)
	{
		warn_section("rule", r, e, "skipped due to disabled ipset support");
		return false;
	}
	else if (r->ipset.set &&
	         !(r->ipset.ptr = fw3_lookup_ipset(state, r->ipset.name)))
	{
		warn_section("rule", r, e, "refers to unknown ipset '%s'", r->ipset.name);
		return false;
	}

	if (!r->_src && r->target == FW3_FLAG_NOTRACK)
	{
		warn_section("rule", r, e, "is set to target NOTRACK but has no source assigned");
		return false;
	}

	if (!r->set_mark.set && !r->set_xmark.set &&
	    r->target == FW3_FLAG_MARK)
	{
		warn_section("rule", r, e, "is set to target MARK but specifies neither "
		                "'set_mark' nor 'set_xmark' option");
		return false;
	}

	if (r->_dest && r->target == FW3_FLAG_MARK)
	{
		warn_section("rule", r, e, "must not specify 'dest' for MARK target");
		return false;
	}

	if (r->set_mark.invert || r->set_xmark.invert)
	{
		warn_section("rule", r, e, "must not have inverted 'set_mark' or 'set_xmark'");
		return false;
	}

	if (!r->_src && !r->_dest && !r->src.any && !r->dest.any)
	{
		warn_section("rule", r, e, "has neither a source nor a destination zone assigned "
		                "- assuming an output r");
	}

	if (list_empty(&r->proto))
	{
		warn_section("rule", r, e, "does not specify a protocol, assuming TCP+UDP");
		fw3_parse_protocol(&r->proto, "tcpudp", true);
	}

	if (r->target == FW3_FLAG_UNSPEC)
	{
		warn_section("rule", r, e, "has no target specified, defaulting to REJECT");
		r->target = FW3_FLAG_REJECT;
	}
	else if (r->target > FW3_FLAG_MARK)
	{
		warn_section("rule", r, e, "has invalid target specified, defaulting to REJECT");
		r->target = FW3_FLAG_REJECT;
	}

	/* NB: r family... */
	if (r->_dest)
	{
		fw3_setbit(r->_dest->flags[0], r->target);
		fw3_setbit(r->_dest->flags[1], r->target);
	}
	else if (need_src_action_chain(r))
	{
		fw3_setbit(r->_src->flags[0], fw3_to_src_target(r->target));
		fw3_setbit(r->_src->flags[1], fw3_to_src_target(r->target));
	}

	return true;
}

void
fw3_load_rules(struct fw3_state *state, struct uci_package *p,
		struct blob_attr *a)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_rule *rule;
	struct blob_attr *entry;
	unsigned rem;

	INIT_LIST_HEAD(&state->rules);

	blob_for_each_attr(entry, a, rem) {
		const char *type;
		const char *name = "ubus rule";

		if (!fw3_attr_parse_name_type(entry, &name, &type))
			continue;

		if (strcmp(type, "rule"))
			continue;

		if (!(rule = alloc_rule(state)))
			continue;

		if (!fw3_parse_blob_options(rule, fw3_rule_opts, entry, name))
		{
			warn_section("rule", rule, NULL, "skipped due to invalid options");
			fw3_free_rule(rule);
			continue;
		}

		if (!check_rule(state, rule, NULL))
			fw3_free_rule(rule);
	}

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "rule"))
			continue;

		if (!(rule = alloc_rule(state)))
			continue;

		if (!fw3_parse_options(rule, fw3_rule_opts, s))
		{
			warn_elem(e, "skipped due to invalid options");
			fw3_free_rule(rule);
			continue;
		}

		if (!check_rule(state, rule, e))
			fw3_free_rule(rule);
	}
}


static void
append_chain(struct fw3_ipt_rule *r, struct fw3_rule *rule)
{
	char chain[32];

	snprintf(chain, sizeof(chain), "OUTPUT");

	if (rule->target == FW3_FLAG_NOTRACK)
	{
		snprintf(chain, sizeof(chain), "zone_%s_notrack", rule->src.name);
	}
	else if (rule->target == FW3_FLAG_MARK && (rule->_src || rule->src.any))
	{
		snprintf(chain, sizeof(chain), "PREROUTING");
	}
	else
	{
		if (rule->src.set)
		{
			if (!rule->src.any)
			{
				if (rule->dest.set)
					snprintf(chain, sizeof(chain), "zone_%s_forward",
					         rule->src.name);
				else
					snprintf(chain, sizeof(chain), "zone_%s_input",
					         rule->src.name);
			}
			else
			{
				if (rule->dest.set)
					snprintf(chain, sizeof(chain), "FORWARD");
				else
					snprintf(chain, sizeof(chain), "INPUT");
			}
		}

		if (rule->dest.set && !rule->src.set)
		{
			if (rule->dest.any)
				snprintf(chain, sizeof(chain), "OUTPUT");
			else
				snprintf(chain, sizeof(chain), "zone_%s_output",
				         rule->dest.name);
		}
	}

	fw3_ipt_rule_append(r, chain);
}

static void set_target(struct fw3_ipt_rule *r, struct fw3_rule *rule)
{
	const char *name;
	struct fw3_mark *mark;
	char buf[sizeof("0xFFFFFFFF/0xFFFFFFFF\0")];

	switch(rule->target)
	{
	case FW3_FLAG_MARK:
		name = rule->set_mark.set ? "--set-mark" : "--set-xmark";
		mark = rule->set_mark.set ? &rule->set_mark : &rule->set_xmark;
		sprintf(buf, "0x%x/0x%x", mark->mark, mark->mask);

		fw3_ipt_rule_target(r, "MARK");
		fw3_ipt_rule_addarg(r, false, name, buf);
		return;

	case FW3_FLAG_NOTRACK:
		fw3_ipt_rule_target(r, "CT");
		fw3_ipt_rule_addarg(r, false, "--notrack", NULL);
		return;

	case FW3_FLAG_ACCEPT:
	case FW3_FLAG_DROP:
		name = fw3_flag_names[rule->target];
		break;

	default:
		name = fw3_flag_names[FW3_FLAG_REJECT];
		break;
	}

	if (rule->dest.set && !rule->dest.any)
		fw3_ipt_rule_target(r, "zone_%s_dest_%s", rule->dest.name, name);
	else if (need_src_action_chain(rule))
		fw3_ipt_rule_target(r, "zone_%s_src_%s", rule->src.name, name);
	else if (strcmp(name, "REJECT"))
		fw3_ipt_rule_target(r, name);
	else
		fw3_ipt_rule_target(r, "reject");
}

static void
set_comment(struct fw3_ipt_rule *r, const char *name, int num)
{
	if (name)
		fw3_ipt_rule_comment(r, name);
	else
		fw3_ipt_rule_comment(r, "@rule[%u]", num);
}

static void
print_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
           struct fw3_rule *rule, int num, struct fw3_protocol *proto,
           struct fw3_address *sip, struct fw3_address *dip,
           struct fw3_port *sport, struct fw3_port *dport,
           struct fw3_mac *mac, struct fw3_icmptype *icmptype)
{
	struct fw3_ipt_rule *r;

	if (!fw3_is_family(sip, handle->family) ||
	    !fw3_is_family(dip, handle->family))
	{
		if ((sip && !sip->resolved) || (dip && !dip->resolved))
			info("     ! Skipping due to different family of ip address");

		return;
	}

	if (proto->protocol == 58 && handle->family == FW3_FAMILY_V4)
	{
		info("     ! Skipping due to different family of protocol");
		return;
	}

	r = fw3_ipt_rule_create(handle, proto, NULL, NULL, sip, dip);
	fw3_ipt_rule_sport_dport(r, sport, dport);
	fw3_ipt_rule_device(r, rule->device, rule->direction_out);
	fw3_ipt_rule_icmptype(r, icmptype);
	fw3_ipt_rule_mac(r, mac);
	fw3_ipt_rule_ipset(r, &rule->ipset);
	fw3_ipt_rule_limit(r, &rule->limit);
	fw3_ipt_rule_time(r, &rule->time);
	fw3_ipt_rule_mark(r, &rule->mark);
	set_target(r, rule);
	fw3_ipt_rule_extra(r, rule->extra);
	set_comment(r, rule->name, num);
	append_chain(r, rule);
}

static void
expand_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
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

	if (!fw3_is_family(rule, handle->family))
		return;

	if ((rule->target == FW3_FLAG_NOTRACK && handle->table != FW3_TABLE_RAW) ||
	    (rule->target == FW3_FLAG_MARK && handle->table != FW3_TABLE_MANGLE) ||
		(rule->target < FW3_FLAG_NOTRACK && handle->table != FW3_TABLE_FILTER))
		return;

	if (rule->name)
		info("   * Rule '%s'", rule->name);
	else
		info("   * Rule #%u", num);

	if (!fw3_is_family(rule->_src, handle->family) ||
	    !fw3_is_family(rule->_dest, handle->family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	if (rule->ipset.ptr)
	{
		if (!fw3_is_family(rule->ipset.ptr, handle->family))
		{
			info("     ! Skipping due to different family in ipset");
			return;
		}

		if (!fw3_check_ipset(rule->ipset.ptr))
		{
			info("     ! Skipping due to missing ipset '%s'",
			     rule->ipset.ptr->external
					? rule->ipset.ptr->external : rule->ipset.ptr->name);
			return;
		}

		set(rule->ipset.ptr->flags, handle->family, handle->family);
	}

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
			print_rule(handle, state, rule, num, proto, sip, dip,
			           sport, dport, mac, icmptype);
	}
}

void
fw3_print_rules(struct fw3_ipt_handle *handle, struct fw3_state *state)
{
	int num = 0;
	struct fw3_rule *rule;

	list_for_each_entry(rule, &state->rules, list)
		expand_rule(handle, state, rule, num++);
}
