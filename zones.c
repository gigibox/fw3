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

#include "zones.h"
#include "ubus.h"


#define C(f, tbl, tgt, name) \
	{ FW3_FAMILY_##f, FW3_TABLE_##tbl, FW3_TARGET_##tgt, name }

struct chain {
	enum fw3_family family;
	enum fw3_table table;
	enum fw3_target target;
	const char *name;
};

static const struct chain src_chains[] = {
	C(ANY, FILTER, UNSPEC,  "zone_%s_input"),
	C(ANY, FILTER, UNSPEC,  "zone_%s_output"),
	C(ANY, FILTER, UNSPEC,  "zone_%s_forward"),

	C(ANY, FILTER, ACCEPT,  "zone_%s_src_ACCEPT"),
	C(ANY, FILTER, REJECT,  "zone_%s_src_REJECT"),
	C(ANY, FILTER, DROP,    "zone_%s_src_DROP"),
};

static const struct chain dst_chains[] = {
	C(ANY, FILTER, ACCEPT,  "zone_%s_dest_ACCEPT"),
	C(ANY, FILTER, REJECT,  "zone_%s_dest_REJECT"),
	C(ANY, FILTER, DROP,    "zone_%s_dest_DROP"),

	C(V4,  NAT,    SNAT,    "zone_%s_postrouting"),
	C(V4,  NAT,    DNAT,    "zone_%s_prerouting"),

	C(ANY, RAW,    NOTRACK, "zone_%s_notrack"),
};

static struct fw3_option zone_opts[] = {
	FW3_OPT("name",                string,   zone,     name),

	FW3_LIST("network",            device,   zone,     networks),
	FW3_LIST("device",             device,   zone,     devices),
	FW3_LIST("subnet",             address,  zone,     subnets),

	FW3_OPT("input",               target,   zone,     policy_input),
	FW3_OPT("forward",             target,   zone,     policy_forward),
	FW3_OPT("output",              target,   zone,     policy_output),

	FW3_OPT("masq",                bool,     zone,     masq),
	FW3_LIST("masq_src",           address,  zone,     masq_src),
	FW3_LIST("masq_dest",          address,  zone,     masq_dest),

	FW3_OPT("extra",               string,   zone,     extra_src),
	FW3_OPT("extra_src",           string,   zone,     extra_src),
	FW3_OPT("extra_dest",          string,   zone,     extra_dest),

	FW3_OPT("conntrack",           bool,     zone,     conntrack),
	FW3_OPT("mtu_fix",             bool,     zone,     mtu_fix),
	FW3_OPT("custom_chains",       bool,     zone,     custom_chains),

	FW3_OPT("log",                 bool,     zone,     log),
	FW3_OPT("log_limit",           limit,    zone,     log_limit),
};


static bool
print_chains(enum fw3_table table, enum fw3_family family,
             const char *fmt, const char *name, uint16_t targets,
             const struct chain *chains, int n)
{
	bool rv = false;
	char cn[128] = { 0 };
	const struct chain *c;

	for (c = chains; n > 0; c++, n--)
	{
		if (!fw3_is_family(c, family))
			continue;

		if (c->table != table)
			continue;

		if ((c->target != FW3_TARGET_UNSPEC) && !hasbit(targets, c->target))
			continue;

		snprintf(cn, sizeof(cn), c->name, name);
		fw3_pr(fmt, cn);

		rv = true;
	}

	return rv;
}

static void
check_policy(struct uci_element *e, enum fw3_target *pol, enum fw3_target def,
             const char *name)
{
	if (*pol == FW3_TARGET_UNSPEC)
	{
		warn_elem(e, "has no %s policy specified, using default", name);
		*pol = def;
	}
	else if (*pol > FW3_TARGET_DROP)
	{
		warn_elem(e, "has invalid %s policy, using default", name);
		*pol = def;
	}
}

static void
resolve_networks(struct uci_element *e, struct fw3_zone *zone)
{
	struct fw3_device *net, *tmp;

	list_for_each_entry(net, &zone->networks, list)
	{
		tmp = fw3_ubus_device(net->name);

		if (!tmp)
		{
			warn_elem(e, "cannot resolve device of network '%s'", net->name);
			continue;
		}

		list_add_tail(&tmp->list, &zone->devices);
	}
}

void
fw3_load_zones(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_zone *zone;
	struct fw3_defaults *defs = &state->defaults;

	INIT_LIST_HEAD(&state->zones);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "zone"))
			continue;

		zone = malloc(sizeof(*zone));

		if (!zone)
			continue;

		memset(zone, 0, sizeof(*zone));

		INIT_LIST_HEAD(&zone->networks);
		INIT_LIST_HEAD(&zone->devices);
		INIT_LIST_HEAD(&zone->subnets);
		INIT_LIST_HEAD(&zone->masq_src);
		INIT_LIST_HEAD(&zone->masq_dest);

		zone->log_limit.rate = 10;

		fw3_parse_options(zone, zone_opts, ARRAY_SIZE(zone_opts), s);

		if (!zone->extra_dest)
			zone->extra_dest = zone->extra_src;

		if (!zone->name || !*zone->name)
		{
			warn_elem(e, "has no name - ignoring");
			fw3_free_zone(zone);
			continue;
		}

		if (list_empty(&zone->networks) && list_empty(&zone->devices) &&
		    list_empty(&zone->subnets) && !zone->extra_src)
		{
			warn_elem(e, "has no device, network, subnet or extra options");
		}

		check_policy(e, &zone->policy_input, defs->policy_input, "input");
		check_policy(e, &zone->policy_output, defs->policy_output, "output");
		check_policy(e, &zone->policy_forward, defs->policy_forward, "forward");

		resolve_networks(e, zone);

		if (zone->masq)
		{
			setbit(zone->dst_flags, FW3_TARGET_SNAT);
			zone->conntrack = true;
		}

		setbit(zone->src_flags, zone->policy_input);
		setbit(zone->dst_flags, zone->policy_output);
		setbit(zone->dst_flags, zone->policy_forward);

		list_add_tail(&zone->list, &state->zones);
	}
}


static void
print_zone_chain(enum fw3_table table, enum fw3_family family,
                 struct fw3_zone *zone, bool disable_notrack)
{
	bool s, d;

	if (!fw3_is_family(zone, family))
		return;

	if (!zone->conntrack && !disable_notrack)
		setbit(zone->dst_flags, FW3_TARGET_NOTRACK);

	s = print_chains(table, family, ":%s - [0:0]\n", zone->name,
	                 zone->src_flags, src_chains, ARRAY_SIZE(src_chains));

	d = print_chains(table, family, ":%s - [0:0]\n", zone->name,
	                 zone->dst_flags, dst_chains, ARRAY_SIZE(dst_chains));

	if (s || d)
		info("   * Zone '%s'", zone->name);
}

static void
print_interface_rule(enum fw3_table table, enum fw3_family family,
                     struct fw3_zone *zone, struct fw3_device *dev,
                     struct fw3_address *sub, bool disable_notrack)
{
	enum fw3_target t;

#define jump_target(t) \
	((t == FW3_TARGET_REJECT) ? "reject" : fw3_flag_names[t])

	if (table == FW3_TABLE_FILTER)
	{
		for (t = FW3_TARGET_ACCEPT; t <= FW3_TARGET_DROP; t++)
		{
			if (hasbit(zone->src_flags, t))
			{
				fw3_pr("-A zone_%s_src_%s", zone->name, fw3_flag_names[t]);
				fw3_format_in_out(dev, NULL);
				fw3_format_src_dest(sub, NULL);
				fw3_format_extra(zone->extra_src);
				fw3_pr(" -j %s\n", jump_target(t));
			}

			if (hasbit(zone->dst_flags, t))
			{
				fw3_pr("-A zone_%s_dest_%s", zone->name, fw3_flag_names[t]);
				fw3_format_in_out(NULL, dev);
				fw3_format_src_dest(NULL, sub);
				fw3_format_extra(zone->extra_dest);
				fw3_pr(" -j %s\n", jump_target(t));
			}
		}

		fw3_pr("-A delegate_input");
		fw3_format_in_out(dev, NULL);
		fw3_format_src_dest(sub, NULL);
		fw3_format_extra(zone->extra_src);
		fw3_pr(" -j zone_%s_input\n", zone->name);

		fw3_pr("-A delegate_forward");
		fw3_format_in_out(dev, NULL);
		fw3_format_src_dest(sub, NULL);
		fw3_format_extra(zone->extra_src);
		fw3_pr(" -j zone_%s_forward\n", zone->name);

		fw3_pr("-A delegate_output");
		fw3_format_in_out(NULL, dev);
		fw3_format_src_dest(NULL, sub);
		fw3_format_extra(zone->extra_dest);
		fw3_pr(" -j zone_%s_output\n", zone->name);
	}
	else if (table == FW3_TABLE_NAT)
	{
		if (hasbit(zone->dst_flags, FW3_TARGET_DNAT))
		{
			fw3_pr("-A delegate_prerouting");
			fw3_format_in_out(dev, NULL);
			fw3_format_src_dest(sub, NULL);
			fw3_format_extra(zone->extra_src);
			fw3_pr(" -j zone_%s_prerouting\n", zone->name);
		}

		if (hasbit(zone->dst_flags, FW3_TARGET_SNAT))
		{
			fw3_pr("-A delegate_postrouting");
			fw3_format_in_out(NULL, dev);
			fw3_format_src_dest(NULL, sub);
			fw3_format_extra(zone->extra_dest);
			fw3_pr(" -j zone_%s_postrouting\n", zone->name);
		}
	}
	else if (table == FW3_TABLE_MANGLE)
	{
		if (zone->mtu_fix)
		{
			if (zone->log)
			{
				fw3_pr("-A mssfix");
				fw3_format_in_out(NULL, dev);
				fw3_format_src_dest(NULL, sub);
				fw3_pr(" -p tcp --tcp-flags SYN,RST SYN");
				fw3_format_limit(&zone->log_limit);
				fw3_format_comment(zone->name, " (mtu_fix logging)");
				fw3_pr(" -j LOG --log-prefix \"MSSFIX(%s): \"\n", zone->name);
			}

			fw3_pr("-A mssfix");
			fw3_format_in_out(NULL, dev);
			fw3_format_src_dest(NULL, sub);
			fw3_pr(" -p tcp --tcp-flags SYN,RST SYN");
			fw3_format_comment(zone->name, " (mtu_fix)");
			fw3_pr(" -j TCPMSS --clamp-mss-to-pmtu\n");
		}
	}
	else if (table == FW3_TABLE_RAW)
	{
		if (!zone->conntrack && !disable_notrack)
		{
			fw3_pr("-A notrack");
			fw3_format_in_out(dev, NULL);
			fw3_format_src_dest(sub, NULL);
			fw3_format_extra(zone->extra_src);
			fw3_format_comment(zone->name, " (notrack)");
			fw3_pr(" -j CT --notrack\n", zone->name);
		}
	}
}

static void
print_interface_rules(enum fw3_table table, enum fw3_family family,
                      struct fw3_zone *zone, bool disable_notrack)
{
	struct fw3_device *dev;
	struct fw3_address *sub;

	fw3_foreach(dev, &zone->devices)
	fw3_foreach(sub, &zone->subnets)
	{
		if (!fw3_is_family(sub, family))
			continue;

		if (!dev && !sub)
			continue;

		print_interface_rule(table, family, zone, dev, sub, disable_notrack);
	}
}

static void
print_zone_rule(enum fw3_table table, enum fw3_family family,
                struct fw3_zone *zone, bool disable_notrack)
{
	struct fw3_address *msrc;
	struct fw3_address *mdest;

	enum fw3_target t;

	if (!fw3_is_family(zone, family))
		return;

	switch (table)
	{
	case FW3_TABLE_FILTER:
		fw3_pr("-A zone_%s_input -j zone_%s_src_%s\n",
			   zone->name, zone->name, fw3_flag_names[zone->policy_input]);

		fw3_pr("-A zone_%s_forward -j zone_%s_dest_%s\n",
			   zone->name, zone->name, fw3_flag_names[zone->policy_forward]);

		fw3_pr("-A zone_%s_output -j zone_%s_dest_%s\n",
			   zone->name, zone->name, fw3_flag_names[zone->policy_output]);

		if (zone->log)
		{
			for (t = FW3_TARGET_REJECT; t <= FW3_TARGET_DROP; t++)
			{
				if (hasbit(zone->src_flags, t))
				{
					fw3_pr("-A zone_%s_src_%s", zone->name, fw3_flag_names[t]);
					fw3_format_limit(&zone->log_limit);
					fw3_pr(" -j LOG --log-prefix \"%s(src %s)\"\n",
						   fw3_flag_names[t], zone->name);
				}

				if (hasbit(zone->dst_flags, t))
				{
					fw3_pr("-A zone_%s_dest_%s", zone->name, fw3_flag_names[t]);
					fw3_format_limit(&zone->log_limit);
					fw3_pr(" -j LOG --log-prefix \"%s(dest %s)\"\n",
						   fw3_flag_names[t], zone->name);
				}
			}
		}
		break;

	case FW3_TABLE_NAT:
		if (zone->masq && family == FW3_FAMILY_V4)
		{
			fw3_foreach(msrc, &zone->masq_src)
			fw3_foreach(mdest, &zone->masq_dest)
			{
				fw3_pr("-A zone_%s_postrouting ", zone->name);
				fw3_format_src_dest(msrc, mdest);
				fw3_pr("-j MASQUERADE\n");
			}
		}
		break;

	case FW3_TABLE_RAW:
	case FW3_TABLE_MANGLE:
		break;
	}

	print_interface_rules(table, family, zone, disable_notrack);
}

void
fw3_print_zone_chains(enum fw3_table table, enum fw3_family family,
                      struct fw3_state *state)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_chain(table, family, zone, state->defaults.drop_invalid);
}

void
fw3_print_zone_rules(enum fw3_table table, enum fw3_family family,
                     struct fw3_state *state)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_rule(table, family, zone, state->defaults.drop_invalid);
}

void
fw3_flush_zones(enum fw3_table table, enum fw3_family family,
			    bool pass2, struct list_head *statefile)
{
	struct fw3_statefile_entry *e;

	list_for_each_entry(e, statefile, list)
	{
		if (e->type != FW3_TYPE_ZONE)
			continue;

		print_chains(table, family, pass2 ? "-X %s\n" : "-F %s\n",
		             e->name, e->flags[0], src_chains, ARRAY_SIZE(src_chains));

		print_chains(table, family, pass2 ? "-X %s\n" : "-F %s\n",
		             e->name, e->flags[1], dst_chains, ARRAY_SIZE(dst_chains));
	}
}

struct fw3_zone *
fw3_lookup_zone(struct fw3_state *state, const char *name)
{
	struct fw3_zone *z;

	if (list_empty(&state->zones))
		return NULL;

	list_for_each_entry(z, &state->zones, list)
		if (!strcmp(z->name, name))
			return z;

	return NULL;
}

void
fw3_free_zone(struct fw3_zone *zone)
{
	fw3_free_list(&zone->networks);
	fw3_free_list(&zone->devices);
	fw3_free_list(&zone->subnets);

	fw3_free_list(&zone->masq_src);
	fw3_free_list(&zone->masq_dest);

	free(zone);
}
