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


#define C(f, tbl, tgt, fmt) \
	{ FW3_FAMILY_##f, FW3_TABLE_##tbl, FW3_FLAG_##tgt, fmt }

static const struct fw3_rule_spec zone_chains[] = {
	C(ANY, FILTER, UNSPEC,        "zone_%1$s_input"),
	C(ANY, FILTER, UNSPEC,        "zone_%1$s_output"),
	C(ANY, FILTER, UNSPEC,        "zone_%1$s_forward"),

	C(ANY, FILTER, SRC_ACCEPT,    "zone_%1$s_src_ACCEPT"),
	C(ANY, FILTER, SRC_REJECT,    "zone_%1$s_src_REJECT"),
	C(ANY, FILTER, SRC_DROP,      "zone_%1$s_src_DROP"),

	C(ANY, FILTER, ACCEPT,        "zone_%1$s_dest_ACCEPT"),
	C(ANY, FILTER, REJECT,        "zone_%1$s_dest_REJECT"),
	C(ANY, FILTER, DROP,          "zone_%1$s_dest_DROP"),

	C(V4,  NAT,    SNAT,          "zone_%1$s_postrouting"),
	C(V4,  NAT,    DNAT,          "zone_%1$s_prerouting"),

	C(ANY, FILTER, CUSTOM_CHAINS, "input_%1$s_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "output_%1$s_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "forwarding_%1$s_rule"),

	C(V4,  NAT,    CUSTOM_CHAINS, "prerouting_%1$s_rule"),
	C(V4,  NAT,    CUSTOM_CHAINS, "postrouting_%1$s_rule"),

	{ }
};


#define R(dir1, dir2) \
	"zone_%1$s_" #dir1 " -m comment --comment \"user chain for %1$s " \
	#dir2 "\" -j " #dir2 "_%1$s_rule"

static const struct fw3_rule_spec zone_rules[] = {
	C(ANY, FILTER, CUSTOM_CHAINS, R(input, input)),
	C(ANY, FILTER, CUSTOM_CHAINS, R(output, output)),
	C(ANY, FILTER, CUSTOM_CHAINS, R(forward, forwarding)),

	C(V4,  NAT,    CUSTOM_CHAINS, R(prerouting, prerouting)),
	C(V4,  NAT,    CUSTOM_CHAINS, R(postrouting, postrouting)),

	{ }
};

const struct fw3_option fw3_zone_opts[] = {
	FW3_OPT("enabled",             bool,     zone,     enabled),

	FW3_OPT("name",                string,   zone,     name),
	FW3_OPT("family",              family,   zone,     family),

	FW3_LIST("network",            device,   zone,     networks),
	FW3_LIST("device",             device,   zone,     devices),
	FW3_LIST("subnet",             network,  zone,     subnets),

	FW3_OPT("input",               target,   zone,     policy_input),
	FW3_OPT("forward",             target,   zone,     policy_forward),
	FW3_OPT("output",              target,   zone,     policy_output),

	FW3_OPT("masq",                bool,     zone,     masq),
	FW3_LIST("masq_src",           network,  zone,     masq_src),
	FW3_LIST("masq_dest",          network,  zone,     masq_dest),

	FW3_OPT("extra",               string,   zone,     extra_src),
	FW3_OPT("extra_src",           string,   zone,     extra_src),
	FW3_OPT("extra_dest",          string,   zone,     extra_dest),

	FW3_OPT("conntrack",           bool,     zone,     conntrack),
	FW3_OPT("mtu_fix",             bool,     zone,     mtu_fix),
	FW3_OPT("custom_chains",       bool,     zone,     custom_chains),

	FW3_OPT("log",                 bool,     zone,     log),
	FW3_OPT("log_limit",           limit,    zone,     log_limit),

	{ }
};


static void
check_policy(struct uci_element *e, enum fw3_flag *pol, enum fw3_flag def,
             const char *name)
{
	if (*pol == FW3_FLAG_UNSPEC)
	{
		warn_elem(e, "has no %s policy specified, using default", name);
		*pol = def;
	}
	else if (*pol > FW3_FLAG_DROP)
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

		tmp->network = net;
		list_add_tail(&tmp->list, &zone->devices);
	}
}

struct fw3_zone *
fw3_alloc_zone(void)
{
	struct fw3_zone *zone;

	zone = malloc(sizeof(*zone));

	if (!zone)
		return NULL;

	memset(zone, 0, sizeof(*zone));

	INIT_LIST_HEAD(&zone->networks);
	INIT_LIST_HEAD(&zone->devices);
	INIT_LIST_HEAD(&zone->subnets);
	INIT_LIST_HEAD(&zone->masq_src);
	INIT_LIST_HEAD(&zone->masq_dest);

	INIT_LIST_HEAD(&zone->running_networks);
	INIT_LIST_HEAD(&zone->running_devices);

	zone->enabled = true;
	zone->custom_chains = true;
	zone->log_limit.rate = 10;

	return zone;
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

		zone = fw3_alloc_zone();

		if (!zone)
			continue;

		fw3_parse_options(zone, fw3_zone_opts, s);

		if (!zone->enabled)
		{
			fw3_free_zone(zone);
			continue;
		}

		if (!zone->extra_dest)
			zone->extra_dest = zone->extra_src;

		if (!defs->custom_chains && zone->custom_chains)
			zone->custom_chains = false;

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
			setbit(zone->flags[0], FW3_FLAG_SNAT);
			zone->conntrack = true;
		}

		if (zone->custom_chains)
		{
			setbit(zone->flags[0], FW3_FLAG_SNAT);
			setbit(zone->flags[0], FW3_FLAG_DNAT);
		}

		setbit(zone->flags[0], fw3_to_src_target(zone->policy_input));
		setbit(zone->flags[0], zone->policy_output);
		setbit(zone->flags[0], zone->policy_forward);

		setbit(zone->flags[1], fw3_to_src_target(zone->policy_input));
		setbit(zone->flags[1], zone->policy_output);
		setbit(zone->flags[1], zone->policy_forward);

		list_add_tail(&zone->list, &state->zones);
	}
}


static void
print_zone_chain(struct fw3_state *state, enum fw3_family family,
                 enum fw3_table table, bool reload, struct fw3_zone *zone)
{
	bool c, r;
	uint32_t custom_mask = ~0;

	if (!fw3_is_family(zone, family))
		return;

	set(zone->flags, family, table);

	/* Don't touch user chains on reload */
	if (reload)
		delbit(custom_mask, FW3_FLAG_CUSTOM_CHAINS);

	if (zone->custom_chains)
		set(zone->flags, family, FW3_FLAG_CUSTOM_CHAINS);

	if (!zone->conntrack && !state->defaults.drop_invalid)
		set(zone->flags, family, FW3_FLAG_NOTRACK);

	c = fw3_pr_rulespec(table, family, zone->flags, custom_mask, zone_chains,
	                    ":%s - [0:0]\n", zone->name);

	r = fw3_pr_rulespec(table, family, zone->flags, 0, zone_rules,
	                    "-A %s\n", zone->name);

	if (c || r)
	{
		info("   * Zone '%s'", zone->name);
		fw3_set_running(zone, &state->running_zones);

		set(zone->flags, family, table);
	}
}

static void
print_interface_rule(struct fw3_state *state, enum fw3_family family,
                     enum fw3_table table, bool reload, struct fw3_zone *zone,
                     struct fw3_device *dev, struct fw3_address *sub)
{
	bool disable_notrack = state->defaults.drop_invalid;

	enum fw3_flag t;

#define jump_target(t) \
	((t == FW3_FLAG_REJECT) ? "reject" : fw3_flag_names[t])

	if (table == FW3_TABLE_FILTER)
	{
		for (t = FW3_FLAG_ACCEPT; t <= FW3_FLAG_DROP; t++)
		{
			if (has(zone->flags, family, fw3_to_src_target(t)))
			{
				fw3_pr("-A zone_%s_src_%s", zone->name, fw3_flag_names[t]);
				fw3_format_in_out(dev, NULL);
				fw3_format_src_dest(sub, NULL);
				fw3_format_extra(zone->extra_src);
				fw3_pr(" -j %s\n", jump_target(t));
			}

			if (has(zone->flags, family, t))
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
		if (has(zone->flags, family, FW3_FLAG_DNAT))
		{
			fw3_pr("-A delegate_prerouting");
			fw3_format_in_out(dev, NULL);
			fw3_format_src_dest(sub, NULL);
			fw3_format_extra(zone->extra_src);
			fw3_pr(" -j zone_%s_prerouting\n", zone->name);
		}

		if (has(zone->flags, family, FW3_FLAG_SNAT))
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
print_interface_rules(struct fw3_state *state, enum fw3_family family,
                      enum fw3_table table, bool reload, struct fw3_zone *zone)
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

		print_interface_rule(state, family, table, reload, zone, dev, sub);
	}
}

static void
print_zone_rule(struct fw3_state *state, enum fw3_family family,
                enum fw3_table table, bool reload, struct fw3_zone *zone)
{
	struct fw3_address *msrc;
	struct fw3_address *mdest;

	enum fw3_flag t;

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
			for (t = FW3_FLAG_REJECT; t <= FW3_FLAG_DROP; t++)
			{
				if (has(zone->flags, family, fw3_to_src_target(t)))
				{
					fw3_pr("-A zone_%s_src_%s", zone->name, fw3_flag_names[t]);
					fw3_format_limit(&zone->log_limit);
					fw3_pr(" -j LOG --log-prefix \"%s(src %s)\"\n",
						   fw3_flag_names[t], zone->name);
				}

				if (has(zone->flags, family, t))
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
				if (!fw3_is_family(msrc, family) ||
				    !fw3_is_family(mdest, family))
					continue;

				fw3_pr("-A zone_%s_postrouting", zone->name);
				fw3_format_src_dest(msrc, mdest);
				fw3_pr(" -j MASQUERADE\n");
			}
		}
		break;

	case FW3_TABLE_RAW:
	case FW3_TABLE_MANGLE:
		break;
	}

	print_interface_rules(state, family, table, reload, zone);
}

void
fw3_print_zone_chains(struct fw3_state *state, enum fw3_family family,
                      enum fw3_table table, bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_chain(state, family, table, reload, zone);
}

void
fw3_print_zone_rules(struct fw3_state *state, enum fw3_family family,
                     enum fw3_table table, bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_rule(state, family, table, reload, zone);
}

void
fw3_flush_zones(struct fw3_state *state, enum fw3_family family,
                enum fw3_table table, bool reload, bool pass2)
{
	struct fw3_zone *z, *tmp;
	uint32_t custom_mask = ~0;

	/* don't touch user chains on selective stop */
	if (reload)
		delbit(custom_mask, FW3_FLAG_CUSTOM_CHAINS);

	list_for_each_entry_safe(z, tmp, &state->running_zones, running_list)
	{
		if (!has(z->flags, family, table))
			continue;

		fw3_pr_rulespec(table, family, z->flags, custom_mask, zone_chains,
		                pass2 ? "-X %s\n" : "-F %s\n", z->name);

		if (pass2)
			del(z->flags, family, table);
	}
}

void
fw3_hotplug_zones(struct fw3_state *state, bool add)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	if (add)
	{
		list_for_each_entry(z, &state->running_zones, running_list)
		{
			if (!hasbit(z->flags[0], FW3_FLAG_HOTPLUG))
			{
				list_for_each_entry(d, &z->devices, list)
					fw3_hotplug(add, z, d);

				setbit(z->flags[0], FW3_FLAG_HOTPLUG);
			}
		}
	}
	else
	{
		list_for_each_entry(z, &state->running_zones, running_list)
		{
			if (hasbit(z->flags[0], FW3_FLAG_HOTPLUG))
			{
				list_for_each_entry(d, &z->running_devices, list)
					fw3_hotplug(add, z, d);

				delbit(z->flags[0], FW3_FLAG_HOTPLUG);
			}
		}
	}
}

struct fw3_zone *
fw3_lookup_zone(struct fw3_state *state, const char *name, bool running)
{
	struct fw3_zone *z;

	if (list_empty(&state->zones))
		return NULL;

	list_for_each_entry(z, &state->zones, list)
	{
		if (strcmp(z->name, name))
			continue;

		if (!running || z->running_list.next)
			return z;

		break;
	}

	return NULL;
}

void
fw3_free_zone(struct fw3_zone *zone)
{
	struct fw3_device *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &zone->running_devices, list)
	{
		list_del(&dev->list);
		free(dev);
	}

	list_for_each_entry_safe(dev, tmp, &zone->running_networks, list)
	{
		list_del(&dev->list);
		free(dev);
	}

	fw3_free_object(zone, fw3_zone_opts);
}
