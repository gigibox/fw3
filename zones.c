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

static const struct fw3_chain_spec zone_chains[] = {
	C(ANY, FILTER, UNSPEC,        "zone_%s_input"),
	C(ANY, FILTER, UNSPEC,        "zone_%s_output"),
	C(ANY, FILTER, UNSPEC,        "zone_%s_forward"),

	C(ANY, FILTER, SRC_ACCEPT,    "zone_%s_src_ACCEPT"),
	C(ANY, FILTER, SRC_REJECT,    "zone_%s_src_REJECT"),
	C(ANY, FILTER, SRC_DROP,      "zone_%s_src_DROP"),

	C(ANY, FILTER, ACCEPT,        "zone_%s_dest_ACCEPT"),
	C(ANY, FILTER, REJECT,        "zone_%s_dest_REJECT"),
	C(ANY, FILTER, DROP,          "zone_%s_dest_DROP"),

	C(V4,  NAT,    SNAT,          "zone_%s_postrouting"),
	C(V4,  NAT,    DNAT,          "zone_%s_prerouting"),

	C(ANY, RAW,    NOTRACK,       "zone_%s_notrack"),

	C(ANY, FILTER, CUSTOM_CHAINS, "input_%s_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "output_%s_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "forwarding_%s_rule"),

	C(V4,  NAT,    CUSTOM_CHAINS, "prerouting_%s_rule"),
	C(V4,  NAT,    CUSTOM_CHAINS, "postrouting_%s_rule"),

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

	FW3_OPT("__flags_v4",          int,      zone,     flags[0]),
	FW3_OPT("__flags_v6",          int,      zone,     flags[1]),

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

		snprintf(tmp->network, sizeof(tmp->network), "%s", net->name);
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

		if (strlen(zone->name) > FW3_ZONE_MAXNAMELEN)
		{
			warn_elem(e, "must not have a name longer than %u characters",
			             FW3_ZONE_MAXNAMELEN);
			fw3_free_zone(zone);
			continue;
		}

		fw3_ubus_zone_devices(zone);

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
		setbit(zone->flags[0], fw3_to_src_target(zone->policy_forward));
		setbit(zone->flags[0], zone->policy_output);

		setbit(zone->flags[1], fw3_to_src_target(zone->policy_input));
		setbit(zone->flags[1], fw3_to_src_target(zone->policy_forward));
		setbit(zone->flags[1], zone->policy_output);

		list_add_tail(&zone->list, &state->zones);
	}
}


static void
print_zone_chain(struct fw3_ipt_handle *handle, struct fw3_state *state,
                 bool reload, struct fw3_zone *zone)
{
	int i;
	struct fw3_ipt_rule *r;
	const struct fw3_chain_spec *c;

	const char *flt_chains[] = {
		"input",   "input",
		"output",  "output",
		"forward", "forwarding",
	};

	const char *nat_chains[] = {
		"prerouting",  "prerouting",
		"postrouting", "postrouting",
	};

	if (!fw3_is_family(zone, handle->family))
		return;

	info("   * Zone '%s'", zone->name);

	set(zone->flags, handle->family, handle->table);

	if (zone->custom_chains)
		set(zone->flags, handle->family, FW3_FLAG_CUSTOM_CHAINS);

	if (!zone->conntrack && !state->defaults.drop_invalid)
		set(zone->flags, handle->family, FW3_FLAG_NOTRACK);

	for (c = zone_chains; c->format; c++)
	{
		/* don't touch user chains on selective stop */
		if (reload && c->flag == FW3_FLAG_CUSTOM_CHAINS)
			continue;

		if (!fw3_is_family(c, handle->family))
			continue;

		if (c->table != handle->table)
			continue;

		if (c->flag &&
		    !hasbit(zone->flags[handle->family == FW3_FAMILY_V6], c->flag))
			continue;

		fw3_ipt_create_chain(handle, c->format, zone->name);
	}

	if (zone->custom_chains)
	{
		if (handle->table == FW3_TABLE_FILTER)
		{
			for (i = 0; i < sizeof(flt_chains)/sizeof(flt_chains[0]); i += 2)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_comment(r, "user chain for %s", flt_chains[i+1]);
				fw3_ipt_rule_target(r, "%s_%s_rule", flt_chains[i+1], zone->name);
				fw3_ipt_rule_append(r, "zone_%s_%s", zone->name, flt_chains[i]);
			}
		}
		else if (handle->table == FW3_TABLE_NAT)
		{
			for (i = 0; i < sizeof(nat_chains)/sizeof(nat_chains[0]); i += 2)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_comment(r, "user chain for %s", nat_chains[i+1]);
				fw3_ipt_rule_target(r, "%s_%s_rule", nat_chains[i+1], zone->name);
				fw3_ipt_rule_append(r, "zone_%s_%s", zone->name, nat_chains[i]);
			}
		}
	}

	set(zone->flags, handle->family, handle->table);
}

static void
print_interface_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
					 bool reload, struct fw3_zone *zone,
                     struct fw3_device *dev, struct fw3_address *sub)
{
	struct fw3_protocol tcp = { .protocol = 6 };
	struct fw3_ipt_rule *r;
	enum fw3_flag t;

	char buf[32];

	int i;

	const char *chains[] = {
		"input",
		"output",
		"forward",
	};

#define jump_target(t) \
	((t == FW3_FLAG_REJECT) ? "reject" : fw3_flag_names[t])

	if (handle->table == FW3_TABLE_FILTER)
	{
		for (t = FW3_FLAG_ACCEPT; t <= FW3_FLAG_DROP; t++)
		{
			if (has(zone->flags, handle->family, fw3_to_src_target(t)))
			{
				r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);
				fw3_ipt_rule_target(r, jump_target(t));
				fw3_ipt_rule_extra(r, zone->extra_src);
				fw3_ipt_rule_replace(r, "zone_%s_src_%s", zone->name,
				                     fw3_flag_names[t]);
			}

			if (has(zone->flags, handle->family, t))
			{
				r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
				fw3_ipt_rule_target(r, jump_target(t));
				fw3_ipt_rule_extra(r, zone->extra_dest);
				fw3_ipt_rule_replace(r, "zone_%s_dest_%s", zone->name,
				                     fw3_flag_names[t]);
			}
		}

		for (i = 0; i < sizeof(chains)/sizeof(chains[0]); i++)
		{
			if (*chains[i] == 'o')
				r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
			else
				r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);

			fw3_ipt_rule_target(r, "zone_%s_%s", zone->name, chains[i]);

			if (*chains[i] == 'o')
				fw3_ipt_rule_extra(r, zone->extra_dest);
			else
				fw3_ipt_rule_extra(r, zone->extra_src);

			fw3_ipt_rule_replace(r, "delegate_%s", chains[i]);
		}
	}
	else if (handle->table == FW3_TABLE_NAT)
	{
		if (has(zone->flags, handle->family, FW3_FLAG_DNAT))
		{
			r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);
			fw3_ipt_rule_target(r, "zone_%s_prerouting", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_src);
			fw3_ipt_rule_replace(r, "delegate_prerouting");
		}

		if (has(zone->flags, handle->family, FW3_FLAG_SNAT))
		{
			r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
			fw3_ipt_rule_target(r, "zone_%s_postrouting", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_dest);
			fw3_ipt_rule_replace(r, "delegate_postrouting");
		}
	}
	else if (handle->table == FW3_TABLE_MANGLE)
	{
		if (zone->mtu_fix)
		{
			if (zone->log)
			{
				snprintf(buf, sizeof(buf) - 1, "MSSFIX(%s): ", zone->name);

				r = fw3_ipt_rule_create(handle, &tcp, NULL, dev, NULL, sub);
				fw3_ipt_rule_addarg(r, false, "--tcp-flags", "SYN,RST");
				fw3_ipt_rule_addarg(r, false, "SYN", NULL);
				fw3_ipt_rule_limit(r, &zone->log_limit);
				fw3_ipt_rule_comment(r, "%s (mtu_fix logging)", zone->name);
				fw3_ipt_rule_target(r, "LOG");
				fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
				fw3_ipt_rule_replace(r, "mssfix");
			}

			r = fw3_ipt_rule_create(handle, &tcp, NULL, dev, NULL, sub);
			fw3_ipt_rule_addarg(r, false, "--tcp-flags", "SYN,RST");
			fw3_ipt_rule_addarg(r, false, "SYN", NULL);
			fw3_ipt_rule_comment(r, "%s (mtu_fix)", zone->name);
			fw3_ipt_rule_target(r, "TCPMSS");
			fw3_ipt_rule_addarg(r, false, "--clamp-mss-to-pmtu", NULL);
			fw3_ipt_rule_replace(r, "mssfix");
		}
	}
	else if (handle->table == FW3_TABLE_RAW)
	{
		if (has(zone->flags, handle->family, FW3_FLAG_NOTRACK))
		{
			r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);
			fw3_ipt_rule_target(r, "zone_%s_notrack", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_src);
			fw3_ipt_rule_replace(r, "delegate_notrack");
		}
	}
}

static void
print_interface_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                      bool reload, struct fw3_zone *zone)
{
	struct fw3_device *dev;
	struct fw3_address *sub;

	fw3_foreach(dev, &zone->devices)
	fw3_foreach(sub, &zone->subnets)
	{
		if (!fw3_is_family(sub, handle->family))
			continue;

		if (!dev && !sub)
			continue;

		print_interface_rule(handle, state, reload, zone, dev, sub);
	}
}

static void
print_zone_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
                bool reload, struct fw3_zone *zone)
{
	bool disable_notrack = state->defaults.drop_invalid;
	struct fw3_address *msrc;
	struct fw3_address *mdest;
	struct fw3_ipt_rule *r;

	enum fw3_flag t;
	char buf[32];

	if (!fw3_is_family(zone, handle->family))
		return;

	switch (handle->table)
	{
	case FW3_TABLE_FILTER:
		if (has(zone->flags, handle->family, FW3_FLAG_DNAT))
		{
			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_extra(r, "-m conntrack --ctstate DNAT");
			fw3_ipt_rule_comment(r, "Accept port redirections");
			fw3_ipt_rule_target(r, fw3_flag_names[FW3_FLAG_ACCEPT]);
			fw3_ipt_rule_append(r, "zone_%s_input", zone->name);

			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_extra(r, "-m conntrack --ctstate DNAT");
			fw3_ipt_rule_comment(r, "Accept port forwards");
			fw3_ipt_rule_target(r, fw3_flag_names[FW3_FLAG_ACCEPT]);
			fw3_ipt_rule_append(r, "zone_%s_forward", zone->name);
		}

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_src_%s", zone->name,
		                     fw3_flag_names[zone->policy_input]);
		fw3_ipt_rule_append(r, "zone_%s_input", zone->name);

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_src_%s", zone->name,
		                     fw3_flag_names[zone->policy_forward]);
		fw3_ipt_rule_append(r, "zone_%s_forward", zone->name);

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_dest_%s", zone->name,
		                     fw3_flag_names[zone->policy_output]);
		fw3_ipt_rule_append(r, "zone_%s_output", zone->name);

		if (zone->log)
		{
			for (t = FW3_FLAG_REJECT; t <= FW3_FLAG_DROP; t++)
			{
				if (has(zone->flags, handle->family, fw3_to_src_target(t)))
				{
					r = fw3_ipt_rule_new(handle);

					snprintf(buf, sizeof(buf) - 1, "%s(src %s)",
					         fw3_flag_names[t], zone->name);

					fw3_ipt_rule_limit(r, &zone->log_limit);
					fw3_ipt_rule_target(r, "LOG");
					fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
					fw3_ipt_rule_append(r, "zone_%s_src_%s",
					                    zone->name, fw3_flag_names[t]);
				}

				if (has(zone->flags, handle->family, t))
				{
					r = fw3_ipt_rule_new(handle);

					snprintf(buf, sizeof(buf) - 1, "%s(dest %s)",
					         fw3_flag_names[t], zone->name);

					fw3_ipt_rule_limit(r, &zone->log_limit);
					fw3_ipt_rule_target(r, "LOG");
					fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
					fw3_ipt_rule_append(r, "zone_%s_dest_%s",
					                    zone->name, fw3_flag_names[t]);
				}
			}
		}
		break;

	case FW3_TABLE_NAT:
		if (zone->masq && handle->family == FW3_FAMILY_V4)
		{
			fw3_foreach(msrc, &zone->masq_src)
			fw3_foreach(mdest, &zone->masq_dest)
			{
				if (!fw3_is_family(msrc, handle->family) ||
				    !fw3_is_family(mdest, handle->family))
					continue;

				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_src_dest(r, msrc, mdest);
				fw3_ipt_rule_target(r, "MASQUERADE");
				fw3_ipt_rule_append(r, "zone_%s_postrouting", zone->name);
			}
		}
		break;

	case FW3_TABLE_RAW:
		if (!zone->conntrack && !disable_notrack)
		{
			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_target(r, "CT");
			fw3_ipt_rule_addarg(r, false, "--notrack", NULL);
			fw3_ipt_rule_append(r, "zone_%s_notrack", zone->name);
		}
		break;

	case FW3_TABLE_MANGLE:
		break;
	}

	print_interface_rules(handle, state, reload, zone);
}

void
fw3_print_zone_chains(struct fw3_ipt_handle *handle, struct fw3_state *state,
                      bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_chain(handle, state, reload, zone);
}

void
fw3_print_zone_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                     bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_rule(handle, state, reload, zone);
}

void
fw3_flush_zones(struct fw3_ipt_handle *handle, struct fw3_state *state,
                bool reload)
{
	struct fw3_zone *z, *tmp;
	const struct fw3_chain_spec *c;
	char chain[32];

	list_for_each_entry_safe(z, tmp, &state->zones, list)
	{
		if (!has(z->flags, handle->family, handle->table))
			continue;

		for (c = zone_chains; c->format; c++)
		{
			/* don't touch user chains on selective stop */
			if (reload && c->flag == FW3_FLAG_CUSTOM_CHAINS)
				continue;

			if (!fw3_is_family(c, handle->family))
				continue;

			if (c->table != handle->table)
				continue;

			if (c->flag && !has(z->flags, handle->family, c->flag))
				continue;

			snprintf(chain, sizeof(chain), c->format, z->name);
			fw3_ipt_flush_chain(handle, chain);

			/* keep certain basic chains that do not depend on any settings to
			   avoid purging unrelated user rules pointing to them */
			if (reload && !c->flag)
				continue;

			fw3_ipt_delete_chain(handle, chain);
		}

		del(z->flags, handle->family, handle->table);
	}
}

void
fw3_hotplug_zones(struct fw3_state *state, bool add)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &state->zones, list)
	{
		if (add != hasbit(z->flags[0], FW3_FLAG_HOTPLUG))
		{
			list_for_each_entry(d, &z->devices, list)
				fw3_hotplug(add, z, d);

			if (add)
				setbit(z->flags[0], FW3_FLAG_HOTPLUG);
			else
				delbit(z->flags[0], FW3_FLAG_HOTPLUG);
		}
	}
}

struct fw3_zone *
fw3_lookup_zone(struct fw3_state *state, const char *name)
{
	struct fw3_zone *z;

	if (list_empty(&state->zones))
		return NULL;

	list_for_each_entry(z, &state->zones, list)
	{
		if (strcmp(z->name, name))
			continue;

		return z;
	}

	return NULL;
}

struct list_head *
fw3_resolve_zone_addresses(struct fw3_zone *zone)
{
	struct fw3_device *net;
	struct fw3_address *addr, *tmp;
	struct list_head *addrs, *all;

	all = malloc(sizeof(*all));

	if (!all)
		return NULL;

	memset(all, 0, sizeof(*all));
	INIT_LIST_HEAD(all);

	list_for_each_entry(net, &zone->networks, list)
	{
		addrs = fw3_ubus_address(net->name);

		if (!addrs)
			continue;

		list_for_each_entry_safe(addr, tmp, addrs, list)
		{
			list_del(&addr->list);
			list_add_tail(&addr->list, all);
		}

		free(addrs);
	}

	list_for_each_entry(addr, &zone->subnets, list)
	{
		tmp = malloc(sizeof(*tmp));

		if (!tmp)
			continue;

		memcpy(tmp, addr, sizeof(*tmp));
		list_add_tail(&tmp->list, all);
	}

	return all;
}
