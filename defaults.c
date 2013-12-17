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

#include "defaults.h"


#define C(f, tbl, def, fmt) \
	{ FW3_FAMILY_##f, FW3_TABLE_##tbl, FW3_FLAG_##def, fmt }

static const struct fw3_chain_spec default_chains[] = {
	C(ANY, FILTER, UNSPEC,        "delegate_input"),
	C(ANY, FILTER, UNSPEC,        "delegate_output"),
	C(ANY, FILTER, UNSPEC,        "delegate_forward"),
	C(ANY, FILTER, UNSPEC,        "reject"),
	C(ANY, FILTER, CUSTOM_CHAINS, "input_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "output_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "forwarding_rule"),
	C(ANY, FILTER, SYN_FLOOD,     "syn_flood"),

	C(V4,  NAT,    UNSPEC,        "delegate_prerouting"),
	C(V4,  NAT,    UNSPEC,        "delegate_postrouting"),
	C(V4,  NAT,    CUSTOM_CHAINS, "prerouting_rule"),
	C(V4,  NAT,    CUSTOM_CHAINS, "postrouting_rule"),

	C(ANY, MANGLE, UNSPEC,        "mssfix"),
	C(ANY, MANGLE, UNSPEC,        "fwmark"),

	C(ANY, RAW,    UNSPEC,        "delegate_notrack"),

	{ }
};

const struct fw3_option fw3_flag_opts[] = {
	FW3_OPT("input",               target,   defaults, policy_input),
	FW3_OPT("forward",             target,   defaults, policy_forward),
	FW3_OPT("output",              target,   defaults, policy_output),

	FW3_OPT("drop_invalid",        bool,     defaults, drop_invalid),

	FW3_OPT("syn_flood",           bool,     defaults, syn_flood),
	FW3_OPT("synflood_protect",    bool,     defaults, syn_flood),
	FW3_OPT("synflood_rate",       limit,    defaults, syn_flood_rate),
	FW3_OPT("synflood_burst",      int,      defaults, syn_flood_rate.burst),

	FW3_OPT("tcp_syncookies",      bool,     defaults, tcp_syncookies),
	FW3_OPT("tcp_ecn",             int,      defaults, tcp_ecn),
	FW3_OPT("tcp_window_scaling",  bool,     defaults, tcp_window_scaling),

	FW3_OPT("accept_redirects",    bool,     defaults, accept_redirects),
	FW3_OPT("accept_source_route", bool,     defaults, accept_source_route),

	FW3_OPT("custom_chains",       bool,     defaults, custom_chains),
	FW3_OPT("disable_ipv6",        bool,     defaults, disable_ipv6),

	FW3_OPT("__flags_v4",          int,      defaults, flags[0]),
	FW3_OPT("__flags_v6",          int,      defaults, flags[1]),

	{ }
};


static void
check_policy(struct uci_element *e, enum fw3_flag *pol, const char *name)
{
	if (*pol == FW3_FLAG_UNSPEC)
	{
		warn_elem(e, "has no %s policy specified, defaulting to DROP", name);
		*pol = FW3_FLAG_DROP;
	}
	else if (*pol > FW3_FLAG_DROP)
	{
		warn_elem(e, "has invalid %s policy, defaulting to DROP", name);
		*pol = FW3_FLAG_DROP;
	}
}

void
fw3_load_defaults(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_defaults *defs = &state->defaults;

	bool seen = false;

	defs->syn_flood_rate.rate  = 25;
	defs->syn_flood_rate.burst = 50;
	defs->tcp_syncookies       = true;
	defs->tcp_window_scaling   = true;
	defs->custom_chains        = true;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "defaults"))
			continue;

		if (seen)
		{
			warn_elem(e, "ignoring duplicate section");
			continue;
		}

		fw3_parse_options(&state->defaults, fw3_flag_opts, s);

		check_policy(e, &defs->policy_input, "input");
		check_policy(e, &defs->policy_output, "output");
		check_policy(e, &defs->policy_forward, "forward");
	}
}

void
fw3_print_default_chains(struct fw3_ipt_handle *handle, struct fw3_state *state,
                         bool reload)
{
	struct fw3_defaults *defs = &state->defaults;
	const struct fw3_chain_spec *c;

#define policy(t) \
	((t == FW3_FLAG_REJECT) ? FW3_FLAG_DROP : t)

	if (handle->family == FW3_FAMILY_V6 && defs->disable_ipv6)
		return;

	if (handle->table == FW3_TABLE_FILTER)
	{
		fw3_ipt_set_policy(handle, "INPUT",   policy(defs->policy_input));
		fw3_ipt_set_policy(handle, "OUTPUT",  policy(defs->policy_output));
		fw3_ipt_set_policy(handle, "FORWARD", policy(defs->policy_forward));
	}

	if (defs->custom_chains)
		set(defs->flags, handle->family, FW3_FLAG_CUSTOM_CHAINS);

	if (defs->syn_flood)
		set(defs->flags, handle->family, FW3_FLAG_SYN_FLOOD);

	for (c = default_chains; c->format; c++)
	{
		/* don't touch user chains on selective stop */
		if (reload && c->flag == FW3_FLAG_CUSTOM_CHAINS)
			continue;

		if (!fw3_is_family(c, handle->family))
			continue;

		if (c->table != handle->table)
			continue;

		if (c->flag &&
		    !hasbit(defs->flags[handle->family == FW3_FAMILY_V6], c->flag))
			continue;

		fw3_ipt_create_chain(handle, c->format);
	}

	set(defs->flags, handle->family, handle->table);
}


struct toplevel_rule {
	enum fw3_table table;
	const char *chain;
	const char *target;
};

void
fw3_print_default_head_rules(struct fw3_ipt_handle *handle,
                             struct fw3_state *state, bool reload)
{
	int i;
	struct fw3_defaults *defs = &state->defaults;
	struct fw3_device lodev = { .set = true };
	struct fw3_protocol tcp = { .protocol = 6 };
	struct fw3_ipt_rule *r;
	struct toplevel_rule *tr;

	const char *chains[] = {
		"delegate_input", "input",
		"delegate_output", "output",
		"delegate_forward", "forwarding",
	};

	struct toplevel_rule rules[] = {
		{ FW3_TABLE_FILTER, "INPUT",       "delegate_input" },
		{ FW3_TABLE_FILTER, "OUTPUT",      "delegate_output" },
		{ FW3_TABLE_FILTER, "FORWARD",     "delegate_forward" },

		{ FW3_TABLE_NAT,    "PREROUTING",  "delegate_prerouting" },
		{ FW3_TABLE_NAT,    "POSTROUTING", "delegate_postrouting" },

		{ FW3_TABLE_MANGLE, "FORWARD",     "mssfix" },
		{ FW3_TABLE_MANGLE, "PREROUTING",  "fwmark" },

		{ FW3_TABLE_RAW,    "PREROUTING",  "delegate_notrack" },

		{ 0, NULL },
	};

	for (tr = rules; tr->chain; tr++)
	{
		if (tr->table != handle->table)
			continue;

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, tr->target);
		fw3_ipt_rule_replace(r, tr->chain);
	}

	switch (handle->table)
	{
	case FW3_TABLE_FILTER:

		sprintf(lodev.name, "lo");

		r = fw3_ipt_rule_create(handle, NULL, &lodev, NULL, NULL, NULL);
		fw3_ipt_rule_target(r, "ACCEPT");
		fw3_ipt_rule_append(r, "delegate_input");

		r = fw3_ipt_rule_create(handle, NULL, NULL, &lodev, NULL, NULL);
		fw3_ipt_rule_target(r, "ACCEPT");
		fw3_ipt_rule_append(r, "delegate_output");

		if (defs->custom_chains)
		{
			for (i = 0; i < ARRAY_SIZE(chains); i += 2)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_comment(r, "user chain for %s", chains[i+1]);
				fw3_ipt_rule_target(r, "%s_rule", chains[i+1]);
				fw3_ipt_rule_append(r, chains[i]);
			}
		}

		for (i = 0; i < ARRAY_SIZE(chains); i += 2)
		{
			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_extra(r, "-m conntrack --ctstate RELATED,ESTABLISHED");
			fw3_ipt_rule_target(r, "ACCEPT");
			fw3_ipt_rule_append(r, chains[i]);

			if (defs->drop_invalid)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_extra(r, "-m conntrack --ctstate INVALID");
				fw3_ipt_rule_target(r, "DROP");
				fw3_ipt_rule_append(r, chains[i]);
			}
		}

		if (defs->syn_flood)
		{
			r = fw3_ipt_rule_create(handle, &tcp, NULL, NULL, NULL, NULL);
			fw3_ipt_rule_extra(r, "--syn");
			fw3_ipt_rule_limit(r, &defs->syn_flood_rate);
			fw3_ipt_rule_target(r, "RETURN");
			fw3_ipt_rule_append(r, "syn_flood");

			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_target(r, "DROP");
			fw3_ipt_rule_append(r, "syn_flood");

			r = fw3_ipt_rule_create(handle, &tcp, NULL, NULL, NULL, NULL);
			fw3_ipt_rule_extra(r, "--syn");
			fw3_ipt_rule_target(r, "syn_flood");
			fw3_ipt_rule_append(r, "delegate_input");
		}

		r = fw3_ipt_rule_create(handle, &tcp, NULL, NULL, NULL, NULL);
		fw3_ipt_rule_target(r, "REJECT");
		fw3_ipt_rule_addarg(r, false, "--reject-with", "tcp-reset");
		fw3_ipt_rule_append(r, "reject");

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "REJECT");
		fw3_ipt_rule_addarg(r, false, "--reject-with", "port-unreach");
		fw3_ipt_rule_append(r, "reject");

		break;

	case FW3_TABLE_NAT:
		if (defs->custom_chains)
		{
			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_comment(r, "user chain for prerouting");
			fw3_ipt_rule_target(r, "prerouting_rule");
			fw3_ipt_rule_append(r, "delegate_prerouting");

			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_comment(r, "user chain for postrouting");
			fw3_ipt_rule_target(r, "postrouting_rule");
			fw3_ipt_rule_append(r, "delegate_postrouting");
		}
		break;

	default:
		break;
	}
}

void
fw3_print_default_tail_rules(struct fw3_ipt_handle *handle,
                             struct fw3_state *state, bool reload)
{
	struct fw3_defaults *defs = &state->defaults;
	struct fw3_ipt_rule *r;

	if (handle->table != FW3_TABLE_FILTER)
		return;

	if (defs->policy_input == FW3_FLAG_REJECT)
	{
		r = fw3_ipt_rule_new(handle);

		if (!r)
			return;

		fw3_ipt_rule_target(r, "reject");
		fw3_ipt_rule_append(r, "delegate_input");
	}

	if (defs->policy_output == FW3_FLAG_REJECT)
	{
		r = fw3_ipt_rule_new(handle);

		if (!r)
			return;

		fw3_ipt_rule_target(r, "reject");
		fw3_ipt_rule_append(r, "delegate_output");
	}

	if (defs->policy_forward == FW3_FLAG_REJECT)
	{
		r = fw3_ipt_rule_new(handle);

		if (!r)
			return;

		fw3_ipt_rule_target(r, "reject");
		fw3_ipt_rule_append(r, "delegate_forward");
	}
}

static void
set_default(const char *name, int set)
{
	FILE *f;
	char path[sizeof("/proc/sys/net/ipv4/tcp_window_scaling\0")];

	snprintf(path, sizeof(path), "/proc/sys/net/ipv4/tcp_%s", name);

	info(" * Set tcp_%s to %s", name, set ? "on" : "off", name);

	if (!(f = fopen(path, "w")))
	{
		info("   ! Unable to write value: %s", strerror(errno));
		return;
	}

	fprintf(f, "%u\n", set);
	fclose(f);
}

void
fw3_set_defaults(struct fw3_state *state)
{
	set_default("ecn",            state->defaults.tcp_ecn);
	set_default("syncookies",     state->defaults.tcp_syncookies);
	set_default("window_scaling", state->defaults.tcp_window_scaling);
}

void
fw3_flush_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                bool reload)
{
	enum fw3_flag policy = reload ? FW3_FLAG_DROP : FW3_FLAG_ACCEPT;
	struct fw3_defaults *defs = &state->defaults;
	const struct fw3_chain_spec *c;

	if (!has(defs->flags, handle->family, handle->table))
		return;

	if (handle->table == FW3_TABLE_FILTER)
	{
		fw3_ipt_set_policy(handle, "INPUT",   policy);
		fw3_ipt_set_policy(handle, "OUTPUT",  policy);
		fw3_ipt_set_policy(handle, "FORWARD", policy);
	}

	for (c = default_chains; c->format; c++)
	{
		/* don't touch user chains on selective stop */
		if (reload && c->flag == FW3_FLAG_CUSTOM_CHAINS)
			continue;

		if (!fw3_is_family(c, handle->family))
			continue;

		if (c->table != handle->table)
			continue;

		if (c->flag && !has(defs->flags, handle->family, c->flag))
			continue;

		fw3_ipt_flush_chain(handle, c->format);

		/* keep certain basic chains that do not depend on any settings to
		   avoid purging unrelated user rules pointing to them */
		if (reload && !c->flag)
			continue;

		fw3_ipt_delete_chain(handle, c->format);
	}

	del(defs->flags, handle->family, handle->table);
}

void
fw3_flush_all(struct fw3_ipt_handle *handle)
{
	if (handle->table == FW3_TABLE_FILTER)
	{
		fw3_ipt_set_policy(handle, "INPUT",   FW3_FLAG_ACCEPT);
		fw3_ipt_set_policy(handle, "OUTPUT",  FW3_FLAG_ACCEPT);
		fw3_ipt_set_policy(handle, "FORWARD", FW3_FLAG_ACCEPT);
	}

	fw3_ipt_flush(handle);
}
