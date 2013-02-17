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


static struct fw3_option default_opts[] = {
	FW3_OPT("input",               target,   defaults, policy_input),
	FW3_OPT("forward",             target,   defaults, policy_forward),
	FW3_OPT("output",              target,   defaults, policy_output),

	FW3_OPT("drop_invalid",        bool,     defaults, drop_invalid),

	FW3_OPT("syn_flood",           bool,     defaults, syn_flood),
	FW3_OPT("synflood_protect",    bool,     defaults, syn_flood),
	FW3_OPT("synflood_rate",       limit,    defaults, syn_flood_rate),
	FW3_OPT("synflood_burst",      int,      defaults, syn_flood_rate.burst),

	FW3_OPT("tcp_syncookies",      bool,     defaults, tcp_syncookies),
	FW3_OPT("tcp_ecn",             bool,     defaults, tcp_ecn),
	FW3_OPT("tcp_westwood",        bool,     defaults, tcp_westwood),
	FW3_OPT("tcp_window_scaling",  bool,     defaults, tcp_window_scaling),

	FW3_OPT("accept_redirects",    bool,     defaults, accept_redirects),
	FW3_OPT("accept_source_route", bool,     defaults, accept_source_route),

	FW3_OPT("custom_chains",       bool,     defaults, custom_chains),
	FW3_OPT("disable_ipv6",        bool,     defaults, disable_ipv6),
};


static void
check_policy(struct uci_element *e, enum fw3_target *pol, const char *name)
{
	if (*pol == FW3_TARGET_UNSPEC)
	{
		warn_elem(e, "has no %s policy specified, defaulting to DROP", name);
		*pol = FW3_TARGET_DROP;
	}
	else if (*pol > FW3_TARGET_DROP)
	{
		warn_elem(e, "has invalid %s policy, defaulting to DROP", name);
		*pol = FW3_TARGET_DROP;
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

		fw3_parse_options(&state->defaults,
		                  default_opts, ARRAY_SIZE(default_opts), s);

		check_policy(e, &defs->policy_input, "input");
		check_policy(e, &defs->policy_output, "output");
		check_policy(e, &defs->policy_forward, "forward");
	}
}

void
fw3_print_default_chains(enum fw3_table table, enum fw3_family family,
                         struct fw3_state *state)
{
	struct fw3_defaults *defs = &state->defaults;
	const char *policy[] = {
		"(bug)",
		"ACCEPT",
		"DROP",
		"DROP",
		"(bug)",
		"(bug)",
		"(bug)",
	};

	switch (table)
	{
	case FW3_TABLE_FILTER:
		fw3_pr(":INPUT %s [0:0]\n", policy[defs->policy_input]);
		fw3_pr(":FORWARD %s [0:0]\n", policy[defs->policy_forward]);
		fw3_pr(":OUTPUT %s [0:0]\n", policy[defs->policy_output]);

		if (defs->custom_chains)
		{
			fw3_pr(":input_rule - [0:0]\n");
			fw3_pr(":output_rule - [0:0]\n");
			fw3_pr(":forwarding_rule - [0:0]\n");
		}

		fw3_pr(":delegate_input - [0:0]\n");
		fw3_pr(":delegate_output - [0:0]\n");
		fw3_pr(":delegate_forward - [0:0]\n");
		fw3_pr(":reject - [0:0]\n");
		fw3_pr(":syn_flood - [0:0]\n");
		break;

	case FW3_TABLE_NAT:
		if (defs->custom_chains)
		{
			fw3_pr(":prerouting_rule - [0:0]\n");
			fw3_pr(":postrouting_rule - [0:0]\n");
		}
		break;

	case FW3_TABLE_MANGLE:
		fw3_pr(":mssfix - [0:0]\n");
		break;

	case FW3_TABLE_RAW:
		if (!defs->drop_invalid)
			fw3_pr(":notrack - [0:0]\n");
		break;
	}
}

void
fw3_print_default_rules(enum fw3_table table, enum fw3_family family,
                        struct fw3_state *state)
{
	int i;
	struct fw3_defaults *defs = &state->defaults;
	const char *chains[] = {
		"INPUT",
		"OUTPUT",
		"FORWARD",
	};

	switch (table)
	{
	case FW3_TABLE_FILTER:
		fw3_pr("-A INPUT -i lo -j ACCEPT\n");
		fw3_pr("-A OUTPUT -o lo -j ACCEPT\n");

		for (i = 0; i < ARRAY_SIZE(chains); i++)
		{
			fw3_pr("-A %s -m conntrack --ctstate RELATED,ESTABLISHED "
			       "-j ACCEPT\n", chains[i]);

			if (defs->drop_invalid)
			{
				fw3_pr("-A %s -m conntrack --ctstate INVALID -j DROP\n",
				       chains[i]);
			}
		}

		if (defs->syn_flood)
		{
			fw3_pr("-A syn_flood -p tcp --syn");
			fw3_format_limit(&defs->syn_flood_rate);
			fw3_pr(" -j RETURN\n");

			fw3_pr("-A syn_flood -j DROP\n");
			fw3_pr("-A INPUT -p tcp --syn -j syn_flood\n");
		}

		if (defs->custom_chains)
		{
			fw3_pr("-A INPUT -j input_rule\n");
			fw3_pr("-A OUTPUT -j output_rule\n");
			fw3_pr("-A FORWARD -j forwarding_rule\n");
		}

		fw3_pr("-A INPUT -j delegate_input\n");
		fw3_pr("-A OUTPUT -j delegate_output\n");
		fw3_pr("-A FORWARD -j delegate_forward\n");

		fw3_pr("-A reject -p tcp -j REJECT --reject-with tcp-reset\n");
		fw3_pr("-A reject -j REJECT --reject-with port-unreach\n");

		if (defs->policy_input == FW3_TARGET_REJECT)
			fw3_pr("-A INPUT -j reject\n");

		if (defs->policy_output == FW3_TARGET_REJECT)
			fw3_pr("-A OUTPUT -j reject\n");

		if (defs->policy_forward == FW3_TARGET_REJECT)
			fw3_pr("-A FORWARD -j reject\n");

		break;

	case FW3_TABLE_NAT:
		if (defs->custom_chains)
		{
			fw3_pr("-A PREROUTING -j prerouting_rule\n");
			fw3_pr("-A POSTROUTING -j postrouting_rule\n");
		}
		break;

	case FW3_TABLE_MANGLE:
		fw3_pr("-A FORWARD -j mssfix\n");
		break;

	case FW3_TABLE_RAW:
		if (!defs->drop_invalid)
			fw3_pr("-A PREROUTING -j notrack\n");
		break;
	}
}

void
fw3_print_flush_rules(enum fw3_table table, enum fw3_family family,
					  struct fw3_state *state, bool complete)
{
	switch (table)
	{
	case FW3_TABLE_FILTER:
		fw3_pr(":INPUT ACCEPT [0:0]\n");
		fw3_pr(":OUTPUT ACCEPT [0:0]\n");
		fw3_pr(":FORWARD ACCEPT [0:0]\n");
		/* fall through */

	case FW3_TABLE_NAT:
		fw3_pr("-F\n");
		fw3_pr("-X\n");
		break;

	case FW3_TABLE_MANGLE:
		if (complete)
		{
			fw3_pr("-F\n");
			fw3_pr("-X\n");
		}
		else
		{
			fw3_pr("-D FORWARD -j mssfix\n");
			fw3_pr("-F mssfix\n");
			fw3_pr("-X mssfix\n");
		}
		break;

	case FW3_TABLE_RAW:
		if (complete)
		{
			fw3_pr("-F\n");
			fw3_pr("-X\n");
		}
		else
		{
			fw3_pr("-D PREROUTING -j notrack\n");
			fw3_pr("-F notrack\n");
			fw3_pr("-X notrack\n");
		}
		break;
	}
}
