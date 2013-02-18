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

#include <stdio.h>
#include <unistd.h>

#include "options.h"
#include "defaults.h"
#include "zones.h"
#include "rules.h"
#include "redirects.h"
#include "forwards.h"
#include "ipsets.h"
#include "ubus.h"


static bool print_rules = false;
static bool skip_family[FW3_FAMILY_V6 + 1] = { false };


static struct fw3_state *
build_state(void)
{
	struct fw3_state *state = NULL;
	struct uci_package *p = NULL;

	state = malloc(sizeof(*state));

	if (!state)
		error("Out of memory");

	memset(state, 0, sizeof(*state));
	state->uci = uci_alloc_context();

	if (!state->uci)
		error("Out of memory");

	if (uci_load(state->uci, "firewall", &p))
	{
		uci_perror(state->uci, NULL);
		error("Failed to load /etc/config/firewall");
	}

	if (!fw3_find_command("ipset"))
	{
		warn("Unable to locate ipset utility, disabling ipset support");
		state->disable_ipsets = true;
	}

	fw3_load_defaults(state, p);
	fw3_load_ipsets(state, p);
	fw3_load_zones(state, p);
	fw3_load_rules(state, p);
	fw3_load_redirects(state, p);
	fw3_load_forwards(state, p);

	if (state->defaults.disable_ipv6 && !skip_family[FW3_FAMILY_V6])
	{
		warn("IPv6 rules globally disabled in configuration");
		skip_family[FW3_FAMILY_V6] = true;
	}

	return state;
}

static void
free_state(struct fw3_state *state)
{
	struct list_head *cur, *tmp;

	list_for_each_safe(cur, tmp, &state->zones)
		fw3_free_zone((struct fw3_zone *)cur);

	list_for_each_safe(cur, tmp, &state->rules)
		fw3_free_rule((struct fw3_rule *)cur);

	list_for_each_safe(cur, tmp, &state->redirects)
		fw3_free_redirect((struct fw3_redirect *)cur);

	list_for_each_safe(cur, tmp, &state->forwards)
		fw3_free_forward((struct fw3_forward *)cur);

	uci_free_context(state->uci);

	free(state);

	fw3_ubus_disconnect();
}


static bool
restore_pipe(enum fw3_family family, bool silent)
{
	const char *cmd[] = {
		"(bug)",
		"iptables-restore",
		"ip6tables-restore",
	};

	if (print_rules)
		return fw3_stdout_pipe();

	if (!fw3_command_pipe(silent, cmd[family], "--lenient", "--noflush"))
	{
		warn("Unable to execute %s", cmd[family]);
		return false;
	}

	return true;
}

static int
stop(struct fw3_state *state, bool complete, bool ipsets)
{
	enum fw3_family family;
	enum fw3_table table;

	struct list_head *statefile = fw3_read_state();

	const char *tables[] = {
		"filter",
		"nat",
		"mangle",
		"raw",
	};

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (skip_family[family] || !restore_pipe(family, true))
			continue;

		info("Removing IPv%d rules ...", family == FW3_FAMILY_V4 ? 4 : 6);

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, tables[table]))
				continue;

			info(" * %sing %s table",
			     complete ? "Flush" : "Clear", tables[table]);

			fw3_pr("*%s\n", tables[table]);

			if (complete)
			{
				fw3_flush_all(table);
			}
			else
			{
				/* pass 1 */
				fw3_flush_rules(table, family, false, statefile);
				fw3_flush_zones(table, family, false, statefile);

				/* pass 2 */
				fw3_flush_rules(table, family, true, statefile);
				fw3_flush_zones(table, family, true, statefile);
			}

			fw3_pr("COMMIT\n");
		}

		fw3_command_close();
	}

	if (ipsets && fw3_command_pipe(false, "ipset", "-exist", "-"))
	{
		fw3_destroy_ipsets(statefile);
		fw3_command_close();
	}

	fw3_free_state(statefile);

	return 0;
}

static int
start(struct fw3_state *state)
{
	enum fw3_family family;
	enum fw3_table table;

	const char *tables[] = {
		"filter",
		"nat",
		"mangle",
		"raw",
	};

	if (!print_rules && fw3_command_pipe(false, "ipset", "-exist", "-"))
	{
		fw3_create_ipsets(state);
		fw3_command_close();
	}

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (skip_family[family] || !restore_pipe(family, false))
			continue;

		info("Constructing IPv%d rules ...", family == FW3_FAMILY_V4 ? 4 : 6);

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, tables[table]))
				continue;

			info(" * Populating %s table", tables[table]);

			fw3_pr("*%s\n", tables[table]);
			fw3_print_default_chains(table, family, state);
			fw3_print_zone_chains(table, family, state);
			fw3_print_default_head_rules(table, family, state);
			fw3_print_rules(table, family, state);
			fw3_print_redirects(table, family, state);
			fw3_print_forwards(table, family, state);
			fw3_print_zone_rules(table, family, state);
			fw3_print_default_tail_rules(table, family, state);
			fw3_pr("COMMIT\n");
		}

		fw3_command_close();
	}

	return 0;
}

static int
lookup_network(struct fw3_state *state, const char *net)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &state->zones, list)
	{
		list_for_each_entry(d, &z->networks, list)
		{
			if (!strcmp(d->name, net))
			{
				printf("%s\n", z->name);
				return 0;
			}
		}
	}

	return 1;
}

static int
lookup_device(struct fw3_state *state, const char *dev)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &state->zones, list)
	{
		list_for_each_entry(d, &z->devices, list)
		{
			if (!strcmp(d->name, dev))
			{
				printf("%s\n", z->name);
				return 0;
			}
		}
	}

	return 1;
}

static int
usage(void)
{
	fprintf(stderr, "fw3 [-4] [-6] [-q] {start|stop|flush|restart|print}\n");
	fprintf(stderr, "fw3 [-q] network {net}\n");
	fprintf(stderr, "fw3 [-q] device {dev}\n");

	return 1;
}


int main(int argc, char **argv)
{
	int ch, rv = 1;
	struct fw3_state *state = NULL;

	while ((ch = getopt(argc, argv, "46qh")) != -1)
	{
		switch (ch)
		{
		case '4':
			skip_family[FW3_FAMILY_V4] = false;
			skip_family[FW3_FAMILY_V6] = true;
			break;

		case '6':
			skip_family[FW3_FAMILY_V4] = true;
			skip_family[FW3_FAMILY_V6] = false;
			break;

		case 'q':
			freopen("/dev/null", "w", stderr);
			break;

		case 'h':
			rv = usage();
			goto out;
		}
	}

	if (!fw3_ubus_connect())
		error("Failed to connect to ubus");

	state = build_state();

	if (!fw3_lock())
		goto out;

	if (optind >= argc)
	{
		rv = usage();
		goto out;
	}

	if (!strcmp(argv[optind], "print"))
	{
		freopen("/dev/null", "w", stderr);

		state->disable_ipsets = true;
		print_rules = true;

		if (!skip_family[FW3_FAMILY_V4] && !skip_family[FW3_FAMILY_V6])
			skip_family[FW3_FAMILY_V6] = true;

		rv = start(state);
	}
	else if (!strcmp(argv[optind], "start"))
	{
		if (fw3_has_state())
		{
			warn("The firewall appears to be started already. "
				 "If it is indeed empty, remove the %s file and retry.",
				 FW3_STATEFILE);

			goto out;
		}

		rv = start(state);
		fw3_write_state(state);
	}
	else if (!strcmp(argv[optind], "stop"))
	{
		if (!fw3_has_state())
		{
			warn("The firewall appears to be stopped. "
				 "Use the 'flush' command to forcefully purge all rules.");

			goto out;
		}

		rv = stop(state, false, true);

		fw3_remove_state();
	}
	else if (!strcmp(argv[optind], "flush"))
	{
		rv = stop(state, true, true);

		if (fw3_has_state())
			fw3_remove_state();
	}
	else if (!strcmp(argv[optind], "restart"))
	{
		if (fw3_has_state())
		{
			stop(state, false, false);
			fw3_remove_state();
		}

		rv = start(state);
		fw3_write_state(state);
	}
	else if (!strcmp(argv[optind], "network") && (optind + 1) < argc)
	{
		rv = lookup_network(state, argv[optind + 1]);
	}
	else if (!strcmp(argv[optind], "device") && (optind + 1) < argc)
	{
		rv = lookup_device(state, argv[optind + 1]);
	}
	else
	{
		rv = usage();
	}

out:
	if (state)
		free_state(state);

	fw3_unlock();

	return rv;
}
