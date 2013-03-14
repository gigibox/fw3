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
#include "includes.h"
#include "ubus.h"


static bool print_rules = false;
static enum fw3_family use_family = FW3_FAMILY_ANY;


static struct fw3_state *
build_state(void)
{
	struct fw3_state *state = NULL;
	struct uci_package *p = NULL;

	if (!fw3_ubus_connect())
		error("Failed to connect to ubus");

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

	INIT_LIST_HEAD(&state->running_zones);
	INIT_LIST_HEAD(&state->running_ipsets);

	fw3_load_defaults(state, p);
	fw3_load_ipsets(state, p);
	fw3_load_zones(state, p);
	fw3_load_rules(state, p);
	fw3_load_redirects(state, p);
	fw3_load_forwards(state, p);
	fw3_load_includes(state, p);

	state->statefile = fw3_read_statefile(state);

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

	list_for_each_safe(cur, tmp, &state->ipsets)
		fw3_free_ipset((struct fw3_ipset *)cur);

	list_for_each_safe(cur, tmp, &state->includes)
		fw3_free_include((struct fw3_include *)cur);

	uci_free_context(state->uci);

	free(state);

	fw3_ubus_disconnect();
}


static bool
restore_pipe(enum fw3_family family, bool silent)
{
	const char *cmd;

	cmd = (family == FW3_FAMILY_V4) ? "iptables-restore" : "ip6tables-restore";

	if (print_rules)
		return fw3_stdout_pipe();

	if (!fw3_command_pipe(silent, cmd, "--lenient", "--noflush"))
	{
		warn("Unable to execute %s", cmd);
		return false;
	}

	return true;
}

static bool
family_running(struct fw3_state *state, enum fw3_family family)
{
	return has(state->defaults.flags, family, family);
}

static bool
family_used(enum fw3_family family)
{
	return (use_family == FW3_FAMILY_ANY) || (use_family == family);
}

static void
family_set(struct fw3_state *state, enum fw3_family family, bool set)
{
	if (set)
		set(state->defaults.flags, family, family);
	else
		del(state->defaults.flags, family, family);
}

static int
stop(struct fw3_state *state, bool complete, bool reload)
{
	FILE *ct;

	int rv = 1;
	enum fw3_family family;
	enum fw3_table table;

	if (!complete && !state->statefile)
	{
		if (!reload)
			warn("The firewall appears to be stopped. "
				 "Use the 'flush' command to forcefully purge all rules.");

		return rv;
	}

	if (!print_rules)
		fw3_hotplug_zones(false, state);

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (!complete && !family_running(state, family))
			continue;

		if (!family_used(family) || !restore_pipe(family, true))
			continue;

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			info(" * %sing %s %s table", complete ? "Flush" : "Clear",
			     fw3_flag_names[family], fw3_flag_names[table]);

			fw3_pr("*%s\n", fw3_flag_names[table]);

			if (complete)
			{
				fw3_flush_all(table);
			}
			else
			{
				/* pass 1 */
				fw3_flush_rules(table, family, false, reload, state);
				fw3_flush_zones(table, family, false, reload, state);

				/* pass 2 */
				fw3_flush_rules(table, family, true, reload, state);
				fw3_flush_zones(table, family, true, reload, state);
			}

			fw3_pr("COMMIT\n");
		}

		fw3_command_close();

		if (!reload)
		{
			if (fw3_command_pipe(false, "ipset", "-exist", "-"))
			{
				fw3_destroy_ipsets(state, family);
				fw3_command_close();
			}

			family_set(state, family, false);
		}

		rv = 0;
	}

	if (complete && (ct = fopen("/proc/net/nf_conntrack", "w")) != NULL)
	{
		info(" * Flushing conntrack table ...");

		fwrite("f\n", 2, 1, ct);
		fclose(ct);
	}

	if (!rv)
		fw3_write_statefile(state);

	return rv;
}

static int
start(struct fw3_state *state, bool reload)
{
	int rv = 1;
	enum fw3_family family;
	enum fw3_table table;

	if (!print_rules && !reload)
	{
		if (fw3_command_pipe(false, "ipset", "-exist", "-"))
		{
			fw3_create_ipsets(state);
			fw3_command_close();
		}
	}

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (!family_used(family))
			continue;

		if (!print_rules && !reload && family_running(state, family))
		{
			warn("The %s firewall appears to be started already. "
			     "If it is indeed empty, remove the %s file and retry.",
			     fw3_flag_names[family], FW3_STATEFILE);

			continue;
		}

		if (!restore_pipe(family, false))
			continue;

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			info(" * Populating %s %s table",
			     fw3_flag_names[family], fw3_flag_names[table]);

			fw3_pr("*%s\n", fw3_flag_names[table]);
			fw3_print_default_chains(table, family, reload, state);
			fw3_print_zone_chains(table, family, reload, state);
			fw3_print_default_head_rules(table, family, reload, state);
			fw3_print_rules(table, family, state);
			fw3_print_redirects(table, family, state);
			fw3_print_forwards(table, family, state);
			fw3_print_zone_rules(table, family, reload, state);
			fw3_print_default_tail_rules(table, family, reload, state);
			fw3_pr("COMMIT\n");
		}

		fw3_print_includes(state, family, reload);

		fw3_command_close();
		family_set(state, family, true);

		rv = 0;
	}

	if (!rv)
	{
		fw3_set_defaults(state);

		if (!print_rules)
		{
			fw3_run_includes(state, reload);
			fw3_hotplug_zones(true, state);
			fw3_write_statefile(state);
		}
	}

	return rv;
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
	fprintf(stderr, "fw3 [-4] [-6] [-q] {start|stop|flush|reload|restart|print}\n");
	fprintf(stderr, "fw3 [-q] network {net}\n");
	fprintf(stderr, "fw3 [-q] device {dev}\n");

	return 1;
}


int main(int argc, char **argv)
{
	int ch, rv = 1;
	struct fw3_state *state = NULL;
	struct fw3_defaults *defs = NULL;

	while ((ch = getopt(argc, argv, "46dqh")) != -1)
	{
		switch (ch)
		{
		case '4':
			use_family = FW3_FAMILY_V4;
			break;

		case '6':
			use_family = FW3_FAMILY_V6;
			break;

		case 'd':
			fw3_pr_debug = true;
			break;

		case 'q':
			freopen("/dev/null", "w", stderr);
			break;

		case 'h':
			rv = usage();
			goto out;
		}
	}

	state = build_state();
	defs = &state->defaults;

	if (!fw3_lock())
		goto out;

	if (optind >= argc)
	{
		rv = usage();
		goto out;
	}

	if (use_family == FW3_FAMILY_V6 && defs->disable_ipv6)
		warn("IPv6 rules globally disabled in configuration");

	if (!strcmp(argv[optind], "print"))
	{
		if (use_family == FW3_FAMILY_ANY)
			use_family = FW3_FAMILY_V4;

		freopen("/dev/null", "w", stderr);

		state->disable_ipsets = true;
		print_rules = true;

		rv = start(state, false);
	}
	else if (!strcmp(argv[optind], "start"))
	{
		rv = start(state, false);
	}
	else if (!strcmp(argv[optind], "stop"))
	{
		rv = stop(state, false, false);
	}
	else if (!strcmp(argv[optind], "flush"))
	{
		rv = stop(state, true, false);
	}
	else if (!strcmp(argv[optind], "restart"))
	{
		stop(state, true, false);
		free_state(state);

		state = build_state();
		rv = start(state, false);
	}
	else if (!strcmp(argv[optind], "reload"))
	{
		rv = stop(state, false, true);
		rv = start(state, !rv);
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
