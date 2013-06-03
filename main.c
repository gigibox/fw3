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
#include "iptables.h"


static enum fw3_family print_family = FW3_FAMILY_ANY;

static struct fw3_state *run_state = NULL;
static struct fw3_state *cfg_state = NULL;


static bool
build_state(bool runtime)
{
	struct fw3_state *state = NULL;
	struct uci_package *p = NULL;
	FILE *sf;

	state = malloc(sizeof(*state));

	if (!state)
		error("Out of memory");

	memset(state, 0, sizeof(*state));
	state->uci = uci_alloc_context();

	if (!state->uci)
		error("Out of memory");

	if (runtime)
	{
		sf = fopen(FW3_STATEFILE, "r");

		if (sf)
		{
			uci_import(state->uci, sf, "fw3_state", &p, true);
			fclose(sf);
		}

		if (!p)
		{
			uci_free_context(state->uci);
			free(state);

			return false;
		}

		state->statefile = true;

		run_state = state;
	}
	else
	{
		if (!fw3_ubus_connect())
			error("Failed to connect to ubus");

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

		cfg_state = state;
	}

	fw3_load_defaults(state, p);
	fw3_load_ipsets(state, p);
	fw3_load_zones(state, p);
	fw3_load_rules(state, p);
	fw3_load_redirects(state, p);
	fw3_load_forwards(state, p);
	fw3_load_includes(state, p);

	return true;
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
family_running(enum fw3_family family)
{
	return (run_state && has(run_state->defaults.flags, family, family));
}

static void
family_set(struct fw3_state *state, enum fw3_family family, bool set)
{
	if (!state)
		return;

	if (set)
		set(state->defaults.flags, family, family);
	else
		del(state->defaults.flags, family, family);
}

static int
stop(bool complete)
{
	FILE *ct;

	int rv = 1;
	enum fw3_family family;
	enum fw3_table table;
	struct fw3_ipt_handle *handle;

	if (!complete && !run_state)
	{
		warn("The firewall appears to be stopped. "
			 "Use the 'flush' command to forcefully purge all rules.");

		return rv;
	}

	if (!print_family && run_state)
		fw3_hotplug_zones(run_state, false);

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (!complete && !family_running(family))
			continue;

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			if (!(handle = fw3_ipt_open(family, table)))
				continue;

			info(" * %sing %s %s table", complete ? "Flush" : "Clear",
			     fw3_flag_names[family], fw3_flag_names[table]);

			if (complete)
			{
				fw3_flush_all(handle);
			}
			else if (run_state)
			{
				fw3_flush_rules(handle, run_state, false);
				fw3_flush_zones(handle, run_state, false);
			}

			fw3_ipt_commit(handle);
			fw3_ipt_close(handle);
		}

		family_set(run_state, family, false);
		family_set(cfg_state, family, false);

		rv = 0;
	}

	if (run_state)
		fw3_destroy_ipsets(run_state);

	if (complete && (ct = fopen("/proc/net/nf_conntrack", "w")) != NULL)
	{
		info(" * Flushing conntrack table ...");

		fwrite("f\n", 2, 1, ct);
		fclose(ct);
	}

	if (!rv && run_state)
		fw3_write_statefile(run_state);

	return rv;
}

static int
start(void)
{
	int rv = 1;
	enum fw3_family family;
	enum fw3_table table;
	struct fw3_ipt_handle *handle;

	if (!print_family)
		fw3_create_ipsets(cfg_state);

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (family == FW3_FAMILY_V6 && cfg_state->defaults.disable_ipv6)
			continue;

		if (print_family && family != print_family)
			continue;

		if (!print_family && family_running(family))
		{
			warn("The %s firewall appears to be started already. "
			     "If it is indeed empty, remove the %s file and retry.",
			     fw3_flag_names[family], FW3_STATEFILE);

			continue;
		}

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			if (!(handle = fw3_ipt_open(family, table)))
				continue;

			info(" * Populating %s %s table",
			     fw3_flag_names[family], fw3_flag_names[table]);

			fw3_print_default_chains(handle, cfg_state, false);
			fw3_print_zone_chains(handle, cfg_state, false);
			fw3_print_default_head_rules(handle, cfg_state, false);
			fw3_print_rules(handle, cfg_state);
			fw3_print_redirects(handle, cfg_state);
			fw3_print_forwards(handle, cfg_state);
			fw3_print_zone_rules(handle, cfg_state, false);
			fw3_print_default_tail_rules(handle, cfg_state, false);

			if (!print_family)
				fw3_ipt_commit(handle);

			fw3_ipt_close(handle);
		}

		if (!print_family)
			fw3_print_includes(cfg_state, family, false);

		family_set(run_state, family, true);
		family_set(cfg_state, family, true);

		rv = 0;
	}

	if (!rv)
	{
		fw3_set_defaults(cfg_state);

		if (!print_family)
		{
			fw3_run_includes(cfg_state, false);
			fw3_hotplug_zones(cfg_state, true);
			fw3_write_statefile(cfg_state);
		}
	}

	return rv;
}


static int
reload(void)
{
	int rv = 1;
	enum fw3_family family;
	enum fw3_table table;
	struct fw3_ipt_handle *handle;

	if (!run_state)
		return start();

	fw3_hotplug_zones(run_state, false);

	for (family = FW3_FAMILY_V4; family <= FW3_FAMILY_V6; family++)
	{
		if (!family_running(family))
			goto start;

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			if (!(handle = fw3_ipt_open(family, table)))
				continue;

			info(" * Clearing %s %s table",
			     fw3_flag_names[family], fw3_flag_names[table]);

			fw3_flush_rules(handle, run_state, true);
			fw3_flush_zones(handle, run_state, true);
			fw3_ipt_commit(handle);
			fw3_ipt_close(handle);
		}

		family_set(run_state, family, false);
		family_set(cfg_state, family, false);

start:
		if (family == FW3_FAMILY_V6 && cfg_state->defaults.disable_ipv6)
			continue;

		for (table = FW3_TABLE_FILTER; table <= FW3_TABLE_RAW; table++)
		{
			if (!fw3_has_table(family == FW3_FAMILY_V6, fw3_flag_names[table]))
				continue;

			if (!(handle = fw3_ipt_open(family, table)))
				continue;

			info(" * Populating %s %s table",
			     fw3_flag_names[family], fw3_flag_names[table]);

			fw3_print_default_chains(handle, cfg_state, true);
			fw3_print_zone_chains(handle, cfg_state, true);
			fw3_print_default_head_rules(handle, cfg_state, true);
			fw3_print_rules(handle, cfg_state);
			fw3_print_redirects(handle, cfg_state);
			fw3_print_forwards(handle, cfg_state);
			fw3_print_zone_rules(handle, cfg_state, true);
			fw3_print_default_tail_rules(handle, cfg_state, true);

			fw3_ipt_commit(handle);
			fw3_ipt_close(handle);
		}

		fw3_print_includes(cfg_state, family, true);

		family_set(run_state, family, true);
		family_set(cfg_state, family, true);

		rv = 0;
	}

	if (!rv)
	{
		fw3_set_defaults(cfg_state);
		fw3_run_includes(cfg_state, true);
		fw3_hotplug_zones(cfg_state, true);
		fw3_write_statefile(cfg_state);
	}

	return rv;
}

static int
lookup_network(const char *net)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &cfg_state->zones, list)
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
lookup_device(const char *dev)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &cfg_state->zones, list)
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
	fprintf(stderr, "fw3 [-4] [-6] [-q] print\n");
	fprintf(stderr, "fw3 [-q] {start|stop|flush|reload|restart}\n");
	fprintf(stderr, "fw3 [-q] network {net}\n");
	fprintf(stderr, "fw3 [-q] device {dev}\n");

	return 1;
}


int main(int argc, char **argv)
{
	int ch, rv = 1;
	enum fw3_family family = FW3_FAMILY_ANY;
	struct fw3_defaults *defs = NULL;

	while ((ch = getopt(argc, argv, "46dqh")) != -1)
	{
		switch (ch)
		{
		case '4':
			family = FW3_FAMILY_V4;
			break;

		case '6':
			family = FW3_FAMILY_V6;
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

	build_state(false);
	build_state(true);
	defs = &cfg_state->defaults;

	if (optind >= argc)
	{
		rv = usage();
		goto out;
	}

	if (!strcmp(argv[optind], "print"))
	{
		if (family == FW3_FAMILY_ANY)
		{
			family = FW3_FAMILY_V4;
		}
		else if (family == FW3_FAMILY_V6)
		{
			if (defs->disable_ipv6)
				warn("IPv6 rules globally disabled in configuration");
#ifdef DISABLE_IPV6
			else
				warn("IPv6 support is not compiled in");
#endif
		}

		freopen("/dev/null", "w", stderr);

		cfg_state->disable_ipsets = true;
		print_family = family;
		fw3_pr_debug = true;

		rv = start();
	}
	else if (!strcmp(argv[optind], "start"))
	{
		if (fw3_lock())
		{
			rv = start();
			fw3_unlock();
		}
	}
	else if (!strcmp(argv[optind], "stop"))
	{
		if (fw3_lock())
		{
			rv = stop(false);
			fw3_unlock();
		}
	}
	else if (!strcmp(argv[optind], "flush"))
	{
		if (fw3_lock())
		{
			rv = stop(true);
			fw3_unlock();
		}
	}
	else if (!strcmp(argv[optind], "restart"))
	{
		if (fw3_lock())
		{
			stop(true);
			rv = start();
			fw3_unlock();
		}
	}
	else if (!strcmp(argv[optind], "reload"))
	{
		if (fw3_lock())
		{
			rv = reload();
			fw3_unlock();
		}
	}
	else if (!strcmp(argv[optind], "network") && (optind + 1) < argc)
	{
		rv = lookup_network(argv[optind + 1]);
	}
	else if (!strcmp(argv[optind], "device") && (optind + 1) < argc)
	{
		rv = lookup_device(argv[optind + 1]);
	}
	else
	{
		rv = usage();
	}

out:
	if (cfg_state)
		free_state(cfg_state);

	if (run_state)
		free_state(run_state);

	return rv;
}
