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

#include "includes.h"


const struct fw3_option fw3_include_opts[] = {
	FW3_OPT("enabled",             bool,           include,     enabled),

	FW3_OPT("path",                string,         include,     path),
	FW3_OPT("type",                include_type,   include,     type),
	FW3_OPT("family",              family,         include,     family),
	FW3_OPT("reload",              bool,           include,     reload),

	{ }
};


void
fw3_load_includes(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_include *include;

	INIT_LIST_HEAD(&state->includes);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "include"))
			continue;

		include = malloc(sizeof(*include));

		if (!include)
			continue;

		memset(include, 0, sizeof(*include));

		include->name = e->name;
		include->enabled = true;

		fw3_parse_options(include, fw3_include_opts, s);

		if (!include->enabled)
		{
			fw3_free_include(include);
			continue;
		}

		if (!include->path)
		{
			warn_elem(e, "must specify a path");
			fw3_free_include(include);
			continue;
		}

		if (include->type == FW3_INC_TYPE_RESTORE && !include->family)
			warn_elem(e, "does not specify a family, include will get loaded "
			             "with both iptables-restore and ip6tables-restore!");

		list_add_tail(&include->list, &state->includes);
		continue;
	}
}


static void
print_include(struct fw3_include *include)
{
	FILE *f;
	char line[1024];

	info(" * Loading include '%s'", include->path);

	if (!(f = fopen(include->path, "r")))
	{
		info("   ! Skipping due to open error: %s", strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f))
		fw3_pr(line);

	fclose(f);
}

void
fw3_print_includes(struct fw3_state *state, enum fw3_family family, bool reload)
{
	struct fw3_include *include;

	bool exec = false;
	const char *restore = "iptables-restore";

	if (family == FW3_FAMILY_V6)
		restore = "ip6tables-restore";

	list_for_each_entry(include, &state->includes, list)
	{
		if (reload && !include->reload)
			continue;

		if (include->type != FW3_INC_TYPE_RESTORE)
			continue;

		if (!fw3_is_family(include, family))
			continue;

		if (!exec)
		{
			exec = fw3_command_pipe(false, restore, "--noflush");

			if (!exec)
				return;
		}

		print_include(include);
	}

	if (exec)
		fw3_command_close();
}


static void
run_include(struct fw3_include *include)
{
	int rv;
	struct stat s;
	const char *tmpl =
		"config() { "
			"echo \"You cannot use UCI in firewall includes!\" >&2; "
			"exit 1; "
		"}; . %s";

	char buf[PATH_MAX + sizeof(tmpl)];

	info(" * Running script '%s'", include->path);

	if (stat(include->path, &s))
	{
		info("   ! Skipping due to path error: %s", strerror(errno));
		return;
	}

	snprintf(buf, sizeof(buf), tmpl, include->path);
	rv = system(buf);

	if (rv)
		info("   ! Failed with exit code %u", WEXITSTATUS(rv));
}

void
fw3_run_includes(struct fw3_state *state, bool reload)
{
	struct fw3_include *include;

	list_for_each_entry(include, &state->includes, list)
	{
		if (reload && !include->reload)
			continue;

		if (include->type == FW3_INC_TYPE_SCRIPT)
			run_include(include);
	}
}
