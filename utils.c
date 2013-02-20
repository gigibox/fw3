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

#include "utils.h"
#include "options.h"

#include "zones.h"
#include "ipsets.h"


static int lock_fd = -1;
static pid_t pipe_pid = -1;
static FILE *pipe_fd = NULL;

static void
warn_elem_section_name(struct uci_section *s, bool find_name)
{
	int i = 0;
	struct uci_option *o;
	struct uci_element *tmp;

	if (s->anonymous)
	{
		uci_foreach_element(&s->package->sections, tmp)
		{
			if (strcmp(uci_to_section(tmp)->type, s->type))
				continue;

			if (&s->e == tmp)
				break;

			i++;
		}

		fprintf(stderr, "@%s[%d]", s->type, i);

		if (find_name)
		{
			uci_foreach_element(&s->options, tmp)
			{
				o = uci_to_option(tmp);

				if (!strcmp(tmp->name, "name") && (o->type == UCI_TYPE_STRING))
				{
					fprintf(stderr, " (%s)", o->v.string);
					break;
				}
			}
		}
	}
	else
	{
		fprintf(stderr, "'%s'", s->e.name);
	}

	if (find_name)
		fprintf(stderr, " ");
}

void
warn_elem(struct uci_element *e, const char *format, ...)
{
	if (e->type == UCI_TYPE_SECTION)
	{
		fprintf(stderr, "Warning: Section ");
		warn_elem_section_name(uci_to_section(e), true);
	}
	else if (e->type == UCI_TYPE_OPTION)
	{
		fprintf(stderr, "Warning: Option ");
		warn_elem_section_name(uci_to_option(e)->section, false);
		fprintf(stderr, ".%s ", e->name);
	}

    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);

	fprintf(stderr, "\n");
}

void
warn(const char* format, ...)
{
	fprintf(stderr, "Warning: ");
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
	fprintf(stderr, "\n");
}

void
error(const char* format, ...)
{
	fprintf(stderr, "Error: ");
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
	fprintf(stderr, "\n");

	exit(1);
}

void
info(const char* format, ...)
{
	va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
	fprintf(stderr, "\n");
}

const char *
fw3_find_command(const char *cmd)
{
	struct stat s;
	int plen = 0, clen = strlen(cmd) + 1;
	char *search, *p;
	static char path[PATH_MAX];

	if (!stat(cmd, &s) && S_ISREG(s.st_mode))
		return cmd;

	search = getenv("PATH");

	if (!search)
		search = "/bin:/usr/bin:/sbin:/usr/sbin";

	p = search;

	do
	{
		if (*p != ':' && *p != '\0')
			continue;

		plen = p - search;

		if ((plen + clen) >= sizeof(path))
			continue;

		strncpy(path, search, plen);
		sprintf(path + plen, "/%s", cmd);

		if (!stat(path, &s) && S_ISREG(s.st_mode))
			return path;

		search = p + 1;
	}
	while (*p++);

	return NULL;
}

bool
fw3_stdout_pipe(void)
{
	pipe_fd = stdout;
	return true;
}

bool
__fw3_command_pipe(bool silent, const char *command, ...)
{
	pid_t pid;
	va_list argp;
	int pfds[2];
	int argn;
	char *arg, **args, **tmp;

	command = fw3_find_command(command);

	if (!command)
		return false;

	if (pipe(pfds))
		return false;

	argn = 2;
	args = malloc(argn * sizeof(arg));

	if (!args)
		return false;

	args[0] = (char *)command;
	args[1] = NULL;

	va_start(argp, command);

	while ((arg = va_arg(argp, char *)) != NULL)
	{
		tmp = realloc(args, ++argn * sizeof(arg));

		if (!tmp)
			break;

		args = tmp;
		args[argn-2] = arg;
		args[argn-1] = NULL;
	}

	va_end(argp);

	switch ((pid = fork()))
	{
	case -1:
		return false;

	case 0:
		dup2(pfds[0], 0);

		close(pfds[0]);
		close(pfds[1]);

		close(1);

		if (silent)
			close(2);

		execv(command, args);

	default:
		signal(SIGPIPE, SIG_IGN);
		pipe_pid = pid;
		close(pfds[0]);
	}

	pipe_fd = fdopen(pfds[1], "w");
	return true;
}

void
fw3_pr(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(pipe_fd, fmt, args);
    va_end(args);
}

void
fw3_command_close(void)
{
	if (pipe_fd && pipe_fd != stdout)
		fclose(pipe_fd);

	if (pipe_pid > -1)
		waitpid(pipe_pid, NULL, 0);

	signal(SIGPIPE, SIG_DFL);

	pipe_fd = NULL;
	pipe_pid = -1;
}

bool
fw3_has_table(bool ipv6, const char *table)
{
	FILE *f;

	char line[12];
	bool seen = false;

	const char *path = ipv6
		? "/proc/net/ip6_tables_names" : "/proc/net/ip_tables_names";

	if (!(f = fopen(path, "r")))
		return false;

	while (fgets(line, sizeof(line), f))
	{
		if (!strncmp(line, table, strlen(table)))
		{
			seen = true;
			break;
		}
	}

	fclose(f);

	return seen;
}


bool
fw3_lock(void)
{
	lock_fd = open(FW3_LOCKFILE, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);

	if (lock_fd < 0)
	{
		warn("Cannot create lock file %s: %s", FW3_LOCKFILE, strerror(errno));
		return false;
	}

	if (flock(lock_fd, LOCK_EX))
	{
		warn("Cannot acquire exclusive lock: %s", strerror(errno));
		return false;
	}

	return true;
}

void
fw3_unlock(void)
{
	if (lock_fd < 0)
		return;

	if (flock(lock_fd, LOCK_UN))
		warn("Cannot release exclusive lock: %s", strerror(errno));

	close(lock_fd);
	unlink(FW3_LOCKFILE);

	lock_fd = -1;
}


bool
fw3_read_statefile(void *state)
{
	FILE *sf;

	int n, type;
	char line[128];
	const char *p, *name;

	uint16_t flags[2];

	struct fw3_state *s = state;
	struct fw3_zone *zone;
	struct fw3_ipset *ipset;

	sf = fopen(FW3_STATEFILE, "r");

	if (!sf)
		return false;

	while (fgets(line, sizeof(line), sf))
	{
		p = strtok(line, " \t\n");

		if (!p)
			continue;

		type = strtoul(p, NULL, 10);
		name = strtok(NULL, " \t\n");

		if (!name)
			continue;

		for (n = 0, p = strtok(NULL, " \t\n");
		     n < ARRAY_SIZE(flags) && p != NULL;
		     n++, p = strtok(NULL, " \t\n"))
		{
			flags[n] = strtoul(p, NULL, 10);
		}

		switch (type)
		{
		case FW3_TYPE_DEFAULTS:
			s->running_defaults.flags = flags[0];
			break;

		case FW3_TYPE_ZONE:
			if (!(zone = fw3_lookup_zone(state, name, false)))
			{
				zone = fw3_alloc_zone();

				if (!zone)
					continue;

				zone->name = strdup(name);
				list_add_tail(&zone->list, &s->zones);
			}

			zone->src_flags = flags[0];
			zone->dst_flags = flags[1];
			list_add_tail(&zone->running_list, &s->running_zones);
			break;

		case FW3_TYPE_IPSET:
			if (!(ipset = fw3_lookup_ipset(state, name, false)))
			{
				ipset = fw3_alloc_ipset();

				if (!ipset)
					continue;

				ipset->name = strdup(name);
				list_add_tail(&ipset->list, &s->ipsets);
			}

			ipset->flags = flags[0];
			list_add_tail(&ipset->running_list, &s->running_ipsets);
			break;
		}
	}

	fclose(sf);

	return true;
}

void
fw3_write_statefile(void *state)
{
	FILE *sf;
	struct fw3_state *s = state;
	struct fw3_defaults *d = &s->defaults;
	struct fw3_zone *z;
	struct fw3_ipset *i;

	int mask = (1 << FW3_FAMILY_V4) | (1 << FW3_FAMILY_V6);

	if (!(d->flags & mask))
	{
		if (unlink(FW3_STATEFILE))
			warn("Unable to remove state %s: %s",
			     FW3_STATEFILE, strerror(errno));

		return;
	}

	sf = fopen(FW3_STATEFILE, "w");

	if (!sf)
	{
		warn("Cannot create state %s: %s", FW3_STATEFILE, strerror(errno));
		return;
	}

	fprintf(sf, "%u - %u\n", FW3_TYPE_DEFAULTS, d->flags);

	list_for_each_entry(z, &s->running_zones, running_list)
	{
		fprintf(sf, "%u %s %u %u\n", FW3_TYPE_ZONE,
		        z->name, z->src_flags, z->dst_flags);
	}

	list_for_each_entry(i, &s->running_ipsets, running_list)
	{
		fprintf(sf, "%u %s %u\n", FW3_TYPE_IPSET, i->name, i->flags);
	}

	fclose(sf);
}


struct object_list_heads
{
	struct list_head list;
	struct list_head running_list;
};

void
fw3_set_running(void *object, struct list_head *dest)
{
	struct object_list_heads *o = object;

	if (dest && !o->running_list.next)
		list_add_tail(&o->running_list, dest);
	else if (!dest && o->running_list.next)
		list_del(&o->running_list);
}
