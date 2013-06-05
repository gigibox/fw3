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

bool fw3_pr_debug = false;


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

void *
fw3_alloc(size_t size)
{
	void *mem;

	mem = calloc(1, size);

	if (!mem)
		error("Out of memory while allocating %d bytes", size);

	return mem;
}

char *
fw3_strdup(const char *s)
{
	char *ns;

	ns = strdup(s);

	if (!ns)
		error("Out of memory while duplicating string '%s'", s);

	return ns;
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
		fcntl(pfds[1], F_SETFD, fcntl(pfds[1], F_GETFD) | FD_CLOEXEC);
	}

	pipe_fd = fdopen(pfds[1], "w");
	return true;
}

void
fw3_pr(const char *fmt, ...)
{
	va_list args;

	if (fw3_pr_debug && pipe_fd != stdout)
	{
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}

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


static void
write_defaults_uci(struct uci_context *ctx, struct fw3_defaults *d,
                   struct uci_package *dest)
{
	char buf[sizeof("0xffffffff\0")];
	struct uci_ptr ptr = { .p = dest };

	uci_add_section(ctx, dest, "defaults", &ptr.s);

	ptr.o      = NULL;
	ptr.option = "input";
	ptr.value  = fw3_flag_names[d->policy_input];
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "output";
	ptr.value  = fw3_flag_names[d->policy_output];
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "forward";
	ptr.value  = fw3_flag_names[d->policy_forward];
	uci_set(ctx, &ptr);

	sprintf(buf, "0x%x", d->flags[0]);
	ptr.o      = NULL;
	ptr.option = "__flags_v4";
	ptr.value  = buf;
	uci_set(ctx, &ptr);

	sprintf(buf, "0x%x", d->flags[1]);
	ptr.o      = NULL;
	ptr.option = "__flags_v6";
	ptr.value  = buf;
	uci_set(ctx, &ptr);
}

static void
write_zone_uci(struct uci_context *ctx, struct fw3_zone *z,
               struct uci_package *dest)
{
	struct fw3_device *dev;
	struct fw3_address *sub;
	enum fw3_family fam = FW3_FAMILY_ANY;

	char *p, buf[34];

	struct uci_ptr ptr = { .p = dest };

	if (!z->enabled)
		return;

	if (fw3_no_table(z->flags[0]) && !fw3_no_table(z->flags[1]))
		fam = FW3_FAMILY_V6;
	else if (!fw3_no_table(z->flags[0]) && fw3_no_table(z->flags[1]))
		fam = FW3_FAMILY_V4;
	else if (fw3_no_table(z->flags[0]) && fw3_no_table(z->flags[1]))
		return;

	uci_add_section(ctx, dest, "zone", &ptr.s);

	ptr.o      = NULL;
	ptr.option = "name";
	ptr.value  = z->name;
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "input";
	ptr.value  = fw3_flag_names[z->policy_input];
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "output";
	ptr.value  = fw3_flag_names[z->policy_output];
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "forward";
	ptr.value  = fw3_flag_names[z->policy_forward];
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "masq";
	ptr.value  = z->masq ? "1" : "0";
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "conntrack";
	ptr.value  = z->conntrack ? "1" : "0";
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "mtu_fix";
	ptr.value  = z->mtu_fix ? "1" : "0";
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "custom_chains";
	ptr.value  = z->custom_chains ? "1" : "0";
	uci_set(ctx, &ptr);

	if (fam != FW3_FAMILY_ANY)
	{
		ptr.o      = NULL;
		ptr.option = "family";
		ptr.value  = fw3_flag_names[fam];
		uci_set(ctx, &ptr);
	}

	ptr.o      = NULL;
	ptr.option = "device";

	fw3_foreach(dev, &z->devices)
	{
		if (!dev)
			continue;

		p = buf;

		if (dev->invert)
			p += sprintf(p, "!");

		if (*dev->network)
			p += sprintf(p, "%s@%s", dev->name, dev->network);
		else
			p += sprintf(p, "%s", dev->name);

		ptr.value = buf;
		uci_add_list(ctx, &ptr);
	}

	ptr.o      = NULL;
	ptr.option = "subnet";

	fw3_foreach(sub, &z->subnets)
	{
		if (!sub)
			continue;

		ptr.value = fw3_address_to_string(sub, true);
		uci_add_list(ctx, &ptr);
	}

	sprintf(buf, "0x%x", z->flags[0]);
	ptr.o      = NULL;
	ptr.option = "__flags_v4";
	ptr.value  = buf;
	uci_set(ctx, &ptr);

	sprintf(buf, "0x%x", z->flags[1]);
	ptr.o      = NULL;
	ptr.option = "__flags_v6";
	ptr.value  = buf;
	uci_set(ctx, &ptr);
}

static void
write_ipset_uci(struct uci_context *ctx, struct fw3_ipset *s,
                struct uci_package *dest)
{
	struct fw3_ipset_datatype *type;

	char buf[sizeof("65535-65535\0")];

	struct uci_ptr ptr = { .p = dest };

	if (!s->enabled || s->external)
		return;

	uci_add_section(ctx, dest, "ipset", &ptr.s);

	ptr.o      = NULL;
	ptr.option = "name";
	ptr.value  = s->name;
	uci_set(ctx, &ptr);

	ptr.o      = NULL;
	ptr.option = "storage";
	ptr.value  = fw3_ipset_method_names[s->method];
	uci_set(ctx, &ptr);

	list_for_each_entry(type, &s->datatypes, list)
	{
		sprintf(buf, "%s_%s", type->dir, fw3_ipset_type_names[type->type]);
		ptr.o      = NULL;
		ptr.option = "match";
		ptr.value  = buf;
		uci_add_list(ctx, &ptr);
	}

	if (s->iprange.set)
	{
		ptr.o      = NULL;
		ptr.option = "iprange";
		ptr.value  = fw3_address_to_string(&s->iprange, false);
		uci_set(ctx, &ptr);
	}

	if (s->portrange.set)
	{
		sprintf(buf, "%u-%u", s->portrange.port_min, s->portrange.port_max);
		ptr.o      = NULL;
		ptr.option = "portrange";
		ptr.value  = buf;
		uci_set(ctx, &ptr);
	}
}

void
fw3_write_statefile(void *state)
{
	FILE *sf;
	struct fw3_state *s = state;
	struct fw3_zone *z;
	struct fw3_ipset *i;

	struct uci_package *p;

	if (fw3_no_family(s->defaults.flags[0]) &&
	    fw3_no_family(s->defaults.flags[1]))
	{
		unlink(FW3_STATEFILE);
	}
	else
	{
		sf = fopen(FW3_STATEFILE, "w+");

		if (!sf)
		{
			warn("Cannot create state %s: %s", FW3_STATEFILE, strerror(errno));
			return;
		}

		if ((p = uci_lookup_package(s->uci, "fw3_state")) != NULL)
			uci_unload(s->uci, p);

		uci_import(s->uci, sf, "fw3_state", NULL, true);

		if ((p = uci_lookup_package(s->uci, "fw3_state")) != NULL)
		{
			write_defaults_uci(s->uci, &s->defaults, p);

			list_for_each_entry(z, &s->zones, list)
				write_zone_uci(s->uci, z, p);

			list_for_each_entry(i, &s->ipsets, list)
				write_ipset_uci(s->uci, i, p);

			uci_export(s->uci, sf, p, true);
			uci_unload(s->uci, p);
		}

		fsync(fileno(sf));
		fclose(sf);
	}
}


void
fw3_free_object(void *obj, const void *opts)
{
	const struct fw3_option *ol;
	struct list_head *list, *cur, *tmp;

	for (ol = opts; ol->name; ol++)
	{
		if (!ol->elem_size)
			continue;

		list = (struct list_head *)((char *)obj + ol->offset);
		list_for_each_safe(cur, tmp, list)
		{
			list_del(cur);
			free(cur);
		}
	}

	free(obj);
}

void
fw3_free_list(struct list_head *head)
{
	struct list_head *entry, *tmp;

	if (!head)
		return;

	list_for_each_safe(entry, tmp, head)
	{
		list_del(entry);
		free(entry);
	}

	free(head);
}

bool
fw3_hotplug(bool add, void *zone, void *device)
{
	struct fw3_zone *z = zone;
	struct fw3_device *d = device;

	if (!*d->network)
		return false;

	switch (fork())
	{
	case -1:
		warn("Unable to fork(): %s\n", strerror(errno));
		return false;

	case 0:
		break;

	default:
		return true;
	}

	close(0);
	close(1);
	close(2);
	chdir("/");

	clearenv();
	setenv("ACTION",    add ? "add" : "remove", 1);
	setenv("ZONE",      z->name,                1);
	setenv("INTERFACE", d->network,             1);
	setenv("DEVICE",    d->name,                1);

	execl(FW3_HOTPLUG, FW3_HOTPLUG, "firewall", NULL);

	/* unreached */
	return false;
}
