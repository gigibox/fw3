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

#include "ipsets.h"


const struct fw3_option fw3_ipset_opts[] = {
	FW3_OPT("enabled",       bool,           ipset,     enabled),

	FW3_OPT("name",          string,         ipset,     name),
	FW3_OPT("family",        family,         ipset,     family),

	FW3_OPT("storage",       ipset_method,   ipset,     method),
	FW3_LIST("match",        ipset_datatype, ipset,     datatypes),

	FW3_OPT("iprange",       address,        ipset,     iprange),
	FW3_OPT("portrange",     port,           ipset,     portrange),

	FW3_OPT("netmask",       int,            ipset,     netmask),
	FW3_OPT("maxelem",       int,            ipset,     maxelem),
	FW3_OPT("hashsize",      int,            ipset,     hashsize),
	FW3_OPT("timeout",       int,            ipset,     timeout),

	FW3_OPT("external",      string,         ipset,     external),

	{ }
};

#define T(m, t1, t2, t3, r, o) \
	{ FW3_IPSET_METHOD_##m, \
	  FW3_IPSET_TYPE_##t1 | (FW3_IPSET_TYPE_##t2 << 8) | (FW3_IPSET_TYPE_##t3 << 16), \
	  r, o }

enum ipset_optflag {
	OPT_IPRANGE   = (1 << 0),
	OPT_PORTRANGE = (1 << 1),
	OPT_NETMASK   = (1 << 2),
	OPT_HASHSIZE  = (1 << 3),
	OPT_MAXELEM   = (1 << 4),
	OPT_FAMILY    = (1 << 5),
};

struct ipset_type {
	enum fw3_ipset_method method;
	uint32_t types;
	uint8_t required;
	uint8_t optional;
};

static struct ipset_type ipset_types[] = {
	T(BITMAP, IP,   UNSPEC, UNSPEC, OPT_IPRANGE, OPT_NETMASK),
	T(BITMAP, IP,   MAC,    UNSPEC, OPT_IPRANGE, 0),
	T(BITMAP, PORT, UNSPEC, UNSPEC, OPT_PORTRANGE, 0),

	T(HASH,   IP,   UNSPEC, UNSPEC, 0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM | OPT_NETMASK),
	T(HASH,   NET,  UNSPEC, UNSPEC, 0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM),
	T(HASH,   IP,   PORT,   UNSPEC, 0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM),
	T(HASH,   NET,  PORT,   UNSPEC, 0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM),
	T(HASH,   IP,   PORT,   IP,     0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM),
	T(HASH,   IP,   PORT,   NET,    0,
	  OPT_FAMILY | OPT_HASHSIZE | OPT_MAXELEM),

	T(LIST,   SET,  UNSPEC, UNSPEC, 0, OPT_MAXELEM),
};


static bool
check_types(struct uci_element *e, struct fw3_ipset *ipset)
{
	int i = 0;
	uint32_t typelist = 0;
	struct fw3_ipset_datatype *type;

	const char *methods[] = {
		"(bug)",
		"bitmap",
		"hash",
		"list",
	};

	typelist = 0;

	list_for_each_entry(type, &ipset->datatypes, list)
	{
		if (i >= 3)
		{
			warn_elem(e, "must not have more than 3 datatypes assigned");
			return false;
		}

		typelist |= (type->type << (i++ * 8));
	}

	/* find a suitable storage method if none specified */
	if (ipset->method == FW3_IPSET_METHOD_UNSPEC)
	{
		for (i = 0; i < ARRAY_SIZE(ipset_types); i++)
		{
			if (ipset_types[i].types == typelist)
			{
				ipset->method = ipset_types[i].method;

				warn_elem(e, "defines no storage method, assuming '%s'",
				          methods[ipset->method]);

				break;
			}
		}
	}

	//typelist |= ipset->method;

	for (i = 0; i < ARRAY_SIZE(ipset_types); i++)
	{
		if (ipset_types[i].method == ipset->method &&
		    ipset_types[i].types == typelist)
		{
			if (!ipset->external || !*ipset->external)
			{
				if ((ipset_types[i].required & OPT_IPRANGE) &&
					!ipset->iprange.set)
				{
					warn_elem(e, "requires an ip range");
					return false;
				}

				if ((ipset_types[i].required & OPT_PORTRANGE) &&
				    !ipset->portrange.set)
				{
					warn_elem(e, "requires a port range");
					return false;
				}

				if (!(ipset_types[i].required & OPT_IPRANGE) &&
				    ipset->iprange.set)
				{
					warn_elem(e, "iprange ignored");
					ipset->iprange.set = false;
				}

				if (!(ipset_types[i].required & OPT_PORTRANGE) &&
				    ipset->portrange.set)
				{
					warn_elem(e, "portrange ignored");
					ipset->portrange.set = false;
				}

				if (!(ipset_types[i].optional & OPT_NETMASK) &&
				    ipset->netmask > 0)
				{
					warn_elem(e, "netmask ignored");
					ipset->netmask = 0;
				}

				if (!(ipset_types[i].optional & OPT_HASHSIZE) &&
				    ipset->hashsize > 0)
				{
					warn_elem(e, "hashsize ignored");
					ipset->hashsize = 0;
				}

				if (!(ipset_types[i].optional & OPT_MAXELEM) &&
				    ipset->maxelem > 0)
				{
					warn_elem(e, "maxelem ignored");
					ipset->maxelem = 0;
				}

				if (!(ipset_types[i].optional & OPT_FAMILY) &&
				    ipset->family != FW3_FAMILY_ANY)
				{
					warn_elem(e, "family ignored");
					ipset->family = FW3_FAMILY_ANY;
				}
			}

			return true;
		}
	}

	warn_elem(e, "has an invalid combination of storage method and matches");
	return false;
}

struct fw3_ipset *
fw3_alloc_ipset(void)
{
	struct fw3_ipset *ipset;

	ipset = malloc(sizeof(*ipset));

	if (!ipset)
		return NULL;

	memset(ipset, 0, sizeof(*ipset));

	INIT_LIST_HEAD(&ipset->datatypes);

	return ipset;
}

void
fw3_load_ipsets(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_ipset *ipset;

	INIT_LIST_HEAD(&state->ipsets);

	if (state->disable_ipsets)
		return;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "ipset"))
			continue;

		ipset = fw3_alloc_ipset();

		if (!ipset)
			continue;

		fw3_parse_options(ipset, fw3_ipset_opts, s);

		if (!ipset->name || !*ipset->name)
		{
			warn_elem(e, "must have a name assigned");
		}
		//else if (fw3_lookup_ipset(state, ipset->name) != NULL)
		//{
		//	warn_elem(e, "has duplicated set name '%s'", ipset->name);
		//}
		else if (list_empty(&ipset->datatypes))
		{
			warn_elem(e, "has no datatypes assigned");
		}
		else if (check_types(e, ipset))
		{
			list_add_tail(&ipset->list, &state->ipsets);
			continue;
		}

		fw3_free_ipset(ipset);
	}
}


static void
create_ipset(struct fw3_ipset *ipset, struct fw3_state *state)
{
	bool first = true;
	char s[INET6_ADDRSTRLEN];

	struct fw3_ipset_datatype *type;
	struct fw3_address *a;

	const char *methods[] = {
		"(bug)",
		"bitmap",
		"hash",
		"list",
	};

	const char *types[] = {
		"(bug)",
		"ip",
		"port",
		"mac",
		"net",
		"set",
	};

	if (ipset->external && *ipset->external)
		return;

	info(" * Creating ipset %s", ipset->name);

	first = true;
	fw3_pr("create %s %s", ipset->name, methods[ipset->method]);

	list_for_each_entry(type, &ipset->datatypes, list)
	{
		fw3_pr("%c%s", first ? ':' : ',', types[type->type]);
		first = false;
	}

	if (ipset->iprange.set)
	{
		a = &ipset->iprange;

		if (!a->range)
		{
			inet_ntop(a->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a->address.v6, s, sizeof(s));

			fw3_pr(" range %s/%u", s, a->mask);
		}
		else
		{
			inet_ntop(a->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a->address.v6, s, sizeof(s));

			fw3_pr(" range %s", s);

			inet_ntop(a->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a->address2.v6, s, sizeof(s));

			fw3_pr("-%s", s);
		}
	}
	else if (ipset->portrange.set)
	{
		fw3_pr(" range %u-%u",
		       ipset->portrange.port_min, ipset->portrange.port_max);
	}

	if (ipset->family != FW3_FAMILY_ANY)
		fw3_pr(" family inet%s", (ipset->family == FW3_FAMILY_V4) ? "" : "6");

	if (ipset->timeout > 0)
		fw3_pr(" timeout %u", ipset->timeout);

	if (ipset->maxelem > 0)
		fw3_pr(" maxelem %u", ipset->maxelem);

	if (ipset->netmask > 0)
		fw3_pr(" netmask %u", ipset->netmask);

	if (ipset->hashsize > 0)
		fw3_pr(" hashsize %u", ipset->hashsize);

	fw3_pr("\n");
}

void
fw3_create_ipsets(struct fw3_state *state)
{
	struct fw3_ipset *ipset;

	if (state->disable_ipsets)
		return;

	list_for_each_entry(ipset, &state->ipsets, list)
		if (!hasbit(ipset->flags[0], FW3_FLAG_DELETED))
			if (!fw3_lookup_ipset(state, ipset->name, true))
				create_ipset(ipset, state);

	fw3_pr("quit\n");
}

void
fw3_destroy_ipsets(struct fw3_state *state, enum fw3_family family)
{
	struct fw3_ipset *s, *tmp;

	list_for_each_entry_safe(s, tmp, &state->ipsets, list)
	{
		del(s->flags, family, family);

		if (fw3_no_family(s->flags[family == FW3_FAMILY_V6]))
		{
			info(" * Deleting ipset %s", s->name);

			fw3_pr("flush %s\n", s->name);
			fw3_pr("destroy %s\n", s->name);
		}
	}
}

struct fw3_ipset *
fw3_lookup_ipset(struct fw3_state *state, const char *name, bool running)
{
	struct fw3_ipset *s;

	if (list_empty(&state->ipsets))
		return NULL;

	list_for_each_entry(s, &state->ipsets, list)
	{
		if (strcmp(s->name, name))
			continue;

		return s;
	}

	return NULL;
}
