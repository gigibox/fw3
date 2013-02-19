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


static struct fw3_option ipset_opts[] = {
	FW3_OPT("name",          string,         ipset,     name),
	FW3_OPT("family",        family,         ipset,     family),

	FW3_OPT("storage",       ipset_method,   ipset,     method),
	FW3_LIST("match",        ipset_datatype, ipset,     datatypes),

	FW3_LIST("iprange",      address,        ipset,     iprange),
	FW3_OPT("portrange",     port,           ipset,     portrange),

	FW3_OPT("netmask",       int,            ipset,     netmask),
	FW3_OPT("maxelem",       int,            ipset,     maxelem),
	FW3_OPT("hashsize",      int,            ipset,     hashsize),
	FW3_OPT("timeout",       int,            ipset,     timeout),

	FW3_OPT("external",      string,         ipset,     external),
};

#define T(m, t1, t2, t3, r, o) \
	{ FW3_IPSET_METHOD_##m, \
	  FW3_IPSET_TYPE_##t1 | (FW3_IPSET_TYPE_##t2 << 8) | (FW3_IPSET_TYPE_##t3 << 16), \
	  r, o }

static struct fw3_ipset_settype ipset_types[] = {
	T(BITMAP, IP,   UNSPEC, UNSPEC, FW3_IPSET_OPT_IPRANGE,
	  FW3_IPSET_OPT_NETMASK),
	T(BITMAP, IP,   MAC,    UNSPEC, FW3_IPSET_OPT_IPRANGE, 0),
	T(BITMAP, PORT, UNSPEC, UNSPEC, FW3_IPSET_OPT_PORTRANGE, 0),

	T(HASH,   IP,   UNSPEC, UNSPEC, 0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM |
	  FW3_IPSET_OPT_NETMASK),
	T(HASH,   NET,  UNSPEC, UNSPEC, 0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM),
	T(HASH,   IP,   PORT,   UNSPEC, 0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM),
	T(HASH,   NET,  PORT,   UNSPEC, 0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM),
	T(HASH,   IP,   PORT,   IP,     0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM),
	T(HASH,   IP,   PORT,   NET,    0,
	  FW3_IPSET_OPT_FAMILY | FW3_IPSET_OPT_HASHSIZE | FW3_IPSET_OPT_MAXELEM),

	T(LIST,   SET,  UNSPEC, UNSPEC, 0, FW3_IPSET_OPT_MAXELEM),
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
				if ((ipset_types[i].required & FW3_IPSET_OPT_IPRANGE) &&
					list_empty(&ipset->iprange))
				{
					warn_elem(e, "requires an ip range");
					return false;
				}

				if ((ipset_types[i].required & FW3_IPSET_OPT_PORTRANGE) &&
				    !ipset->portrange.set)
				{
					warn_elem(e, "requires a port range");
					return false;
				}

				if (!(ipset_types[i].required & FW3_IPSET_OPT_IPRANGE) &&
				    !list_empty(&ipset->iprange))
				{
					warn_elem(e, "iprange ignored");
					fw3_free_list(&ipset->iprange);
				}

				if (!(ipset_types[i].required & FW3_IPSET_OPT_PORTRANGE) &&
				    ipset->portrange.set)
				{
					warn_elem(e, "portrange ignored");
					memset(&ipset->portrange, 0, sizeof(ipset->portrange));
				}

				if (!(ipset_types[i].optional & FW3_IPSET_OPT_NETMASK) &&
				    ipset->netmask > 0)
				{
					warn_elem(e, "netmask ignored");
					ipset->netmask = 0;
				}

				if (!(ipset_types[i].optional & FW3_IPSET_OPT_HASHSIZE) &&
				    ipset->hashsize > 0)
				{
					warn_elem(e, "hashsize ignored");
					ipset->hashsize = 0;
				}

				if (!(ipset_types[i].optional & FW3_IPSET_OPT_MAXELEM) &&
				    ipset->maxelem > 0)
				{
					warn_elem(e, "maxelem ignored");
					ipset->maxelem = 0;
				}

				if (!(ipset_types[i].optional & FW3_IPSET_OPT_FAMILY) &&
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

		ipset = malloc(sizeof(*ipset));

		if (!ipset)
			continue;

		memset(ipset, 0, sizeof(*ipset));

		INIT_LIST_HEAD(&ipset->datatypes);
		INIT_LIST_HEAD(&ipset->iprange);

		fw3_parse_options(ipset, ipset_opts, ARRAY_SIZE(ipset_opts), s);

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
create_ipset(struct fw3_ipset *ipset)
{
	bool first = true;
	char s[INET6_ADDRSTRLEN];

	struct fw3_ipset_datatype *type;
	struct fw3_address *a1, *a2;

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

	info("Creating ipset %s", ipset->name);

	first = true;
	fw3_pr("create %s %s", ipset->name, methods[ipset->method]);

	list_for_each_entry(type, &ipset->datatypes, list)
	{
		fw3_pr("%c%s", first ? ':' : ',', types[type->type]);
		first = false;
	}

	if (!list_empty(&ipset->iprange))
	{
		a1 = list_first_entry(&ipset->iprange, struct fw3_address, list);
		a2 = list_last_entry(&ipset->iprange, struct fw3_address, list);

		if (a1 == a2)
		{
			inet_ntop(a1->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a1->address.v6, s, sizeof(s));

			fw3_pr(" range %s/%u", s, a1->mask);
		}
		else if (a1->family == a2->family &&
		         fw3_is_family(ipset, a1->family) &&
		         fw3_is_family(ipset, a2->family))
		{
			inet_ntop(a1->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a1->address.v6, s, sizeof(s));

			fw3_pr(" range %s", s);

			inet_ntop(a2->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          &a2->address.v6, s, sizeof(s));

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

static bool
ipset_loaded(struct list_head *statefile, const char *name)
{
	struct fw3_statefile_entry *e;
	int mask = (1 << FW3_FAMILY_V4) | (1 << FW3_FAMILY_V6);

	if (!statefile)
		return false;

	list_for_each_entry(e, statefile, list)
	{
		if (e->type != FW3_TYPE_IPSET)
			continue;

		if (!strcmp(e->name, name) && (e->flags[0] & mask))
			return true;
	}

	return false;
}

void
fw3_create_ipsets(struct fw3_state *state, struct list_head *statefile)
{
	struct fw3_ipset *ipset;

	if (state->disable_ipsets)
		return;

	list_for_each_entry(ipset, &state->ipsets, list)
		if (!ipset_loaded(statefile, ipset->name))
			create_ipset(ipset);

	fw3_pr("quit\n");
}

void
fw3_destroy_ipsets(struct fw3_state *state, struct list_head *statefile)
{
	struct fw3_ipset *s;
	struct fw3_statefile_entry *e;
	int mask = (1 << FW3_FAMILY_V4) | (1 << FW3_FAMILY_V6);

	if (!statefile)
		return;

	list_for_each_entry(e, statefile, list)
	{
		if (e->type != FW3_TYPE_IPSET)
			continue;

		if (!hasbit(state->defaults.flags, FW3_FAMILY_V4))
			delbit(e->flags[0], FW3_FAMILY_V4);

		if (!hasbit(state->defaults.flags, FW3_FAMILY_V6))
			delbit(e->flags[0], FW3_FAMILY_V6);

		if ((s = fw3_lookup_ipset(state, e->name)) != NULL)
			s->flags = e->flags[0];

		if (!(e->flags[0] & mask))
		{
			info("Deleting ipset %s", e->name);

			fw3_pr("flush %s\n", e->name);
			fw3_pr("destroy %s\n", e->name);
		}
	}
}

void
fw3_free_ipset(struct fw3_ipset *ipset)
{
	fw3_free_list(&ipset->datatypes);
	fw3_free_list(&ipset->iprange);

	free(ipset);
}

struct fw3_ipset *
fw3_lookup_ipset(struct fw3_state *state, const char *name)
{
	struct fw3_ipset *ipset;

	if (list_empty(&state->ipsets))
		return NULL;

	list_for_each_entry(ipset, &state->ipsets, list)
		if (!strcmp(ipset->name, name))
			return ipset;

	return NULL;
}
