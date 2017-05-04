/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2014 Jo-Philipp Wich <jo@mein.io>
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

#include "snats.h"


const struct fw3_option fw3_snat_opts[] = {
	FW3_OPT("enabled",             bool,      snat,     enabled),

	FW3_OPT("name",                string,    snat,     name),
	FW3_OPT("family",              family,    snat,     family),

	FW3_OPT("src",                 device,    snat,     src),
	FW3_OPT("device",              string,    snat,     device),

	FW3_OPT("ipset",               setmatch,  snat,     ipset),

	FW3_LIST("proto",              protocol,  snat,     proto),

	FW3_OPT("src_ip",              network,   snat,     ip_src),
	FW3_OPT("src_port",            port,      snat,     port_src),

	FW3_OPT("snat_ip",             network,   snat,     ip_snat),
	FW3_OPT("snat_port",           port,      snat,     port_snat),

	FW3_OPT("dest_ip",             network,   snat,     ip_dest),
	FW3_OPT("dest_port",           port,      snat,     port_dest),

	FW3_OPT("extra",               string,    snat,     extra),

	FW3_OPT("limit",               limit,     snat,     limit),
	FW3_OPT("limit_burst",         int,       snat,     limit.burst),

	FW3_OPT("connlimit_ports",     bool,      snat,     connlimit_ports),

	FW3_OPT("utc_time",            bool,      snat,     time.utc),
	FW3_OPT("start_date",          date,      snat,     time.datestart),
	FW3_OPT("stop_date",           date,      snat,     time.datestop),
	FW3_OPT("start_time",          time,      snat,     time.timestart),
	FW3_OPT("stop_time",           time,      snat,     time.timestop),
	FW3_OPT("weekdays",            weekdays,  snat,     time.weekdays),
	FW3_OPT("monthdays",           monthdays, snat,     time.monthdays),

	FW3_OPT("mark",                mark,      snat,     mark),

	FW3_OPT("target",              target,    snat,     target),

	{ }
};


static bool
check_families(struct uci_element *e, struct fw3_snat *r)
{
	if (r->family == FW3_FAMILY_ANY)
		return true;

	if (r->_src && r->_src->family && r->_src->family != r->family)
	{
		warn_section("nat", r, e, "refers to source zone with different family");
		return false;
	}

	if (r->ipset.ptr && r->ipset.ptr->family &&
	    r->ipset.ptr->family != r->family)
	{
		warn_section("nat", r, e, "refers to ipset with different family");
		return false;
	}

	if (r->ip_src.family && r->ip_src.family != r->family)
	{
		warn_section("nat", r, e, "uses source ip with different family");
		return false;
	}

	if (r->ip_dest.family && r->ip_dest.family != r->family)
	{
		warn_section("nat", r, e, "uses destination ip with different family");
		return false;
	}

	if (r->ip_snat.family && r->ip_snat.family != r->family)
	{
		warn_section("nat", r, e, "uses snat ip with different family");
		return false;
	}

	return true;
}


static struct fw3_snat*
alloc_snat(struct fw3_state *state)
{
	struct fw3_snat *snat = calloc(1, sizeof(*snat));

	if (snat) {
		INIT_LIST_HEAD(&snat->proto);
		list_add_tail(&snat->list, &state->snats);
		snat->enabled = true;
	}

	return snat;
}

static bool
check_snat(struct fw3_state *state, struct fw3_snat *snat, struct uci_element *e)
{
	if (!snat->enabled)
		return false;

	if (snat->src.invert)
	{
		warn_section("nat", snat, e, "must not have an inverted source");
		return false;
	}
	else if (snat->src.set && !snat->src.any &&
			!(snat->_src = fw3_lookup_zone(state, snat->src.name)))
	{
		warn_section("nat", snat, e, "refers to not existing zone '%s'", snat->src.name);
		return false;
	}
	else if (snat->ipset.set && state->disable_ipsets)
	{
		warn_section("nat", snat, e, "skipped due to disabled ipset support");
		return false;
	}
	else if (snat->ipset.set &&
			!(snat->ipset.ptr = fw3_lookup_ipset(state, snat->ipset.name)))
	{
		warn_section("nat", snat, e, "refers to unknown ipset '%s'", snat->ipset.name);
		return false;
	}

	if (!check_families(e, snat))
		return false;

	if (snat->target == FW3_FLAG_UNSPEC)
	{
		warn_section("nat", snat, e, "has no target specified, defaulting to MASQUERADE");
		snat->target = FW3_FLAG_MASQUERADE;
	}
	else if (snat->target != FW3_FLAG_ACCEPT && snat->target != FW3_FLAG_SNAT &&
			snat->target != FW3_FLAG_MASQUERADE)
	{
		warn_section("nat", snat, e, "has invalid target specified, defaulting to MASQUERADE");
		snat->target = FW3_FLAG_MASQUERADE;
	}

	if (snat->target == FW3_FLAG_SNAT &&
			!snat->ip_snat.set && !snat->port_snat.set)
	{
		warn_section("nat", snat, e, "needs either 'snat_ip' or 'snat_port' for SNAT");
		return false;
	}
	else if (snat->target != FW3_FLAG_SNAT && snat->ip_snat.set)
	{
		warn_section("nat", snat, e, "must not use 'snat_ip' for non-SNAT");
		return false;
	}
	else if (snat->target != FW3_FLAG_SNAT && snat->port_snat.set)
	{
		warn_section("nat", snat, e, "must not use 'snat_port' for non-SNAT");
		return false;
	}

	if (list_empty(&snat->proto))
	{
		warn_section("nat", snat, e, "does not specify a protocol, assuming all");
		fw3_parse_protocol(&snat->proto, "all", true);
	}

	if (snat->_src)
		set(snat->_src->flags, FW3_FAMILY_V4, FW3_FLAG_SNAT);

	return true;
}


void
fw3_load_snats(struct fw3_state *state, struct uci_package *p, struct blob_attr *a)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_snat *snat;
	struct blob_attr *entry;
	unsigned rem;

	INIT_LIST_HEAD(&state->snats);

	blob_for_each_attr(entry, a, rem) {
		const char *type = NULL;
		const char *name = "ubus rule";

		if (!fw3_attr_parse_name_type(entry, &name, &type))
			continue;

		if (strcmp(type, "nat"))
			continue;

		snat = alloc_snat(state);
		if (!snat)
			continue;

		if (!fw3_parse_blob_options(snat, fw3_snat_opts, entry, name))
		{
			warn_section("nat", snat, NULL, "skipped due to invalid options");
			fw3_free_snat(snat);
			continue;
		}

		if (!check_snat(state, snat, NULL))
			fw3_free_snat(snat);
	}

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "nat"))
			continue;

		snat = alloc_snat(state);
		if (!snat)
			continue;

		if (!fw3_parse_options(snat, fw3_snat_opts, s))
		{
			warn_elem(e, "skipped due to invalid options");
			fw3_free_snat(snat);
			continue;
		}

		if (!check_snat(state, snat, e))
			fw3_free_snat(snat);
	}
}

static void
append_chain(struct fw3_ipt_rule *r, struct fw3_snat *snat)
{
	if (snat->_src)
		fw3_ipt_rule_append(r, "zone_%s_postrouting", snat->src.name);
	else
		fw3_ipt_rule_append(r, "POSTROUTING");
}

static void
set_target(struct fw3_ipt_rule *r, struct fw3_snat *snat,
           struct fw3_protocol *proto)
{
	char buf[sizeof("255.255.255.255:65535-65535\0")];

	if (snat->target == FW3_FLAG_SNAT)
	{
		buf[0] = '\0';

		if (snat->ip_snat.set)
		{
			inet_ntop(AF_INET, &snat->ip_snat.address.v4, buf, sizeof(buf));
		}

		if (snat->port_snat.set && proto && !proto->any &&
		    (proto->protocol == 6 || proto->protocol == 17 || proto->protocol == 1))
		{
			if (snat->port_snat.port_min == snat->port_snat.port_max)
				sprintf(buf + strlen(buf), ":%u", snat->port_snat.port_min);
			else
				sprintf(buf + strlen(buf), ":%u-%u",
						snat->port_snat.port_min, snat->port_snat.port_max);

			if (snat->connlimit_ports) {
				char portcntbuf[6];
				snprintf(portcntbuf, sizeof(portcntbuf), "%u",
						1 + snat->port_snat.port_max - snat->port_snat.port_min);

				fw3_ipt_rule_addarg(r, false, "-m", "connlimit");
				fw3_ipt_rule_addarg(r, false, "--connlimit-daddr", NULL);
				fw3_ipt_rule_addarg(r, false, "--connlimit-upto", portcntbuf);
			}
		}

		fw3_ipt_rule_target(r, "SNAT");
		fw3_ipt_rule_addarg(r, false, "--to-source", buf);
	}
	else if (snat->target == FW3_FLAG_ACCEPT)
	{
		fw3_ipt_rule_target(r, "ACCEPT");
	}
	else
	{
		fw3_ipt_rule_target(r, "MASQUERADE");
	}
}

static void
set_comment(struct fw3_ipt_rule *r, const char *name, int num)
{
	if (name)
		fw3_ipt_rule_comment(r, name);
	else
		fw3_ipt_rule_comment(r, "@nat[%u]", num);
}

static void
print_snat(struct fw3_ipt_handle *h, struct fw3_state *state,
           struct fw3_snat *snat, int num, struct fw3_protocol *proto)
{
	struct fw3_ipt_rule *r;
	struct fw3_address *src, *dst;
	struct fw3_port *spt, *dpt;

	switch (h->table)
	{
	case FW3_TABLE_NAT:
		src = &snat->ip_src;
		dst = &snat->ip_dest;
		spt = &snat->port_src;
		dpt = &snat->port_dest;

		r = fw3_ipt_rule_create(h, proto, NULL, NULL, src, dst);
		fw3_ipt_rule_sport_dport(r, spt, dpt);
		fw3_ipt_rule_device(r, snat->device, true);
		fw3_ipt_rule_ipset(r, &snat->ipset);
		fw3_ipt_rule_limit(r, &snat->limit);
		fw3_ipt_rule_time(r, &snat->time);
		fw3_ipt_rule_mark(r, &snat->mark);
		set_target(r, snat, proto);
		fw3_ipt_rule_extra(r, snat->extra);
		set_comment(r, snat->name, num);
		append_chain(r, snat);
		break;

	default:
		break;
	}
}

static void
expand_snat(struct fw3_ipt_handle *handle, struct fw3_state *state,
                struct fw3_snat *snat, int num)
{
	struct fw3_protocol *proto;

	if (snat->name)
		info("   * NAT '%s'", snat->name);
	else
		info("   * NAT #%u", num);

	if (!fw3_is_family(snat->_src, handle->family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	if (!fw3_is_family(&snat->ip_src, handle->family) ||
	    !fw3_is_family(&snat->ip_dest, handle->family) ||
		!fw3_is_family(&snat->ip_snat, handle->family))
	{
		if (!snat->ip_src.resolved ||
		    !snat->ip_dest.resolved ||
		    !snat->ip_snat.resolved)
			info("     ! Skipping due to different family of ip address");

		return;
	}

	if (snat->ipset.ptr)
	{
		if (!fw3_is_family(snat->ipset.ptr, handle->family))
		{
			info("     ! Skipping due to different family in ipset");
			return;
		}

		if (!fw3_check_ipset(snat->ipset.ptr))
		{
			info("     ! Skipping due to missing ipset '%s'",
			     snat->ipset.ptr->external ?
					snat->ipset.ptr->external : snat->ipset.ptr->name);
			return;
		}

		set(snat->ipset.ptr->flags, handle->family, handle->family);
	}

	fw3_foreach(proto, &snat->proto)
		print_snat(handle, state, snat, num, proto);
}

void
fw3_print_snats(struct fw3_ipt_handle *handle, struct fw3_state *state)
{
	int num = 0;
	struct fw3_snat *snat;

	if (handle->family == FW3_FAMILY_V6)
		return;

	if (handle->table != FW3_TABLE_NAT)
		return;

	list_for_each_entry(snat, &state->snats, list)
		expand_snat(handle, state, snat, num++);
}
