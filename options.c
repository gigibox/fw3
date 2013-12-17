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

#include "options.h"
#include "ubus.h"


static bool
put_value(void *ptr, void *val, int elem_size, bool is_list)
{
	void *copy;

	if (is_list)
	{
		copy = malloc(elem_size);

		if (!copy)
			return false;

		memcpy(copy, val, elem_size);
		list_add_tail((struct list_head *)copy, (struct list_head *)ptr);
		return true;
	}

	memcpy(ptr, val, elem_size);
	return false;
}

static bool
parse_enum(void *ptr, const char *val, const char **values, int min, int max)
{
	int i, l = strlen(val);

	if (l > 0)
	{
		for (i = 0; i <= (max - min); i++)
		{
			if (!strncasecmp(val, values[i], l))
			{
				*((int *)ptr) = min + i;
				return true;
			}
		}
	}

	return false;
}


const char *fw3_flag_names[__FW3_FLAG_MAX] = {
	"filter",
	"nat",
	"mangle",
	"raw",

	"IPv4",
	"IPv6",

	"ACCEPT",
	"REJECT",
	"DROP",
	"NOTRACK",
	"MARK",
	"DNAT",
	"SNAT",

	"ACCEPT",
	"REJECT",
	"DROP",
};

const char *fw3_limit_units[__FW3_LIMIT_UNIT_MAX] = {
	"second",
	"minute",
	"hour",
	"day",
};

const char *fw3_ipset_method_names[__FW3_IPSET_METHOD_MAX] = {
	"(bug)",
	"bitmap",
	"hash",
	"list",
};

const char *fw3_ipset_type_names[__FW3_IPSET_TYPE_MAX] = {
	"(bug)",
	"ip",
	"port",
	"mac",
	"net",
	"set",
};

static const char *weekdays[] = {
	"monday",
	"tuesday",
	"wednesday",
	"thursday",
	"friday",
	"saturday",
	"sunday",
};

static const char *include_types[] = {
	"script",
	"restore",
};

static const char *reflection_sources[] = {
	"internal",
	"external",
};


bool
fw3_parse_bool(void *ptr, const char *val, bool is_list)
{
	if (!strcmp(val, "true") || !strcmp(val, "yes") || !strcmp(val, "1"))
		*((bool *)ptr) = true;
	else
		*((bool *)ptr) = false;

	return true;
}

bool
fw3_parse_int(void *ptr, const char *val, bool is_list)
{
	char *e;
	int n = strtol(val, &e, 0);

	if (e == val || *e)
		return false;

	*((int *)ptr) = n;

	return true;
}

bool
fw3_parse_string(void *ptr, const char *val, bool is_list)
{
	*((char **)ptr) = (char *)val;
	return true;
}

bool
fw3_parse_target(void *ptr, const char *val, bool is_list)
{
	return parse_enum(ptr, val, &fw3_flag_names[FW3_FLAG_ACCEPT],
	                  FW3_FLAG_ACCEPT, FW3_FLAG_SNAT);
}

bool
fw3_parse_limit(void *ptr, const char *val, bool is_list)
{
	struct fw3_limit *limit = ptr;
	enum fw3_limit_unit u = FW3_LIMIT_UNIT_SECOND;
	char *e;
	int n;

	if (*val == '!')
	{
		limit->invert = true;
		while (isspace(*++val));
	}

	n = strtol(val, &e, 10);

	if (errno == ERANGE || errno == EINVAL)
		return false;

	if (*e && *e++ != '/')
		return false;

	if (!strlen(e))
		return false;

	if (!parse_enum(&u, e, fw3_limit_units, 0, FW3_LIMIT_UNIT_DAY))
		return false;

	limit->rate = n;
	limit->unit = u;

	return true;
}

bool
fw3_parse_device(void *ptr, const char *val, bool is_list)
{
	char *p;
	struct fw3_device dev = { };

	if (*val == '*')
	{
		dev.set = true;
		dev.any = true;
		put_value(ptr, &dev, sizeof(dev), is_list);
		return true;
	}

	if (*val == '!')
	{
		dev.invert = true;
		while (isspace(*++val));
	}

	if ((p = strchr(val, '@')) != NULL)
	{
		*p++ = 0;
		snprintf(dev.network, sizeof(dev.network), "%s", p);
	}

	if (*val)
		snprintf(dev.name, sizeof(dev.name), "%s", val);
	else
		return false;

	dev.set = true;
	put_value(ptr, &dev, sizeof(dev), is_list);
	return true;
}

bool
fw3_parse_address(void *ptr, const char *val, bool is_list)
{
	struct fw3_address addr = { };
	struct in_addr v4;
	struct in6_addr v6;
	char *p, *s, *e;
	int i, m = -1;

	if (*val == '!')
	{
		addr.invert = true;
		while (isspace(*++val));
	}

	s = strdup(val);

	if (!s)
		return false;

	if ((p = strchr(s, '/')) != NULL)
	{
		*p++ = 0;
		m = strtoul(p, &e, 10);

		if ((e == p) || (*e != 0))
		{
			if (strchr(s, ':') || !inet_pton(AF_INET, p, &v4))
			{
				free(s);
				return false;
			}

			for (i = 0, m = 32; !(v4.s_addr & 1) && (i < 32); i++)
			{
				m--;
				v4.s_addr >>= 1;
			}
		}
	}
	else if ((p = strchr(s, '-')) != NULL)
	{
		*p++ = 0;

		if (inet_pton(AF_INET6, p, &v6))
		{
			addr.family = FW3_FAMILY_V6;
			addr.address2.v6 = v6;
			addr.range = true;
		}
		else if (inet_pton(AF_INET, p, &v4))
		{
			addr.family = FW3_FAMILY_V4;
			addr.address2.v4 = v4;
			addr.range = true;
		}
		else
		{
			free(s);
			return false;
		}
	}

	if (inet_pton(AF_INET6, s, &v6))
	{
		addr.family = FW3_FAMILY_V6;
		addr.address.v6 = v6;
		addr.mask = (m >= 0) ? m : 128;
	}
	else if (inet_pton(AF_INET, s, &v4))
	{
		addr.family = FW3_FAMILY_V4;
		addr.address.v4 = v4;
		addr.mask = (m >= 0) ? m : 32;
	}
	else
	{
		free(s);
		return false;
	}

	free(s);
	addr.set = true;
	put_value(ptr, &addr, sizeof(addr), is_list);
	return true;
}

bool
fw3_parse_network(void *ptr, const char *val, bool is_list)
{
	struct fw3_device dev = { };
	struct fw3_address *addr;
	struct list_head *addr_list;

	if (!fw3_parse_address(ptr, val, is_list))
	{
		if (!fw3_parse_device(&dev, val, false))
			return false;

		addr_list = fw3_ubus_address(dev.name);

		if (addr_list)
		{
			list_for_each_entry(addr, addr_list, list)
			{
				addr->invert = dev.invert;
				addr->resolved = true;

				if (!put_value(ptr, addr, sizeof(*addr), is_list))
					break;
			}

			fw3_free_list(addr_list);
		}
	}

	return true;
}

bool
fw3_parse_mac(void *ptr, const char *val, bool is_list)
{
	struct fw3_mac addr = { };
	struct ether_addr *mac;

	if (*val == '!')
	{
		addr.invert = true;
		while (isspace(*++val));
	}

	if ((mac = ether_aton(val)) != NULL)
	{
		addr.mac = *mac;
		addr.set = true;

		put_value(ptr, &addr, sizeof(addr), is_list);
		return true;
	}

	return false;
}

bool
fw3_parse_port(void *ptr, const char *val, bool is_list)
{
	struct fw3_port range = { };
	uint16_t n;
	uint16_t m;
	char *p;

	if (*val == '!')
	{
		range.invert = true;
		while (isspace(*++val));
	}

	n = strtoul(val, &p, 10);

	if (errno == ERANGE || errno == EINVAL)
		return false;

	if (*p && *p != '-' && *p != ':')
		return false;

	if (*p)
	{
		m = strtoul(++p, NULL, 10);

		if (errno == ERANGE || errno == EINVAL || m < n)
			return false;

		range.port_min = n;
		range.port_max = m;
	}
	else
	{
		range.port_min = n;
		range.port_max = n;
	}

	range.set = true;
	put_value(ptr, &range, sizeof(range), is_list);
	return true;
}

bool
fw3_parse_family(void *ptr, const char *val, bool is_list)
{
	if (!strcmp(val, "any"))
		*((enum fw3_family *)ptr) = FW3_FAMILY_ANY;
	else if (!strcmp(val, "inet") || strrchr(val, '4'))
		*((enum fw3_family *)ptr) = FW3_FAMILY_V4;
	else if (!strcmp(val, "inet6") || strrchr(val, '6'))
		*((enum fw3_family *)ptr) = FW3_FAMILY_V6;
	else
		return false;

	return true;
}

bool
fw3_parse_icmptype(void *ptr, const char *val, bool is_list)
{
	struct fw3_icmptype icmp = { };
	bool v4 = false;
	bool v6 = false;
	char *p;
	int i;

	for (i = 0; i < ARRAY_SIZE(fw3_icmptype_list_v4); i++)
	{
		if (!strcmp(val, fw3_icmptype_list_v4[i].name))
		{
			icmp.type     = fw3_icmptype_list_v4[i].type;
			icmp.code_min = fw3_icmptype_list_v4[i].code_min;
			icmp.code_max = fw3_icmptype_list_v4[i].code_max;

			v4 = true;
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(fw3_icmptype_list_v6); i++)
	{
		if (!strcmp(val, fw3_icmptype_list_v6[i].name))
		{
			icmp.type6     = fw3_icmptype_list_v6[i].type;
			icmp.code6_min = fw3_icmptype_list_v6[i].code_min;
			icmp.code6_max = fw3_icmptype_list_v6[i].code_max;

			v6 = true;
			break;
		}
	}

	if (!v4 && !v6)
	{
		i = strtoul(val, &p, 10);

		if ((p == val) || (*p != '/' && *p != 0) || (i > 0xFF))
			return false;

		icmp.type = i;

		if (*p == '/')
		{
			val = ++p;
			i = strtoul(val, &p, 10);

			if ((p == val) || (*p != 0) || (i > 0xFF))
				return false;

			icmp.code_min = i;
			icmp.code_max = i;
		}
		else
		{
			icmp.code_min = 0;
			icmp.code_max = 0xFF;
		}

		icmp.type6     = icmp.type;
		icmp.code6_min = icmp.code_max;
		icmp.code6_max = icmp.code_max;

		v4 = true;
		v6 = true;
	}

	icmp.family = (v4 && v6) ? FW3_FAMILY_ANY
	                         : (v6 ? FW3_FAMILY_V6 : FW3_FAMILY_V4);

	put_value(ptr, &icmp, sizeof(icmp), is_list);
	return true;
}

bool
fw3_parse_protocol(void *ptr, const char *val, bool is_list)
{
	struct fw3_protocol proto = { };
	struct protoent *ent;
	char *e;

	if (*val == '!')
	{
		proto.invert = true;
		while (isspace(*++val));
	}

	if (!strcmp(val, "all"))
	{
		proto.any = true;
		put_value(ptr, &proto, sizeof(proto), is_list);
		return true;
	}
	else if (!strcmp(val, "icmpv6"))
	{
		val = "ipv6-icmp";
	}
	else if (!strcmp(val, "tcpudp"))
	{
		proto.protocol = 6;
		if (put_value(ptr, &proto, sizeof(proto), is_list))
		{
			proto.protocol = 17;
			put_value(ptr, &proto, sizeof(proto), is_list);
		}

		return true;
	}

	ent = getprotobyname(val);

	if (ent)
	{
		proto.protocol = ent->p_proto;
		put_value(ptr, &proto, sizeof(proto), is_list);
		return true;
	}

	proto.protocol = strtoul(val, &e, 10);

	if ((e == val) || (*e != 0))
		return false;

	put_value(ptr, &proto, sizeof(proto), is_list);
	return true;
}

bool
fw3_parse_ipset_method(void *ptr, const char *val, bool is_list)
{
	return parse_enum(ptr, val, &fw3_ipset_method_names[FW3_IPSET_METHOD_BITMAP],
	                  FW3_IPSET_METHOD_BITMAP, FW3_IPSET_METHOD_LIST);
}

bool
fw3_parse_ipset_datatype(void *ptr, const char *val, bool is_list)
{
	struct fw3_ipset_datatype type = { };

	type.dir = "src";

	if (!strncmp(val, "dest_", 5))
	{
		val += 5;
		type.dir = "dst";
	}
	else if (!strncmp(val, "dst_", 4))
	{
		val += 4;
		type.dir = "dst";
	}
	else if (!strncmp(val, "src_", 4))
	{
		val += 4;
		type.dir = "src";
	}

	if (parse_enum(&type.type, val, &fw3_ipset_type_names[FW3_IPSET_TYPE_IP],
	               FW3_IPSET_TYPE_IP, FW3_IPSET_TYPE_SET))
	{
		put_value(ptr, &type, sizeof(type), is_list);
		return true;
	}

	return false;
}

bool
fw3_parse_date(void *ptr, const char *val, bool is_list)
{
	unsigned int year = 1970, mon = 1, day = 1, hour = 0, min = 0, sec = 0;
	struct tm tm = { 0 };
	char *p;

	year = strtoul(val, &p, 10);
	if ((*p != '-' && *p) || year < 1970 || year > 2038)
		goto fail;
	else if (!*p)
		goto ret;

	mon = strtoul(++p, &p, 10);
	if ((*p != '-' && *p) || mon > 12)
		goto fail;
	else if (!*p)
		goto ret;

	day = strtoul(++p, &p, 10);
	if ((*p != 'T' && *p) || day > 31)
		goto fail;
	else if (!*p)
		goto ret;

	hour = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || hour > 23)
		goto fail;
	else if (!*p)
		goto ret;

	min = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || min > 59)
		goto fail;
	else if (!*p)
		goto ret;

	sec = strtoul(++p, &p, 10);
	if (*p || sec > 59)
		goto fail;

ret:
	tm.tm_year = year - 1900;
	tm.tm_mon  = mon - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min  = min;
	tm.tm_sec  = sec;

	if (mktime(&tm) >= 0)
	{
		*((struct tm *)ptr) = tm;
		return true;
	}

fail:
	return false;
}

bool
fw3_parse_time(void *ptr, const char *val, bool is_list)
{
	unsigned int hour = 0, min = 0, sec = 0;
	char *p;

	hour = strtoul(val, &p, 10);
	if (*p != ':' || hour > 23)
		goto fail;

	min = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || min > 59)
		goto fail;
	else if (!*p)
		goto ret;

	sec = strtoul(++p, &p, 10);
	if (*p || sec > 59)
		goto fail;

ret:
	*((int *)ptr) = 60 * 60 * hour + 60 * min + sec;
	return true;

fail:
	return false;
}

bool
fw3_parse_weekdays(void *ptr, const char *val, bool is_list)
{
	unsigned int w = 0;
	char *p, *s;

	if (*val == '!')
	{
		setbit(*(uint8_t *)ptr, 0);
		while (isspace(*++val));
	}

	if (!(s = strdup(val)))
		return false;

	for (p = strtok(s, " \t"); p; p = strtok(NULL, " \t"))
	{
		if (!parse_enum(&w, p, weekdays, 1, 7))
		{
			w = strtoul(p, &p, 10);

			if (*p || w < 1 || w > 7)
			{
				free(s);
				return false;
			}
		}

		setbit(*(uint8_t *)ptr, w);
	}

	free(s);
	return true;
}

bool
fw3_parse_monthdays(void *ptr, const char *val, bool is_list)
{
	unsigned int d;
	char *p, *s;

	if (*val == '!')
	{
		setbit(*(uint32_t *)ptr, 0);
		while (isspace(*++val));
	}

	if (!(s = strdup(val)))
		return false;

	for (p = strtok(s, " \t"); p; p = strtok(NULL, " \t"))
	{
		d = strtoul(p, &p, 10);

		if (*p || d < 1 || d > 31)
		{
			free(s);
			return false;
		}

		setbit(*(uint32_t *)ptr, d);
	}

	free(s);
	return true;
}

bool
fw3_parse_include_type(void *ptr, const char *val, bool is_list)
{
	return parse_enum(ptr, val, include_types,
	                  FW3_INC_TYPE_SCRIPT, FW3_INC_TYPE_RESTORE);
}

bool
fw3_parse_reflection_source(void *ptr, const char *val, bool is_list)
{
	return parse_enum(ptr, val, reflection_sources,
	                  FW3_REFLECTION_INTERNAL, FW3_REFLECTION_EXTERNAL);
}

bool
fw3_parse_mark(void *ptr, const char *val, bool is_list)
{
	uint32_t n;
	char *s, *e;
	struct fw3_mark *m = ptr;

	if (*val == '!')
	{
		m->invert = true;
		while (isspace(*++val));
	}

	if ((s = strchr(val, '/')) != NULL)
		*s++ = 0;

	n = strtoul(val, &e, 0);

	if (e == val || *e)
		return false;

	m->mark = n;
	m->mask = 0xFFFFFFFF;

	if (s)
	{
		n = strtoul(s, &e, 0);

		if (e == s || *e)
			return false;

		m->mask = n;
	}

	m->set = true;
	return true;
}

bool
fw3_parse_setmatch(void *ptr, const char *val, bool is_list)
{
	struct fw3_setmatch *m = ptr;
	char *p, *s;
	int i;

	if (*val == '!')
	{
		m->invert = true;
		while (isspace(*++val));
	}

	if (!(s = strdup(val)))
		return false;

	if (!(p = strtok(s, " \t")))
	{
		free(s);
		return false;
	}

	strncpy(m->name, p, sizeof(m->name));

	for (i = 0, p = strtok(NULL, " \t,");
	     i < 3 && p != NULL;
	     i++, p = strtok(NULL, " \t,"))
	{
		if (!strncmp(p, "dest", 4) || !strncmp(p, "dst", 3))
			m->dir[i] = "dst";
		else if (!strncmp(p, "src", 3))
			m->dir[i] = "src";
	}

	free(s);

	m->set = true;
	return true;
}


bool
fw3_parse_options(void *s, const struct fw3_option *opts,
                  struct uci_section *section)
{
	char *p, *v;
	bool known;
	struct uci_element *e, *l;
	struct uci_option *o;
	const struct fw3_option *opt;
	struct list_head *dest;
	bool valid = true;

	uci_foreach_element(&section->options, e)
	{
		o = uci_to_option(e);
		known = false;

		for (opt = opts; opt->name; opt++)
		{
			if (!opt->parse)
				continue;

			if (strcmp(opt->name, e->name))
				continue;

			if (o->type == UCI_TYPE_LIST)
			{
				if (!opt->elem_size)
				{
					warn_elem(e, "must not be a list");
					valid = false;
				}
				else
				{
					dest = (struct list_head *)((char *)s + opt->offset);

					uci_foreach_element(&o->v.list, l)
					{
						if (!l->name)
							continue;

						if (!opt->parse(dest, l->name, true))
						{
							warn_elem(e, "has invalid value '%s'", l->name);
							valid = false;
							continue;
						}
					}
				}
			}
			else
			{
				v = o->v.string;

				if (!v)
					continue;

				if (!opt->elem_size)
				{
					if (!opt->parse((char *)s + opt->offset, o->v.string, false))
					{
						warn_elem(e, "has invalid value '%s'", o->v.string);
						valid = false;
					}
				}
				else
				{
					dest = (struct list_head *)((char *)s + opt->offset);

					for (p = strtok(v, " \t"); p != NULL; p = strtok(NULL, " \t"))
					{
						if (!opt->parse(dest, p, true))
						{
							warn_elem(e, "has invalid value '%s'", p);
							valid = false;
							continue;
						}
					}
				}
			}

			known = true;
			break;
		}

		if (!known)
			warn_elem(e, "is unknown");
	}

	return valid;
}


const char *
fw3_address_to_string(struct fw3_address *address, bool allow_invert)
{
	char *p, ip[INET6_ADDRSTRLEN];
	static char buf[INET6_ADDRSTRLEN * 2 + 2];

	p = buf;

	if (address->invert && allow_invert)
		p += sprintf(p, "!");

	inet_ntop(address->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
	          &address->address.v4, ip, sizeof(ip));

	p += sprintf(p, "%s", ip);

	if (address->range)
	{
		inet_ntop(address->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
		          &address->address2.v4, ip, sizeof(ip));

		p += sprintf(p, "-%s", ip);
	}
	else
	{
		p += sprintf(p, "/%u", address->mask);
	}

	return buf;
}
