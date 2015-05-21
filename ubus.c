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

#include "ubus.h"

static struct blob_attr *interfaces = NULL;
static struct blob_attr *procd_data;


static void dump_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy = { "interface", BLOBMSG_TYPE_ARRAY };
	struct blob_attr *cur;

	blobmsg_parse(&policy, 1, &cur, blob_data(msg), blob_len(msg));
	if (cur)
		interfaces = blob_memdup(cur);
}

static void procd_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	procd_data = blob_memdup(msg);
}

bool
fw3_ubus_connect(void)
{
	bool status = false;
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx)
		goto out;

	if (ubus_lookup_id(ctx, "network.interface", &id))
		goto out;

	if (ubus_invoke(ctx, id, "dump", NULL, dump_cb, NULL, 500))
		goto out;

	status = true;

	if (ubus_lookup_id(ctx, "service", &id))
		goto out;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "type", "firewall");
	ubus_invoke(ctx, id, "get_data", b.head, procd_data_cb, NULL, 2000);
	blob_buf_free(&b);

out:
	if (ctx)
		ubus_free(ctx);
	return status;
}

void
fw3_ubus_disconnect(void)
{
	free(interfaces);
	interfaces = NULL;
}

static struct fw3_address *
parse_subnet(enum fw3_family family, struct blob_attr *dict, int rem)
{
	struct blob_attr *cur;
	struct fw3_address *addr;

	addr = calloc(1, sizeof(*addr));
	if (!addr)
		return NULL;

	addr->set = true;
	addr->family = family;

	__blob_for_each_attr(cur, dict, rem)
	{
		if (!strcmp(blobmsg_name(cur), "address"))
			inet_pton(family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          blobmsg_get_string(cur), &addr->address.v6);

		else if (!strcmp(blobmsg_name(cur), "mask"))
			fw3_bitlen2netmask(family, blobmsg_get_u32(cur), &addr->mask.v6);
	}

	return addr;
}

static void
parse_subnets(struct list_head *head, enum fw3_family family,
              struct blob_attr *list)
{
	struct blob_attr *cur;
	struct fw3_address *addr;
	int rem;

	if (!list)
		return;

	rem = blobmsg_data_len(list);

	__blob_for_each_attr(cur, blobmsg_data(list), rem)
	{
		addr = parse_subnet(family, blobmsg_data(cur), blobmsg_data_len(cur));

		if (addr)
			list_add_tail(&addr->list, head);
	}
}

struct fw3_device *
fw3_ubus_device(const char *net)
{
	enum {
		DEV_INTERFACE,
		DEV_DEVICE,
		DEV_L3_DEVICE,
		__DEV_MAX
	};
	static const struct blobmsg_policy policy[__DEV_MAX] = {
		[DEV_INTERFACE] = { "interface", BLOBMSG_TYPE_STRING },
		[DEV_DEVICE] = { "device", BLOBMSG_TYPE_STRING },
		[DEV_L3_DEVICE] = { "l3_device", BLOBMSG_TYPE_STRING },
	};
	struct fw3_device *dev = NULL;
	struct blob_attr *tb[__DEV_MAX];
	struct blob_attr *cur;
	char *name = NULL;
	int rem;

	if (!net || !interfaces)
		return NULL;

	blobmsg_for_each_attr(cur, interfaces, rem) {
		blobmsg_parse(policy, __DEV_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[DEV_INTERFACE] ||
		    strcmp(blobmsg_data(tb[DEV_INTERFACE]), net) != 0)
			continue;

		if (tb[DEV_L3_DEVICE])
			name = blobmsg_data(tb[DEV_L3_DEVICE]);
		else if (tb[DEV_DEVICE])
			name = blobmsg_data(tb[DEV_DEVICE]);
		else
			continue;

		break;
	}

	if (!name)
		return NULL;

	dev = calloc(1, sizeof(*dev));

	if (!dev)
		return NULL;

	snprintf(dev->name, sizeof(dev->name), "%s", name);
	dev->set = true;

	return dev;
}

void
fw3_ubus_address(struct list_head *list, const char *net)
{
	enum {
		ADDR_INTERFACE,
		ADDR_IPV4,
		ADDR_IPV6,
		ADDR_IPV6_PREFIX,
		__ADDR_MAX
	};
	static const struct blobmsg_policy policy[__ADDR_MAX] = {
		[ADDR_INTERFACE] = { "interface", BLOBMSG_TYPE_STRING },
		[ADDR_IPV4] = { "ipv4-address", BLOBMSG_TYPE_ARRAY },
		[ADDR_IPV6] = { "ipv6-address", BLOBMSG_TYPE_ARRAY },
		[ADDR_IPV6_PREFIX] = { "ipv6-prefix-assignment", BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[__ADDR_MAX];
	struct blob_attr *cur;
	int rem;

	if (!net || !interfaces)
		return;

	blobmsg_for_each_attr(cur, interfaces, rem) {
		blobmsg_parse(policy, __ADDR_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[ADDR_INTERFACE] ||
		    strcmp(blobmsg_data(tb[ADDR_INTERFACE]), net) != 0)
			continue;

		parse_subnets(list, FW3_FAMILY_V4, tb[ADDR_IPV4]);
		parse_subnets(list, FW3_FAMILY_V6, tb[ADDR_IPV6]);
		parse_subnets(list, FW3_FAMILY_V6, tb[ADDR_IPV6_PREFIX]);
	}
}

void
fw3_ubus_zone_devices(struct fw3_zone *zone)
{
	struct blob_attr *c, *cur, *dcur;
	unsigned r, rem, drem;
	const char *name;
	bool matches;

	blobmsg_for_each_attr(c, interfaces, r) {
		name = NULL;
		matches = false;

		blobmsg_for_each_attr(cur, c, rem) {
			if (!strcmp(blobmsg_name(cur), "interface"))
				name = blobmsg_get_string(cur);
			else if (!strcmp(blobmsg_name(cur), "data"))
				blobmsg_for_each_attr(dcur, cur, drem)
					if (!strcmp(blobmsg_name(dcur), "zone"))
						matches = !strcmp(blobmsg_get_string(dcur), zone->name);
		}

		if (name && matches)
			fw3_parse_device(&zone->networks, name, true);
	}
}

void
fw3_ubus_rules(struct blob_buf *b)
{
	blob_buf_init(b, 0);

	struct blob_attr *c, *cur, *dcur, *rule, *ropt;
	unsigned n, r, rem, drem, rrem, orem;
	char comment[256];

	blobmsg_for_each_attr(c, interfaces, r) {
		const char *l3_device = NULL;
		const char *iface_proto = "unknown";
		const char *iface_name = "unknown";
		struct blob_attr *data = NULL;

		blobmsg_for_each_attr(cur, c, rem) {
			if (!strcmp(blobmsg_name(cur), "l3_device"))
				l3_device = blobmsg_get_string(cur);
			else if (!strcmp(blobmsg_name(cur), "interface"))
				iface_proto = blobmsg_get_string(cur);
			else if (!strcmp(blobmsg_name(cur), "proto"))
				iface_name = blobmsg_get_string(cur);
			else if (!strcmp(blobmsg_name(cur), "data"))
				data = cur;
		}

		if (!data || !l3_device)
			continue;

		blobmsg_for_each_attr(dcur, data, drem) {
			if (strcmp(blobmsg_name(dcur), "firewall"))
				continue;

			n = 0;

			blobmsg_for_each_attr(rule, dcur, rrem) {
				void *k = blobmsg_open_table(b, "");

				snprintf(comment, sizeof(comment), "ubus:%s[%s] rule %d",
				         iface_name, iface_proto, n++);

				blobmsg_for_each_attr(ropt, rule, orem) {
					if (!strcmp(blobmsg_name(ropt), "device"))
						l3_device = blobmsg_get_string(ropt);
					else if (strcmp(blobmsg_name(ropt), "name"))
						blobmsg_add_blob(b, ropt);
				}

				blobmsg_add_string(b, "name", comment);
				blobmsg_add_string(b, "device", l3_device);
				blobmsg_close_table(b, k);
			}
		}
	}

	if (!procd_data)
		return;

	/* service */
	blobmsg_for_each_attr(c, procd_data, r) {
		if (!blobmsg_check_attr(c, true))
			continue;

		/* instance */
		blobmsg_for_each_attr(cur, c, rem) {
			if (!blobmsg_check_attr(cur, true))
				continue;

			/* type */
			blobmsg_for_each_attr(dcur, cur, drem) {
				if (!blobmsg_check_attr(dcur, true))
					continue;

				n = 0;

				blobmsg_for_each_attr(rule, dcur, rrem) {
					void *k = blobmsg_open_table(b, "");

					snprintf(comment, sizeof(comment), "ubus:%s[%s] rule %d",
					         blobmsg_name(c), blobmsg_name(cur), n++);

					blobmsg_for_each_attr(ropt, rule, orem)
						if (strcmp(blobmsg_name(ropt), "name"))
							blobmsg_add_blob(b, ropt);

					blobmsg_add_string(b, "name", comment);
					blobmsg_close_table(b, k);
				}
			}
		}
	}
}
