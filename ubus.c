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


static void dump_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	unsigned rem = blob_len(msg);
	__blob_for_each_attr(cur, blob_data(msg), rem)
		if (!strcmp(blobmsg_name(cur), "interface"))
			interfaces = blob_memdup(cur);
}

bool
fw3_ubus_connect(void)
{
	bool status = false;
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);

	if (!ctx)
		goto out;

	if (ubus_lookup_id(ctx, "network.interface", &id))
		goto out;

	if (ubus_invoke(ctx, id, "dump", NULL, dump_cb, NULL, 500))
		goto out;

	status = true;

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

	addr = malloc(sizeof(*addr));

	if (!addr)
		return NULL;

	memset(addr, 0, sizeof(*addr));

	addr->set = true;
	addr->family = family;

	__blob_for_each_attr(cur, dict, rem)
	{
		if (!strcmp(blobmsg_name(cur), "address"))
			inet_pton(family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
			          blobmsg_data(cur), &addr->address.v6);

		else if (!strcmp(blobmsg_name(cur), "mask"))
			addr->mask = be32_to_cpu(*(uint32_t *)blobmsg_data(cur));
	}

	return addr;
}

static void
parse_subnets(struct list_head *head, enum fw3_family family,
              struct blob_attr *list, int rem)
{
	struct blob_attr *cur;
	struct fw3_address *addr;

	__blob_for_each_attr(cur, list, rem)
	{
		addr = parse_subnet(family, blobmsg_data(cur), blobmsg_data_len(cur));

		if (addr)
			list_add_tail(&addr->list, head);
	}
}

static void *
invoke_common(const char *net, bool device)
{
	struct fw3_device *dev = NULL;
	struct list_head *addr = NULL;
	struct blob_attr *c, *cur;
	unsigned r, rem;
	char *data;
	bool matched;

	if (!net || !interfaces)
		return NULL;

	if (device)
		dev = malloc(sizeof(*dev));
	else
		addr = malloc(sizeof(*addr));

	if ((device && !dev) || (!device && !addr))
		goto fail;

	if (device)
		memset(dev, 0, sizeof(*dev));
	else
		INIT_LIST_HEAD(addr);

	blobmsg_for_each_attr(c, interfaces, r) {
		matched = false;
		blobmsg_for_each_attr(cur, c, rem)
			if (!strcmp(blobmsg_name(cur), "interface"))
				matched = !strcmp(blobmsg_get_string(cur), net);

		if (!matched)
			continue;

		blobmsg_for_each_attr(cur, c, rem) {
			data = blobmsg_data(cur);

			if (dev && !strcmp(blobmsg_name(cur), "device") && !dev->name[0])
				snprintf(dev->name, sizeof(dev->name), "%s", data);
			else if (dev && !strcmp(blobmsg_name(cur), "l3_device"))
				snprintf(dev->name, sizeof(dev->name), "%s", data);
			else if (!dev && !strcmp(blobmsg_name(cur), "ipv4-address"))
				parse_subnets(addr, FW3_FAMILY_V4,
					      blobmsg_data(cur), blobmsg_data_len(cur));
			else if (!dev && (!strcmp(blobmsg_name(cur), "ipv6-address") ||
					  !strcmp(blobmsg_name(cur), "ipv6-prefix-assignment")))
				parse_subnets(addr, FW3_FAMILY_V6,
					      blobmsg_data(cur), blobmsg_data_len(cur));
		}

		if (dev)
			dev->set = !!dev->name[0];

		break;
	}

	if (device && dev->set)
		return dev;
	else if (!device && !list_empty(addr))
		return addr;

fail:
	free(dev);
	free(addr);

	return NULL;
}

struct fw3_device *
fw3_ubus_device(const char *net)
{
	return invoke_common(net, true);
}

struct list_head *
fw3_ubus_address(const char *net)
{
	return invoke_common(net, false);
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
