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


static struct ubus_context *ctx = NULL;

bool
fw3_ubus_connect(void)
{
	ctx = ubus_connect(NULL);
	return !!ctx;
}

void
fw3_ubus_disconnect(void)
{
	if (!ctx)
		return;

	ubus_free(ctx);
	ctx = NULL;
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

struct dev_addr
{
	struct fw3_device *dev;
	struct list_head *addr;
};

static void
invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	int rem;
	char *data;
	struct blob_attr *cur;
	struct dev_addr *da = (struct dev_addr *)req->priv;
	struct fw3_device *dev = da->dev;

	if (!msg)
		return;

	rem = blob_len(msg);
	__blob_for_each_attr(cur, blob_data(msg), rem)
	{
		data = blobmsg_data(cur);

		if (dev && !strcmp(blobmsg_name(cur), "device") && !dev->name[0])
			snprintf(dev->name, sizeof(dev->name), "%s", data);
		else if (dev && !strcmp(blobmsg_name(cur), "l3_device"))
			snprintf(dev->name, sizeof(dev->name), "%s", data);
		else if (!dev && !strcmp(blobmsg_name(cur), "ipv4-address"))
			parse_subnets(da->addr, FW3_FAMILY_V4,
			              blobmsg_data(cur), blobmsg_data_len(cur));
		else if (!dev && (!strcmp(blobmsg_name(cur), "ipv6-address") ||
		                  !strcmp(blobmsg_name(cur), "ipv6-prefix-assignment")))
			parse_subnets(da->addr, FW3_FAMILY_V6,
			              blobmsg_data(cur), blobmsg_data_len(cur));
	}

	if (dev)
		dev->set = !!dev->name[0];
}

static void *
invoke_common(const char *net, bool dev)
{
	uint32_t id;
	char path[128];
	static struct dev_addr da;

	if (!net)
		return NULL;

	memset(&da, 0, sizeof(da));

	if (dev)
		da.dev = malloc(sizeof(*da.dev));
	else
		da.addr = malloc(sizeof(*da.addr));

	if ((dev && !da.dev) || (!dev && !da.addr))
		goto fail;

	if (dev)
		memset(da.dev, 0, sizeof(*da.dev));
	else
		INIT_LIST_HEAD(da.addr);

	snprintf(path, sizeof(path), "network.interface.%s", net);

	if (ubus_lookup_id(ctx, path, &id))
		goto fail;

	if (ubus_invoke(ctx, id, "status", NULL, invoke_cb, &da, 500))
		goto fail;

	if (dev && da.dev->set)
		return da.dev;
	else if (!dev && !list_empty(da.addr))
		return da.addr;

fail:
	if (da.dev)
		free(da.dev);

	if (da.addr)
		free(da.addr);

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
