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

#ifndef __FW3_OPTIONS_H
#define __FW3_OPTIONS_H


#include <errno.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include <ctype.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <uci.h>

#include <libubox/list.h>
#include <libubox/utils.h>

#include "icmp_codes.h"
#include "utils.h"


enum fw3_table
{
	FW3_TABLE_FILTER = 0,
	FW3_TABLE_NAT    = 1,
	FW3_TABLE_MANGLE = 2,
	FW3_TABLE_RAW    = 3,
};

enum fw3_family
{
	FW3_FAMILY_ANY = 0,
	FW3_FAMILY_V4  = 1,
	FW3_FAMILY_V6  = 2,
};

enum fw3_target
{
	FW3_TARGET_UNSPEC  = 0,
	FW3_TARGET_ACCEPT  = 1,
	FW3_TARGET_REJECT  = 2,
	FW3_TARGET_DROP    = 3,
	FW3_TARGET_NOTRACK = 4,
	FW3_TARGET_DNAT    = 5,
	FW3_TARGET_SNAT    = 6,
};

enum fw3_default
{
	FW3_DEFAULT_UNSPEC        = 0,
	FW3_DEFAULT_CUSTOM_CHAINS = 1,
	FW3_DEFAULT_SYN_FLOOD     = 2,
	FW3_DEFAULT_MTU_FIX       = 3,
	FW3_DEFAULT_DROP_INVALID  = 4,
	FW3_DEFAULT_IPV4_LOADED   = 5,
	FW3_DEFAULT_IPV6_LOADED   = 6,
};

enum fw3_limit_unit
{
	FW3_LIMIT_UNIT_SECOND = 0,
	FW3_LIMIT_UNIT_MINUTE = 1,
	FW3_LIMIT_UNIT_HOUR   = 2,
	FW3_LIMIT_UNIT_DAY    = 3,
};

enum fw3_ipset_method
{
	FW3_IPSET_METHOD_UNSPEC = 0,
	FW3_IPSET_METHOD_BITMAP = 1,
	FW3_IPSET_METHOD_HASH   = 2,
	FW3_IPSET_METHOD_LIST   = 3,
};

enum fw3_ipset_type
{
	FW3_IPSET_TYPE_UNSPEC = 0,
	FW3_IPSET_TYPE_IP     = 1,
	FW3_IPSET_TYPE_PORT   = 2,
	FW3_IPSET_TYPE_MAC    = 3,
	FW3_IPSET_TYPE_NET    = 4,
	FW3_IPSET_TYPE_SET    = 5,
};

struct fw3_ipset_datatype
{
	struct list_head list;
	enum fw3_ipset_type type;
	bool dest;
};

struct fw3_device
{
	struct list_head list;

	bool set;
	bool any;
	bool invert;
	char name[32];
};

struct fw3_address
{
	struct list_head list;

	bool set;
	bool invert;
	enum fw3_family family;
	int mask;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct ether_addr mac;
	} address;
};

struct fw3_mac
{
	struct list_head list;

	bool set;
	bool invert;
	struct ether_addr mac;
};

struct fw3_protocol
{
	struct list_head list;

	bool any;
	bool invert;
	uint16_t protocol;
};

struct fw3_port
{
	struct list_head list;

	bool set;
	bool invert;
	uint16_t port_min;
	uint16_t port_max;
};

struct fw3_icmptype
{
	struct list_head list;

	bool invert;
	enum fw3_family family;
	uint8_t type;
	uint8_t code_min;
	uint8_t code_max;
	uint8_t type6;
	uint8_t code6_min;
	uint8_t code6_max;
};

struct fw3_limit
{
	bool invert;
	int rate;
	int burst;
	enum fw3_limit_unit unit;
};

struct fw3_defaults
{
	enum fw3_target policy_input;
	enum fw3_target policy_output;
	enum fw3_target policy_forward;

	bool drop_invalid;

	bool syn_flood;
	struct fw3_limit syn_flood_rate;

	bool tcp_syncookies;
	bool tcp_ecn;
	bool tcp_westwood;
	bool tcp_window_scaling;

	bool accept_redirects;
	bool accept_source_route;

	bool custom_chains;

	bool disable_ipv6;

	uint8_t flags;
};

struct fw3_zone
{
	struct list_head list;

	const char *name;

	enum fw3_family family;

	enum fw3_target policy_input;
	enum fw3_target policy_output;
	enum fw3_target policy_forward;

	struct list_head networks;
	struct list_head devices;
	struct list_head subnets;

	const char *extra_src;
	const char *extra_dest;

	bool masq;
	struct list_head masq_src;
	struct list_head masq_dest;

	bool conntrack;
	bool mtu_fix;

	bool log;
	struct fw3_limit log_limit;

	bool custom_chains;

	uint8_t src_flags;
	uint8_t dst_flags;
};

struct fw3_rule
{
	struct list_head list;

	const char *name;

	enum fw3_family family;

	struct fw3_zone *_src;
	struct fw3_zone *_dest;

	struct fw3_device src;
	struct fw3_device dest;

	struct fw3_ipset *_ipset;
	struct fw3_device ipset;

	struct list_head proto;

	struct list_head ip_src;
	struct list_head mac_src;
	struct list_head port_src;

	struct list_head ip_dest;
	struct list_head port_dest;

	struct list_head icmp_type;

	enum fw3_target target;

	struct fw3_limit limit;

	const char *extra;
};

struct fw3_redirect
{
	struct list_head list;

	const char *name;

	enum fw3_family family;

	struct fw3_zone *_src;
	struct fw3_zone *_dest;

	struct fw3_device src;
	struct fw3_device dest;

	struct fw3_ipset *_ipset;
	struct fw3_device ipset;

	struct list_head proto;

	struct fw3_address ip_src;
	struct list_head mac_src;
	struct fw3_port port_src;

	struct fw3_address ip_dest;
	struct fw3_port port_dest;

	struct fw3_address ip_redir;
	struct fw3_port port_redir;

	enum fw3_target target;

	const char *extra;

	bool reflection;
};

struct fw3_forward
{
	struct list_head list;

	const char *name;

	enum fw3_family family;

	struct fw3_zone *_src;
	struct fw3_zone *_dest;

	struct fw3_device src;
	struct fw3_device dest;
};

struct fw3_ipset
{
	struct list_head list;

	const char *name;
	enum fw3_family family;

	enum fw3_ipset_method method;
	struct list_head datatypes;

	struct list_head iprange;
	struct fw3_port portrange;

	int netmask;
	int maxelem;
	int hashsize;

	int timeout;

	const char *external;
};

struct fw3_state
{
	struct uci_context *uci;
	struct fw3_defaults defaults;
	struct list_head zones;
	struct list_head rules;
	struct list_head redirects;
	struct list_head forwards;
	struct list_head ipsets;

	bool disable_ipsets;
};


struct fw3_option
{
	const char *name;
	bool (*parse)(void *, const char *);
	uintptr_t offset;
	size_t elem_size;
};

#define FW3_OPT(name, parse, structure, member) \
	{ name, fw3_parse_##parse, offsetof(struct fw3_##structure, member) }

#define FW3_LIST(name, parse, structure, member) \
	{ name, fw3_parse_##parse, offsetof(struct fw3_##structure, member), \
	  sizeof(struct fw3_##structure) }


bool fw3_parse_bool(void *ptr, const char *val);
bool fw3_parse_int(void *ptr, const char *val);
bool fw3_parse_string(void *ptr, const char *val);
bool fw3_parse_target(void *ptr, const char *val);
bool fw3_parse_limit(void *ptr, const char *val);
bool fw3_parse_device(void *ptr, const char *val);
bool fw3_parse_address(void *ptr, const char *val);
bool fw3_parse_mac(void *ptr, const char *val);
bool fw3_parse_port(void *ptr, const char *val);
bool fw3_parse_family(void *ptr, const char *val);
bool fw3_parse_icmptype(void *ptr, const char *val);
bool fw3_parse_protocol(void *ptr, const char *val);
bool fw3_parse_ipset_method(void *ptr, const char *val);
bool fw3_parse_ipset_datatype(void *ptr, const char *val);

void fw3_parse_options(void *s, struct fw3_option *opts, int n,
                       struct uci_section *section);

void fw3_format_in_out(struct fw3_device *in, struct fw3_device *out);
void fw3_format_src_dest(struct fw3_address *src, struct fw3_address *dest);
void fw3_format_sport_dport(struct fw3_port *sp, struct fw3_port *dp);
void fw3_format_mac(struct fw3_mac *mac);
void fw3_format_protocol(struct fw3_protocol *proto, enum fw3_family family);
void fw3_format_icmptype(struct fw3_icmptype *icmp, enum fw3_family family);
void fw3_format_limit(struct fw3_limit *limit);
void fw3_format_ipset(struct fw3_ipset *ipset, bool invert);

void __fw3_format_comment(const char *comment, ...);
#define fw3_format_comment(...) __fw3_format_comment(__VA_ARGS__, NULL)

void fw3_format_extra(const char *extra);

#endif
