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

#include <time.h>

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
	FW3_FAMILY_V4  = 4,
	FW3_FAMILY_V6  = 5,
};

enum fw3_flag
{
	FW3_FLAG_UNSPEC        = 0,
	FW3_FLAG_ACCEPT        = 6,
	FW3_FLAG_REJECT        = 7,
	FW3_FLAG_DROP          = 8,
	FW3_FLAG_NOTRACK       = 9,
	FW3_FLAG_MARK          = 10,
	FW3_FLAG_DNAT          = 11,
	FW3_FLAG_SNAT          = 12,
	FW3_FLAG_SRC_ACCEPT    = 13,
	FW3_FLAG_SRC_REJECT    = 14,
	FW3_FLAG_SRC_DROP      = 15,
	FW3_FLAG_CUSTOM_CHAINS = 16,
	FW3_FLAG_SYN_FLOOD     = 17,
	FW3_FLAG_MTU_FIX       = 18,
	FW3_FLAG_DROP_INVALID  = 19,
	FW3_FLAG_HOTPLUG       = 20,

	__FW3_FLAG_MAX
};

extern const char *fw3_flag_names[__FW3_FLAG_MAX];


enum fw3_limit_unit
{
	FW3_LIMIT_UNIT_SECOND = 0,
	FW3_LIMIT_UNIT_MINUTE = 1,
	FW3_LIMIT_UNIT_HOUR   = 2,
	FW3_LIMIT_UNIT_DAY    = 3,

	__FW3_LIMIT_UNIT_MAX
};

extern const char *fw3_limit_units[__FW3_LIMIT_UNIT_MAX];


enum fw3_ipset_method
{
	FW3_IPSET_METHOD_UNSPEC = 0,
	FW3_IPSET_METHOD_BITMAP = 1,
	FW3_IPSET_METHOD_HASH   = 2,
	FW3_IPSET_METHOD_LIST   = 3,

	__FW3_IPSET_METHOD_MAX
};

enum fw3_ipset_type
{
	FW3_IPSET_TYPE_UNSPEC = 0,
	FW3_IPSET_TYPE_IP     = 1,
	FW3_IPSET_TYPE_PORT   = 2,
	FW3_IPSET_TYPE_MAC    = 3,
	FW3_IPSET_TYPE_NET    = 4,
	FW3_IPSET_TYPE_SET    = 5,

	__FW3_IPSET_TYPE_MAX
};

extern const char *fw3_ipset_method_names[__FW3_IPSET_METHOD_MAX];
extern const char *fw3_ipset_type_names[__FW3_IPSET_TYPE_MAX];


enum fw3_include_type
{
	FW3_INC_TYPE_SCRIPT   = 0,
	FW3_INC_TYPE_RESTORE  = 1,
};

enum fw3_reflection_source
{
	FW3_REFLECTION_INTERNAL = 0,
	FW3_REFLECTION_EXTERNAL = 1,
};

struct fw3_ipset_datatype
{
	struct list_head list;
	enum fw3_ipset_type type;
	const char *dir;
};

struct fw3_setmatch
{
	bool set;
	bool invert;
	char name[32];
	const char *dir[3];
	struct fw3_ipset *ptr;
};

struct fw3_device
{
	struct list_head list;

	bool set;
	bool any;
	bool invert;
	char name[32];
	char network[32];
};

struct fw3_address
{
	struct list_head list;

	bool set;
	bool range;
	bool invert;
	bool resolved;
	enum fw3_family family;
	int mask;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct ether_addr mac;
	} address;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct ether_addr mac;
	} address2;
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
	uint32_t protocol;
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

struct fw3_time
{
	bool utc;
	struct tm datestart;
	struct tm datestop;
	uint32_t timestart;
	uint32_t timestop;
	uint32_t monthdays; /* bit 0 is invert + 1 .. 31 */
	uint8_t weekdays;   /* bit 0 is invert + 1 .. 7 */
};

struct fw3_mark
{
	bool set;
	bool invert;
	uint32_t mark;
	uint32_t mask;
};

struct fw3_defaults
{
	enum fw3_flag policy_input;
	enum fw3_flag policy_output;
	enum fw3_flag policy_forward;

	bool drop_invalid;

	bool syn_flood;
	struct fw3_limit syn_flood_rate;

	bool tcp_syncookies;
	int tcp_ecn;
	bool tcp_window_scaling;

	bool accept_redirects;
	bool accept_source_route;

	bool custom_chains;

	bool disable_ipv6;

	uint32_t flags[2];
};

struct fw3_zone
{
	struct list_head list;

	bool enabled;
	const char *name;

	enum fw3_family family;

	enum fw3_flag policy_input;
	enum fw3_flag policy_output;
	enum fw3_flag policy_forward;

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

	uint32_t flags[2];
};

struct fw3_rule
{
	struct list_head list;

	bool enabled;
	const char *name;

	enum fw3_family family;

	struct fw3_zone *_src;
	struct fw3_zone *_dest;

	struct fw3_device src;
	struct fw3_device dest;
	struct fw3_setmatch ipset;

	struct list_head proto;

	struct list_head ip_src;
	struct list_head mac_src;
	struct list_head port_src;

	struct list_head ip_dest;
	struct list_head port_dest;

	struct list_head icmp_type;

	struct fw3_limit limit;
	struct fw3_time time;
	struct fw3_mark mark;

	enum fw3_flag target;
	struct fw3_mark set_mark;
	struct fw3_mark set_xmark;

	const char *extra;
};

struct fw3_redirect
{
	struct list_head list;

	bool enabled;
	const char *name;

	enum fw3_family family;

	struct fw3_zone *_src;
	struct fw3_zone *_dest;

	struct fw3_device src;
	struct fw3_device dest;
	struct fw3_setmatch ipset;

	struct list_head proto;

	struct fw3_address ip_src;
	struct list_head mac_src;
	struct fw3_port port_src;

	struct fw3_address ip_dest;
	struct fw3_port port_dest;

	struct fw3_address ip_redir;
	struct fw3_port port_redir;

	struct fw3_limit limit;
	struct fw3_time time;
	struct fw3_mark mark;

	enum fw3_flag target;

	const char *extra;

	bool local;
	bool reflection;
	enum fw3_reflection_source reflection_src;
};

struct fw3_forward
{
	struct list_head list;

	bool enabled;
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

	bool enabled;
	const char *name;
	enum fw3_family family;

	enum fw3_ipset_method method;
	struct list_head datatypes;

	struct fw3_address iprange;
	struct fw3_port portrange;

	int netmask;
	int maxelem;
	int hashsize;

	int timeout;

	const char *external;

	uint32_t flags[2];
};

struct fw3_include
{
	struct list_head list;

	bool enabled;
	const char *name;
	enum fw3_family family;

	const char *path;
	enum fw3_include_type type;

	bool reload;
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
	struct list_head includes;

	bool disable_ipsets;
	bool statefile;
};

struct fw3_chain_spec {
	int family;
	int table;
	int flag;
	const char *format;
};


struct fw3_option
{
	const char *name;
	bool (*parse)(void *, const char *, bool);
	uintptr_t offset;
	size_t elem_size;
};

#define FW3_OPT(name, parse, structure, member) \
	{ name, fw3_parse_##parse, offsetof(struct fw3_##structure, member) }

#define FW3_LIST(name, parse, structure, member) \
	{ name, fw3_parse_##parse, offsetof(struct fw3_##structure, member), \
	  sizeof(struct fw3_##structure) }

bool fw3_parse_bool(void *ptr, const char *val, bool is_list);
bool fw3_parse_int(void *ptr, const char *val, bool is_list);
bool fw3_parse_string(void *ptr, const char *val, bool is_list);
bool fw3_parse_target(void *ptr, const char *val, bool is_list);
bool fw3_parse_limit(void *ptr, const char *val, bool is_list);
bool fw3_parse_device(void *ptr, const char *val, bool is_list);
bool fw3_parse_address(void *ptr, const char *val, bool is_list);
bool fw3_parse_network(void *ptr, const char *val, bool is_list);
bool fw3_parse_mac(void *ptr, const char *val, bool is_list);
bool fw3_parse_port(void *ptr, const char *val, bool is_list);
bool fw3_parse_family(void *ptr, const char *val, bool is_list);
bool fw3_parse_icmptype(void *ptr, const char *val, bool is_list);
bool fw3_parse_protocol(void *ptr, const char *val, bool is_list);

bool fw3_parse_ipset_method(void *ptr, const char *val, bool is_list);
bool fw3_parse_ipset_datatype(void *ptr, const char *val, bool is_list);

bool fw3_parse_include_type(void *ptr, const char *val, bool is_list);
bool fw3_parse_reflection_source(void *ptr, const char *val, bool is_list);

bool fw3_parse_date(void *ptr, const char *val, bool is_list);
bool fw3_parse_time(void *ptr, const char *val, bool is_list);
bool fw3_parse_weekdays(void *ptr, const char *val, bool is_list);
bool fw3_parse_monthdays(void *ptr, const char *val, bool is_list);
bool fw3_parse_mark(void *ptr, const char *val, bool is_list);
bool fw3_parse_setmatch(void *ptr, const char *val, bool is_list);

bool fw3_parse_options(void *s, const struct fw3_option *opts,
                       struct uci_section *section);

const char * fw3_address_to_string(struct fw3_address *address,
                                   bool allow_invert);

#endif
