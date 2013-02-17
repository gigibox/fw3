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

#ifndef __FW3_ICMP_CODES_H
#define __FW3_ICMP_CODES_H


struct fw3_icmptype_entry {
        const char *name;
        uint8_t type;
        uint8_t code_min;
		uint8_t code_max;
};

/* taken from iptables extensions/libipt_icmp.c */
static const struct fw3_icmptype_entry fw3_icmptype_list_v4[] = {
        { "any", 0xFF, 0, 0xFF },
        { "echo-reply", 0, 0, 0xFF },
        /* Alias */ { "pong", 0, 0, 0xFF },

        { "destination-unreachable", 3, 0, 0xFF },
        {   "network-unreachable", 3, 0, 0 },
        {   "host-unreachable", 3, 1, 1 },
        {   "protocol-unreachable", 3, 2, 2 },
        {   "port-unreachable", 3, 3, 3 },
        {   "fragmentation-needed", 3, 4, 4 },
        {   "source-route-failed", 3, 5, 5 },
        {   "network-unknown", 3, 6, 6 },
        {   "host-unknown", 3, 7, 7 },
        {   "network-prohibited", 3, 9, 9 },
        {   "host-prohibited", 3, 10, 10 },
        {   "TOS-network-unreachable", 3, 11, 11 },
        {   "TOS-host-unreachable", 3, 12, 12 },
        {   "communication-prohibited", 3, 13, 13 },
        {   "host-precedence-violation", 3, 14, 14 },
        {   "precedence-cutoff", 3, 15, 15 },

        { "source-quench", 4, 0, 0xFF },

        { "redirect", 5, 0, 0xFF },
        {   "network-redirect", 5, 0, 0 },
        {   "host-redirect", 5, 1, 1 },
        {   "TOS-network-redirect", 5, 2, 2 },
        {   "TOS-host-redirect", 5, 3, 3 },

        { "echo-request", 8, 0, 0xFF },
        /* Alias */ { "ping", 8, 0, 0xFF },

        { "router-advertisement", 9, 0, 0xFF },

        { "router-solicitation", 10, 0, 0xFF },

        { "time-exceeded", 11, 0, 0xFF },
        /* Alias */ { "ttl-exceeded", 11, 0, 0xFF },
        {   "ttl-zero-during-transit", 11, 0, 0 },
        {   "ttl-zero-during-reassembly", 11, 1, 1 },

        { "parameter-problem", 12, 0, 0xFF },
        {   "ip-header-bad", 12, 0, 0 },
        {   "required-option-missing", 12, 1, 1 },

        { "timestamp-request", 13, 0, 0xFF },

        { "timestamp-reply", 14, 0, 0xFF },

        { "address-mask-request", 17, 0, 0xFF },

        { "address-mask-reply", 18, 0, 0xFF }
};

/* taken from iptables extensions/libip6t_icmp6.c */
static const struct fw3_icmptype_entry fw3_icmptype_list_v6[] = {
	{ "destination-unreachable", 1, 0, 0xFF },
	{   "no-route", 1, 0, 0 },
	{   "communication-prohibited", 1, 1, 1 },
	{   "address-unreachable", 1, 3, 3 },
	{   "port-unreachable", 1, 4, 4 },

	{ "packet-too-big", 2, 0, 0xFF },

	{ "time-exceeded", 3, 0, 0xFF },
	/* Alias */ { "ttl-exceeded", 3, 0, 0xFF },
	{   "ttl-zero-during-transit", 3, 0, 0 },
	{   "ttl-zero-during-reassembly", 3, 1, 1 },

	{ "parameter-problem", 4, 0, 0xFF },
	{   "bad-header", 4, 0, 0 },
	{   "unknown-header-type", 4, 1, 1 },
	{   "unknown-option", 4, 2, 2 },

	{ "echo-request", 128, 0, 0xFF },
	/* Alias */ { "ping", 128, 0, 0xFF },

	{ "echo-reply", 129, 0, 0xFF },
	/* Alias */ { "pong", 129, 0, 0xFF },

	{ "router-solicitation", 133, 0, 0xFF },

	{ "router-advertisement", 134, 0, 0xFF },

	{ "neighbour-solicitation", 135, 0, 0xFF },
	/* Alias */ { "neighbor-solicitation", 135, 0, 0xFF },

	{ "neighbour-advertisement", 136, 0, 0xFF },
	/* Alias */ { "neighbor-advertisement", 136, 0, 0xFF },

	{ "redirect", 137, 0, 0xFF },
};

#endif
