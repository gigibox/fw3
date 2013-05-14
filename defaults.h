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

#ifndef __FW3_DEFAULTS_H
#define __FW3_DEFAULTS_H

#include "options.h"
#include "iptables.h"

extern const struct fw3_option fw3_flag_opts[];

void fw3_load_defaults(struct fw3_state *state, struct uci_package *p);

void fw3_print_default_chains(struct fw3_ipt_handle *handle,
                              struct fw3_state *state, bool reload);

void fw3_print_default_head_rules(struct fw3_ipt_handle *handle,
                                  struct fw3_state *state, bool reload);

void fw3_print_default_tail_rules(struct fw3_ipt_handle *handle,
                                  struct fw3_state *state, bool reload);

void fw3_set_defaults(struct fw3_state *state);

void fw3_flush_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                     bool reload);

void fw3_flush_all(struct fw3_ipt_handle *handle);

#endif
