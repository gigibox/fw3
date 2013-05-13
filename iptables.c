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

#include "iptables.h"


struct fw3_ipt_handle *
fw3_ipt_open(enum fw3_family family, enum fw3_table table)
{
	struct fw3_ipt_handle *h;

	h = malloc(sizeof(*h));

	if (!h)
		return NULL;

	if (family == FW3_FAMILY_V6)
	{
		h->family = FW3_FAMILY_V6;
		h->table  = table;
		h->handle = ip6tc_init(fw3_flag_names[table]);
	}
	else
	{
		h->family = FW3_FAMILY_V4;
		h->table  = table;
		h->handle = iptc_init(fw3_flag_names[table]);
	}

	if (!h->handle)
	{
		free(h);
		return NULL;
	}

	return h;
}

void fw3_ipt_set_policy(struct fw3_ipt_handle *h, enum fw3_flag policy)
{
	if (h->table != FW3_TABLE_FILTER)
		return;

	if (h->family == FW3_FAMILY_V6)
	{
		ip6tc_set_policy("INPUT", fw3_flag_names[policy], NULL, h->handle);
		ip6tc_set_policy("OUTPUT", fw3_flag_names[policy], NULL, h->handle);
		ip6tc_set_policy("FORWARD", fw3_flag_names[policy], NULL, h->handle);
	}
	else
	{
		iptc_set_policy("INPUT", fw3_flag_names[policy], NULL, h->handle);
		iptc_set_policy("OUTPUT", fw3_flag_names[policy], NULL, h->handle);
		iptc_set_policy("FORWARD", fw3_flag_names[policy], NULL, h->handle);
	}
}

void fw3_ipt_delete_chain(struct fw3_ipt_handle *h, const char *chain)
{
	if (h->family == FW3_FAMILY_V6)
	{
		if (ip6tc_flush_entries(chain, h->handle))
			ip6tc_delete_chain(chain, h->handle);
	}
	else
	{
		if (iptc_flush_entries(chain, h->handle))
			iptc_delete_chain(chain, h->handle);
	}
}

void fw3_ipt_delete_rules(struct fw3_ipt_handle *h, const char *target)
{
	unsigned int num;
	const struct ipt_entry *e;
	const struct ip6t_entry *e6;
	const char *chain;
	const char *t;
	bool found;

	if (h->family == FW3_FAMILY_V6)
	{
		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			do {
				found = false;

				for (num = 0, e6 = ip6tc_first_rule(chain, h->handle);
					 e6 != NULL;
					 num++, e6 = ip6tc_next_rule(e6, h->handle))
				{
					t = ip6tc_get_target(e6, h->handle);

					if (*t && !strcmp(t, target))
					{
						ip6tc_delete_num_entry(chain, num, h->handle);
						found = true;
						break;
					}
				}
			} while (found);
		}
	}
	else
	{
		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			do {
				found = false;

				for (num = 0, e = iptc_first_rule(chain, h->handle);
				     e != NULL;
					 num++, e = iptc_next_rule(e, h->handle))
				{
					t = iptc_get_target(e, h->handle);

					if (*t && !strcmp(t, target))
					{
						iptc_delete_num_entry(chain, num, h->handle);
						found = true;
						break;
					}
				}
			} while (found);
		}
	}
}

void fw3_ipt_flush(struct fw3_ipt_handle *h)
{
	const char *chain;

	if (h->family == FW3_FAMILY_V6)
	{
		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			ip6tc_flush_entries(chain, h->handle);
		}

		for (chain = ip6tc_first_chain(h->handle);
		     chain != NULL;
		     chain = ip6tc_next_chain(h->handle))
		{
			ip6tc_delete_chain(chain, h->handle);
		}
	}
	else
	{
		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			iptc_flush_entries(chain, h->handle);
		}

		for (chain = iptc_first_chain(h->handle);
		     chain != NULL;
		     chain = iptc_next_chain(h->handle))
		{
			iptc_delete_chain(chain, h->handle);
		}
	}
}

void fw3_ipt_commit(struct fw3_ipt_handle *h)
{
	if (h->family == FW3_FAMILY_V6)
		ip6tc_commit(h->handle);
	else
		iptc_commit(h->handle);

	free(h);
}
