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

#include "forwards.h"


const struct fw3_option fw3_forward_opts[] = {
	FW3_OPT("name",                string,   forward,     name),
	FW3_OPT("family",              family,   forward,     family),

	FW3_OPT("src",                 device,   forward,     src),
	FW3_OPT("dest",                device,   forward,     dest),

	{ }
};


void
fw3_load_forwards(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_forward *forward;

	INIT_LIST_HEAD(&state->forwards);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "forwarding"))
			continue;

		forward = malloc(sizeof(*forward));

		if (!forward)
			continue;

		memset(forward, 0, sizeof(*forward));

		fw3_parse_options(forward, fw3_forward_opts, s);

		if (forward->src.invert || forward->dest.invert)
		{
			warn_elem(e, "must not have inverted 'src' or 'dest' options");
			fw3_free_forward(forward);
			continue;
		}
		else if (forward->src.set && !forward->src.any &&
		         !(forward->_src = fw3_lookup_zone(state, forward->src.name, false)))
		{
			warn_elem(e, "refers to not existing zone '%s'", forward->src.name);
			fw3_free_forward(forward);
			continue;
		}
		else if (forward->dest.set && !forward->dest.any &&
		         !(forward->_dest = fw3_lookup_zone(state, forward->dest.name, false)))
		{
			warn_elem(e, "refers to not existing zone '%s'", forward->dest.name);
			fw3_free_forward(forward);
			continue;
		}

		if (forward->_dest)
		{
			setbit(forward->_dest->dst_flags, FW3_TARGET_ACCEPT);

			if (forward->_src &&
			    (forward->_src->conntrack || forward->_dest->conntrack))
			{
				forward->_src->conntrack = forward->_dest->conntrack = true;
			}
		}

		list_add_tail(&forward->list, &state->forwards);
		continue;
	}
}


static void
print_chain(struct fw3_forward *forward)
{
	if (forward->src.any || !forward->src.set)
		fw3_pr("-A delegate_forward");
	else
		fw3_pr("-A zone_%s_forward", forward->src.name);
}

static void print_target(struct fw3_forward *forward)
{
	if (forward->dest.any || !forward->dest.set)
		fw3_pr(" -j ACCEPT\n");
	else
		fw3_pr(" -j zone_%s_dest_ACCEPT\n", forward->dest.name);
}

static void
print_forward(enum fw3_table table, enum fw3_family family,
              struct fw3_forward *forward)
{
	const char *s, *d;

	if (table != FW3_TABLE_FILTER)
		return;

	if (!fw3_is_family(forward, family))
		return;

	s = forward->_src  ? forward->_src->name  : "*";
	d = forward->_dest ? forward->_dest->name : "*";

	if (forward->name)
		info("   * Forward '%s'", forward->name);
	else
		info("   * Forward %s->%s", s, d);

	if (!fw3_is_family(forward->_src, family) ||
	    !fw3_is_family(forward->_dest, family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	print_chain(forward);
	fw3_format_comment("forwarding ", s, "->", d);
	print_target(forward);
}

void
fw3_print_forwards(enum fw3_table table, enum fw3_family family,
                   struct fw3_state *state)
{
	struct fw3_forward *forward;

	list_for_each_entry(forward, &state->forwards, list)
		print_forward(table, family, forward);
}
