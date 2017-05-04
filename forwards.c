/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jo@mein.io>
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
	FW3_OPT("enabled",             bool,     forward,     enabled),

	FW3_OPT("name",                string,   forward,     name),
	FW3_OPT("family",              family,   forward,     family),

	FW3_OPT("src",                 device,   forward,     src),
	FW3_OPT("dest",                device,   forward,     dest),

	{ }
};

static bool
check_forward(struct fw3_state *state, struct fw3_forward *forward, struct uci_element *e)
{
	if (!forward->enabled)
		return false;

	if (forward->src.invert || forward->dest.invert)
	{
		warn_section("forward", forward, e, "must not have inverted 'src' or 'dest' options");
		return false;
	}
	else if (forward->src.set && !forward->src.any &&
		 !(forward->_src = fw3_lookup_zone(state, forward->src.name)))
	{
		warn_section("forward", forward, e, "refers to not existing zone '%s'",
				forward->src.name);
		return false;
	}
	else if (forward->dest.set && !forward->dest.any &&
		 !(forward->_dest = fw3_lookup_zone(state, forward->dest.name)))
	{
		warn_section("forward", forward, e, "refers to not existing zone '%s'",
				forward->dest.name);
		return false;
	}

	/* NB: forward family... */
	if (forward->_dest)
	{
		fw3_setbit(forward->_dest->flags[0], FW3_FLAG_ACCEPT);
		fw3_setbit(forward->_dest->flags[1], FW3_FLAG_ACCEPT);
	}

	return true;
}

static struct fw3_forward *
fw3_alloc_forward(struct fw3_state *state)
{
	struct fw3_forward *forward;

	forward = calloc(1, sizeof(*forward));
	if (!forward)
		return NULL;

	forward->enabled = true;

	list_add_tail(&forward->list, &state->forwards);

	return forward;
}

void
fw3_load_forwards(struct fw3_state *state, struct uci_package *p,
		struct blob_attr *a)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_forward *forward;
	struct blob_attr *entry;
	unsigned rem;

	INIT_LIST_HEAD(&state->forwards);

	blob_for_each_attr(entry, a, rem)
	{
		const char *type;
		const char *name = "ubus forward";

		if (!fw3_attr_parse_name_type(entry, &name, &type))
			continue;

		if (strcmp(type, "forwarding"))
			continue;

		forward = fw3_alloc_forward(state);
		if (!forward)
			continue;

		if (!fw3_parse_blob_options(forward, fw3_forward_opts, entry, name))
		{
			warn_section("forward", forward, NULL, "skipped due to invalid options");
			fw3_free_forward(forward);
			continue;
		}

		if (!check_forward(state, forward, NULL))
			fw3_free_forward(forward);
	}

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "forwarding"))
			continue;

		forward = fw3_alloc_forward(state);
		if (!forward)
			continue;

		if (!fw3_parse_options(forward, fw3_forward_opts, s))
			warn_elem(e, "has invalid options");

		if (!check_forward(state, forward, e))
			fw3_free_forward(forward);
	}
}


static void
append_chain(struct fw3_ipt_rule *r, struct fw3_forward *forward)
{
	if (forward->src.any || !forward->src.set)
		fw3_ipt_rule_append(r, "FORWARD");
	else
		fw3_ipt_rule_append(r, "zone_%s_forward", forward->src.name);
}

static void set_target(struct fw3_ipt_rule *r, struct fw3_forward *forward)
{
	if (forward->dest.any || !forward->dest.set)
		fw3_ipt_rule_target(r, "ACCEPT");
	else
		fw3_ipt_rule_target(r, "zone_%s_dest_ACCEPT", forward->dest.name);
}

static void
print_forward(struct fw3_ipt_handle *handle, struct fw3_forward *forward)
{
	const char *s, *d;
	struct fw3_ipt_rule *r;

	if (handle->table != FW3_TABLE_FILTER)
		return;

	if (!fw3_is_family(forward, handle->family))
		return;

	s = forward->_src  ? forward->_src->name  : "*";
	d = forward->_dest ? forward->_dest->name : "*";

	info("   * Forward '%s' -> '%s'", s, d);

	if (!fw3_is_family(forward->_src, handle->family) ||
	    !fw3_is_family(forward->_dest, handle->family))
	{
		info("     ! Skipping due to different family of zone");
		return;
	}

	r = fw3_ipt_rule_new(handle);
	fw3_ipt_rule_comment(r, "forwarding %s -> %s", s, d);
	set_target(r, forward);
	append_chain(r, forward);
}

void
fw3_print_forwards(struct fw3_ipt_handle *handle, struct fw3_state *state)
{
	struct fw3_forward *forward;

	list_for_each_entry(forward, &state->forwards, list)
		print_forward(handle, forward);
}
