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

#ifndef __FW3_UTILS_H
#define __FW3_UTILS_H

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <libubox/list.h>
#include <uci.h>


#define FW3_STATEFILE	"/var/run/fw3.state"
#define FW3_LOCKFILE	"/var/run/fw3.lock"
#define FW3_HOTPLUG     "/sbin/hotplug-call"

extern bool fw3_pr_debug;

void warn_elem(struct uci_element *e, const char *format, ...);
void warn(const char *format, ...);
void error(const char *format, ...);
void info(const char *format, ...);

#define setbit(field, flag) field |= (1 << (flag))
#define delbit(field, flag) field &= ~(1 << (flag))
#define hasbit(field, flag) (field & (1 << (flag)))

#define set(field, family, flag) setbit(field[family == FW3_FAMILY_V6], flag)
#define del(field, family, flag) delbit(field[family == FW3_FAMILY_V6], flag)
#define has(field, family, flag) hasbit(field[family == FW3_FAMILY_V6], flag)

#define fw3_foreach(p, h)                                                  \
	for (p = list_empty(h) ? NULL : list_first_entry(h, typeof(*p), list); \
         list_empty(h) ? (p == NULL) : (&p->list != (h));                  \
	     p = list_empty(h) ? list_first_entry(h, typeof(*p), list)         \
                           : list_entry(p->list.next, typeof(*p), list))

#define fw3_is_family(p, f)                                                \
	(!p || (p)->family == FW3_FAMILY_ANY || (p)->family == f)

#define fw3_no_family(flags)                                               \
	(!(flags & ((1 << FW3_FAMILY_V4) | (1 << FW3_FAMILY_V6))))

#define fw3_no_table(flags)                                                \
    (!(flags & ((1<<FW3_TABLE_FILTER)|(1<<FW3_TABLE_NAT)|                  \
                (1<<FW3_TABLE_MANGLE)|(1<<FW3_TABLE_RAW))))


void * fw3_alloc(size_t size);
char * fw3_strdup(const char *s);

const char * fw3_find_command(const char *cmd);

bool fw3_stdout_pipe(void);
bool __fw3_command_pipe(bool silent, const char *command, ...);
#define fw3_command_pipe(...) __fw3_command_pipe(__VA_ARGS__, NULL)

void fw3_command_close(void);
void fw3_pr(const char *fmt, ...);

bool fw3_has_table(bool ipv6, const char *table);

bool fw3_lock(void);
void fw3_unlock(void);


void fw3_write_statefile(void *state);

void fw3_free_object(void *obj, const void *opts);

void fw3_free_list(struct list_head *head);

bool fw3_hotplug(bool add, void *zone, void *device);

#endif
