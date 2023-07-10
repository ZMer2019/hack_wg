/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_NETLINK_H
#define _WG_NETLINK_H
#include <net/genetlink.h>
int wg_genetlink_init(void);
void wg_genetlink_uninit(void);
extern struct genl_family genl_family;
#endif /* _WG_NETLINK_H */
