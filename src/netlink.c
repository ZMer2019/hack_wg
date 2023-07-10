// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "netlink.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"
#include "uapi/wireguard.h"
#include "yulong/cache_common.h"
#include "sys_wait.h"
#include "yulong.h"
#include <linux/if.h>

#include <net/sock.h>
#include <crypto/algapi.h>

struct genl_family genl_family;

static const struct nla_policy device_policy[WGDEVICE_A_MAX + 1] = {
	[WGDEVICE_A_IFINDEX]		= { .type = NLA_U32 },
	[WGDEVICE_A_IFNAME]		= { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[WGDEVICE_A_PRIVATE_KEY]	= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGDEVICE_A_PUBLIC_KEY]		= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGDEVICE_A_FLAGS]		= { .type = NLA_U32 },
	[WGDEVICE_A_LISTEN_PORT]	= { .type = NLA_U16 },
	[WGDEVICE_A_FWMARK]		= { .type = NLA_U32 },
	[WGDEVICE_A_PEERS]		= { .type = NLA_NESTED }
        ,[WGACL_A_PID]           = {.type = NLA_U32},
        [WGACL_A_UUID]          = {.type = NLA_U32},
        [WGACL_A_OTP_KEY]       = {.type = NLA_STRING, .len = 16},
        [WGACL_A_AUTH]          = {.type = NLA_U8},
        [WGACL_A_SRC_IP]        = {.type = NLA_U32},
        [WGACL_A_SRC_PORT]      = {.type = NLA_U16},
        [WGACL_A_DST_IP]        = {.type = NLA_U32},
        [WGACL_A_DST_PORT]      = {.type = NLA_U16},
        [WGACL_A_PROTOCOL]      = {.type = NLA_U8},
        [WGACL_A_ACL]           = {.type = NLA_U8},
        [WGACL_A_MAGIC]         = {.type = NLA_U32},
        [WGACL_A_SERVER_IDENTITY] = {.type = NLA_NESTED},
        [WGACL_A_NODE_ROLE] = {.type = NLA_U32},
        [WGACL_A_NODE_SN] = {.type = NLA_U32},
        [WGACL_A_DOMAIN_ID] = {.type = NLA_U32},
        [WGACL_A_LEVEL] = {.type = NLA_U32},
        [WGACL_A_MASK] = {.type = NLA_U8},
        [WGACL_A_STARTTIME] = {.type = NLA_U64},
        [WGACL_A_SEQ] = {.type = NLA_U32},
        [WGACL_A_OPTION] = {.type = NLA_STRING, .len = 32},
        [WGACL_A_OPTION_LEN] = {.type = NLA_U16},
        [WGACL_A_HOOK_STATE] = {.type = NLA_U32},
        [WGACL_A_ROUTE_TABLE] = {.type = NLA_NESTED},
        [WGACL_A_AUTH_TYPE] = {.type = NLA_U8},
        [WGACL_A_DACS_BYPASS] = {.type = NLA_U8},
        [WGACL_A_DACS_REJECT_ORIGINAL_PACKET] = {.type = NLA_U8},
        [WGACL_A_COMMUNICATION_ID] = {.type = NLA_U8},
        [WGACL_A_NIC_NAME] = {.type = NLA_STRING, .len = IFNAMSIZ},
        [WGACL_A_NEW_DADDR] = {.type = NLA_U32},
        [WGACL_A_REDIRECT] = {.type = NLA_U8},
};

static const struct nla_policy peer_policy[WGPEER_A_MAX + 1] = {
	[WGPEER_A_PUBLIC_KEY]				= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGPEER_A_PRESHARED_KEY]			= NLA_POLICY_EXACT_LEN(NOISE_SYMMETRIC_KEY_LEN),
	[WGPEER_A_FLAGS]				= { .type = NLA_U32 },
	[WGPEER_A_ENDPOINT]				= NLA_POLICY_MIN_LEN(sizeof(struct sockaddr)),
	[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]	= { .type = NLA_U16 },
	[WGPEER_A_LAST_HANDSHAKE_TIME]			= NLA_POLICY_EXACT_LEN(sizeof(struct __kernel_timespec)),
	[WGPEER_A_RX_BYTES]				= { .type = NLA_U64 },
	[WGPEER_A_TX_BYTES]				= { .type = NLA_U64 },
	[WGPEER_A_ALLOWEDIPS]				= { .type = NLA_NESTED },
	[WGPEER_A_PROTOCOL_VERSION]			= { .type = NLA_U32 }
};

static const struct nla_policy allowedip_policy[WGALLOWEDIP_A_MAX + 1] = {
	[WGALLOWEDIP_A_FAMILY]		= { .type = NLA_U16 },
	[WGALLOWEDIP_A_IPADDR]		= NLA_POLICY_MIN_LEN(sizeof(struct in_addr)),
	[WGALLOWEDIP_A_CIDR_MASK]	= { .type = NLA_U8 }
};

static struct wg_device *lookup_interface(struct nlattr **attrs,
					  struct sk_buff *skb)
{
	struct net_device *dev = NULL;

	if (!attrs[WGDEVICE_A_IFINDEX] == !attrs[WGDEVICE_A_IFNAME])
		return ERR_PTR(-EBADR);
	if (attrs[WGDEVICE_A_IFINDEX])
		dev = dev_get_by_index(sock_net(skb->sk),
				       nla_get_u32(attrs[WGDEVICE_A_IFINDEX]));
	else if (attrs[WGDEVICE_A_IFNAME])
		dev = dev_get_by_name(sock_net(skb->sk),
				      nla_data(attrs[WGDEVICE_A_IFNAME]));
	if (!dev)
		return ERR_PTR(-ENODEV);
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);
		return ERR_PTR(-EOPNOTSUPP);
	}
	return netdev_priv(dev);
}

static int get_allowedips(struct sk_buff *skb, const u8 *ip, u8 cidr,
			  int family)
{
	struct nlattr *allowedip_nest;

	allowedip_nest = nla_nest_start(skb, 0);
	if (!allowedip_nest)
		return -EMSGSIZE;

	if (nla_put_u8(skb, WGALLOWEDIP_A_CIDR_MASK, cidr) ||
	    nla_put_u16(skb, WGALLOWEDIP_A_FAMILY, family) ||
	    nla_put(skb, WGALLOWEDIP_A_IPADDR, family == AF_INET6 ?
		    sizeof(struct in6_addr) : sizeof(struct in_addr), ip)) {
		nla_nest_cancel(skb, allowedip_nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, allowedip_nest);
	return 0;
}

struct dump_ctx {
	struct wg_device *wg;
	struct wg_peer *next_peer;
	u64 allowedips_seq;
	struct allowedips_node *next_allowedip;
};

#define DUMP_CTX(cb) ((struct dump_ctx *)(cb)->args)

static int
get_peer(struct wg_peer *peer, struct sk_buff *skb, struct dump_ctx *ctx)
{

	struct nlattr *allowedips_nest, *peer_nest = nla_nest_start(skb, 0);
	struct allowedips_node *allowedips_node = ctx->next_allowedip;
	bool fail;

	if (!peer_nest)
		return -EMSGSIZE;

	down_read(&peer->handshake.lock);
	fail = nla_put(skb, WGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN,
		       peer->handshake.remote_static);
	up_read(&peer->handshake.lock);
	if (fail)
		goto err;

	if (!allowedips_node) {
		const struct __kernel_timespec last_handshake = {
			.tv_sec = peer->walltime_last_handshake.tv_sec,
			.tv_nsec = peer->walltime_last_handshake.tv_nsec
		};

		down_read(&peer->handshake.lock);
		fail = nla_put(skb, WGPEER_A_PRESHARED_KEY,
			       NOISE_SYMMETRIC_KEY_LEN,
			       peer->handshake.preshared_key);
		up_read(&peer->handshake.lock);
		if (fail)
			goto err;

		if (nla_put(skb, WGPEER_A_LAST_HANDSHAKE_TIME,
			    sizeof(last_handshake), &last_handshake) ||
		    nla_put_u16(skb, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
				peer->persistent_keepalive_interval) ||
		    nla_put_u64_64bit(skb, WGPEER_A_TX_BYTES, peer->tx_bytes,
				      WGPEER_A_UNSPEC) ||
		    nla_put_u64_64bit(skb, WGPEER_A_RX_BYTES, peer->rx_bytes,
				      WGPEER_A_UNSPEC) ||
		    nla_put_u32(skb, WGPEER_A_PROTOCOL_VERSION, 1))
			goto err;

		read_lock_bh(&peer->endpoint_lock);
		if (peer->endpoint.addr.sa_family == AF_INET)
			fail = nla_put(skb, WGPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr4),
				       &peer->endpoint.addr4);
		else if (peer->endpoint.addr.sa_family == AF_INET6)
			fail = nla_put(skb, WGPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr6),
				       &peer->endpoint.addr6);
		read_unlock_bh(&peer->endpoint_lock);
		if (fail)
			goto err;
		allowedips_node =
			list_first_entry_or_null(&peer->allowedips_list,
					struct allowedips_node, peer_list);
	}
	if (!allowedips_node)
		goto no_allowedips;
	if (!ctx->allowedips_seq)
		ctx->allowedips_seq = peer->device->peer_allowedips.seq;
	else if (ctx->allowedips_seq != peer->device->peer_allowedips.seq)
		goto no_allowedips;

	allowedips_nest = nla_nest_start(skb, WGPEER_A_ALLOWEDIPS);
	if (!allowedips_nest)
		goto err;

	list_for_each_entry_from(allowedips_node, &peer->allowedips_list,
				 peer_list) {
		u8 cidr, ip[16] __aligned(__alignof(u64));
		int family;

		family = wg_allowedips_read_node(allowedips_node, ip, &cidr);
		if (get_allowedips(skb, ip, cidr, family)) {
			nla_nest_end(skb, allowedips_nest);
			nla_nest_end(skb, peer_nest);
			ctx->next_allowedip = allowedips_node;
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, allowedips_nest);
no_allowedips:
	nla_nest_end(skb, peer_nest);
	ctx->next_allowedip = NULL;
	ctx->allowedips_seq = 0;
	return 0;
err:
	nla_nest_cancel(skb, peer_nest);
	return -EMSGSIZE;
}

static int wg_get_device_start(struct netlink_callback *cb)
{
	struct wg_device *wg;

	wg = lookup_interface(genl_dumpit_info(cb)->attrs, cb->skb);
	if (IS_ERR(wg))
		return PTR_ERR(wg);
	DUMP_CTX(cb)->wg = wg;
	return 0;
}

static int wg_get_device_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct wg_peer *peer, *next_peer_cursor;
	struct dump_ctx *ctx = DUMP_CTX(cb);
	struct wg_device *wg = ctx->wg;
	struct nlattr *peers_nest;
	int ret = -EMSGSIZE;
	bool done = true;
	void *hdr;

	rtnl_lock();
	mutex_lock(&wg->device_update_lock);
	cb->seq = wg->device_update_gen;
	next_peer_cursor = ctx->next_peer;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &genl_family, NLM_F_MULTI, WG_CMD_GET_DEVICE);
	if (!hdr)
		goto out;
	genl_dump_check_consistent(cb, hdr);

	if (!ctx->next_peer) {
		if (nla_put_u16(skb, WGDEVICE_A_LISTEN_PORT,
				wg->incoming_port) ||
		    nla_put_u32(skb, WGDEVICE_A_FWMARK, wg->fwmark) ||
		    nla_put_u32(skb, WGDEVICE_A_IFINDEX, wg->dev->ifindex) ||
		    nla_put_string(skb, WGDEVICE_A_IFNAME, wg->dev->name))
			goto out;

		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity) {
			if (nla_put(skb, WGDEVICE_A_PRIVATE_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    wg->static_identity.static_private) ||
			    nla_put(skb, WGDEVICE_A_PUBLIC_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    wg->static_identity.static_public)) {
				up_read(&wg->static_identity.lock);
				goto out;
			}
		}
		up_read(&wg->static_identity.lock);
	}

	peers_nest = nla_nest_start(skb, WGDEVICE_A_PEERS);
	if (!peers_nest)
		goto out;
	ret = 0;
	/* If the last cursor was removed via list_del_init in peer_remove, then
	 * we just treat this the same as there being no more peers left. The
	 * reason is that seq_nr should indicate to userspace that this isn't a
	 * coherent dump anyway, so they'll try again.
	 */
	if (list_empty(&wg->peer_list) ||
	    (ctx->next_peer && list_empty(&ctx->next_peer->peer_list))) {
		nla_nest_cancel(skb, peers_nest);
		goto out;
	}
	lockdep_assert_held(&wg->device_update_lock);
	peer = list_prepare_entry(ctx->next_peer, &wg->peer_list, peer_list);
	list_for_each_entry_continue(peer, &wg->peer_list, peer_list) {
		if (get_peer(peer, skb, ctx)) {
			done = false;
			break;
		}
		next_peer_cursor = peer;
	}
	nla_nest_end(skb, peers_nest);

out:
	if (!ret && !done && next_peer_cursor)
		wg_peer_get(next_peer_cursor);
	wg_peer_put(ctx->next_peer);
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();

	if (ret) {
		genlmsg_cancel(skb, hdr);
		return ret;
	}
	genlmsg_end(skb, hdr);
	if (done) {
		ctx->next_peer = NULL;
		return 0;
	}
	ctx->next_peer = next_peer_cursor;
	return skb->len;

	/* At this point, we can't really deal ourselves with safely zeroing out
	 * the private key material after usage. This will need an additional API
	 * in the kernel for marking skbs as zero_on_free.
	 */
}

static int wg_get_device_done(struct netlink_callback *cb)
{
	struct dump_ctx *ctx = DUMP_CTX(cb);

	if (ctx->wg)
		dev_put(ctx->wg->dev);
	wg_peer_put(ctx->next_peer);
	return 0;
}

static int set_port(struct wg_device *wg, u16 port)
{
	struct wg_peer *peer;

	if (wg->incoming_port == port)
		return 0;
	list_for_each_entry(peer, &wg->peer_list, peer_list)
		wg_socket_clear_peer_endpoint_src(peer);
	if (!netif_running(wg->dev)) {
		wg->incoming_port = port;
		return 0;
	}
	return wg_socket_init(wg, port);
}

static int set_allowedip(struct wg_peer *peer, struct nlattr **attrs)
{
	int ret = -EINVAL;
	u16 family;
	u8 cidr;

	if (!attrs[WGALLOWEDIP_A_FAMILY] || !attrs[WGALLOWEDIP_A_IPADDR] ||
	    !attrs[WGALLOWEDIP_A_CIDR_MASK])
		return ret;
	family = nla_get_u16(attrs[WGALLOWEDIP_A_FAMILY]);
	cidr = nla_get_u8(attrs[WGALLOWEDIP_A_CIDR_MASK]);

	if (family == AF_INET && cidr <= 32 &&
	    nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in_addr)){
        ret = wg_allowedips_insert_v4(
                &peer->device->peer_allowedips,
                nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer,
                &peer->device->device_update_lock);
        if(ret < 0){
            return ret;
        }
        ret = context()->flow_table->insert(context()->flow_table,
                                            nla_data(attrs[WGALLOWEDIP_A_IPADDR]),
                                            cidr, &context()->lock);
    }

	else if (family == AF_INET6 && cidr <= 128 &&
		 nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in6_addr))
		ret = wg_allowedips_insert_v6(
			&peer->device->peer_allowedips,
			nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer,
			&peer->device->device_update_lock);

	return ret;
}

static int set_peer(struct wg_device *wg, struct nlattr **attrs)
{
	u8 *public_key = NULL, *preshared_key = NULL;
	struct wg_peer *peer = NULL;
	u32 flags = 0;
	int ret;

	ret = -EINVAL;
	if (attrs[WGPEER_A_PUBLIC_KEY] &&
	    nla_len(attrs[WGPEER_A_PUBLIC_KEY]) == NOISE_PUBLIC_KEY_LEN)
		public_key = nla_data(attrs[WGPEER_A_PUBLIC_KEY]);
	else
		goto out;
	if (attrs[WGPEER_A_PRESHARED_KEY] &&
	    nla_len(attrs[WGPEER_A_PRESHARED_KEY]) == NOISE_SYMMETRIC_KEY_LEN)
		preshared_key = nla_data(attrs[WGPEER_A_PRESHARED_KEY]);

	if (attrs[WGPEER_A_FLAGS])
		flags = nla_get_u32(attrs[WGPEER_A_FLAGS]);
	ret = -EOPNOTSUPP;
	if (flags & ~__WGPEER_F_ALL)
		goto out;

	ret = -EPFNOSUPPORT;
	if (attrs[WGPEER_A_PROTOCOL_VERSION]) {
		if (nla_get_u32(attrs[WGPEER_A_PROTOCOL_VERSION]) != 1)
			goto out;
	}

	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable,
					  nla_data(attrs[WGPEER_A_PUBLIC_KEY]));
	ret = 0;
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		if (flags & (WGPEER_F_REMOVE_ME | WGPEER_F_UPDATE_ONLY))
			goto out;

		/* The peer is new, so there aren't allowed IPs to remove. */
		flags &= ~WGPEER_F_REPLACE_ALLOWEDIPS;

		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity &&
		    !memcmp(nla_data(attrs[WGPEER_A_PUBLIC_KEY]),
			    wg->static_identity.static_public,
			    NOISE_PUBLIC_KEY_LEN)) {
			/* We silently ignore peers that have the same public
			 * key as the device. The reason we do it silently is
			 * that we'd like for people to be able to reuse the
			 * same set of API calls across peers.
			 */
			up_read(&wg->static_identity.lock);
			ret = 0;
			goto out;
		}
		up_read(&wg->static_identity.lock);

		peer = wg_peer_create(wg, public_key, preshared_key);
		if (IS_ERR(peer)) {
			ret = PTR_ERR(peer);
			peer = NULL;
			goto out;
		}
		/* Take additional reference, as though we've just been
		 * looked up.
		 */
		wg_peer_get(peer);
	}

	if (flags & WGPEER_F_REMOVE_ME) {
		wg_peer_remove(peer);
		goto out;
	}

	if (preshared_key) {
		down_write(&peer->handshake.lock);
		memcpy(&peer->handshake.preshared_key, preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
		up_write(&peer->handshake.lock);
	}

	if (attrs[WGPEER_A_ENDPOINT]) {
		struct sockaddr *addr = nla_data(attrs[WGPEER_A_ENDPOINT]);
		size_t len = nla_len(attrs[WGPEER_A_ENDPOINT]);

		if ((len == sizeof(struct sockaddr_in) &&
		     addr->sa_family == AF_INET) ||
		    (len == sizeof(struct sockaddr_in6) &&
		     addr->sa_family == AF_INET6)) {
			struct endpoint endpoint = { { { 0 } } };

			memcpy(&endpoint.addr, addr, len);
			wg_socket_set_peer_endpoint(peer, &endpoint);
		}
	}

	if (flags & WGPEER_F_REPLACE_ALLOWEDIPS)
		wg_allowedips_remove_by_peer(&wg->peer_allowedips, peer,
					     &wg->device_update_lock);

	if (attrs[WGPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr, *allowedip[WGALLOWEDIP_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, attrs[WGPEER_A_ALLOWEDIPS], rem) {
			ret = nla_parse_nested(allowedip, WGALLOWEDIP_A_MAX,
					       attr, allowedip_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_allowedip(peer, allowedip);
			if (ret < 0)
				goto out;
		}
	}

	if (attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
		const u16 persistent_keepalive_interval = nla_get_u16(
				attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		const bool send_keepalive =
			!peer->persistent_keepalive_interval &&
			persistent_keepalive_interval &&
			netif_running(wg->dev);

		peer->persistent_keepalive_interval = persistent_keepalive_interval;
		if (send_keepalive)
			wg_packet_send_keepalive(peer);
	}

	if (netif_running(wg->dev))
		wg_packet_send_staged_packets(peer);

out:
	wg_peer_put(peer);
	if (attrs[WGPEER_A_PRESHARED_KEY])
		memzero_explicit(nla_data(attrs[WGPEER_A_PRESHARED_KEY]),
				 nla_len(attrs[WGPEER_A_PRESHARED_KEY]));
	return ret;
}

static int wg_set_device(struct sk_buff *skb, struct genl_info *info)
{
	struct wg_device *wg = lookup_interface(info->attrs, skb);
	u32 flags = 0;
	int ret;

	if (IS_ERR(wg)) {
		ret = PTR_ERR(wg);
		goto out_nodev;
	}

	rtnl_lock();
	mutex_lock(&wg->device_update_lock);

	if (info->attrs[WGDEVICE_A_FLAGS])
		flags = nla_get_u32(info->attrs[WGDEVICE_A_FLAGS]);
	ret = -EOPNOTSUPP;
	if (flags & ~__WGDEVICE_F_ALL)
		goto out;

	if (info->attrs[WGDEVICE_A_LISTEN_PORT] || info->attrs[WGDEVICE_A_FWMARK]) {
		struct net *net;
		rcu_read_lock();
		net = rcu_dereference(wg->creating_net);
		ret = !net || !ns_capable(net->user_ns, CAP_NET_ADMIN) ? -EPERM : 0;
		rcu_read_unlock();
		if (ret)
			goto out;
	}

	++wg->device_update_gen;

	if (info->attrs[WGDEVICE_A_FWMARK]) {
		struct wg_peer *peer;

		wg->fwmark = nla_get_u32(info->attrs[WGDEVICE_A_FWMARK]);
		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_socket_clear_peer_endpoint_src(peer);
	}

	if (info->attrs[WGDEVICE_A_LISTEN_PORT]) {
		ret = set_port(wg,
			nla_get_u16(info->attrs[WGDEVICE_A_LISTEN_PORT]));
		if (ret)
			goto out;
	}

	if (flags & WGDEVICE_F_REPLACE_PEERS)
		wg_peer_remove_all(wg);

	if (info->attrs[WGDEVICE_A_PRIVATE_KEY] &&
	    nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]) ==
		    NOISE_PUBLIC_KEY_LEN) {
		u8 *private_key = nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]);
		u8 public_key[NOISE_PUBLIC_KEY_LEN];
		struct wg_peer *peer, *temp;

		if (!crypto_memneq(wg->static_identity.static_private,
				   private_key, NOISE_PUBLIC_KEY_LEN))
			goto skip_set_private_key;

		/* We remove before setting, to prevent race, which means doing
		 * two 25519-genpub ops.
		 */
		if (curve25519_generate_public(public_key, private_key)) {
			peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable,
							  public_key);
			if (peer) {
				wg_peer_put(peer);
				wg_peer_remove(peer);
			}
		}

		down_write(&wg->static_identity.lock);
		wg_noise_set_static_identity_private_key(&wg->static_identity,
							 private_key);
		list_for_each_entry_safe(peer, temp, &wg->peer_list,
					 peer_list) {
			wg_noise_precompute_static_static(peer);
			wg_noise_expire_current_peer_keypairs(peer);
		}
		wg_cookie_checker_precompute_device_keys(&wg->cookie_checker);
		up_write(&wg->static_identity.lock);
	}
skip_set_private_key:

	if (info->attrs[WGDEVICE_A_PEERS]) {
		struct nlattr *attr, *peer[WGPEER_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, info->attrs[WGDEVICE_A_PEERS], rem) {
			ret = nla_parse_nested(peer, WGPEER_A_MAX, attr,
					       peer_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_peer(wg, peer);
			if (ret < 0)
				goto out;
		}
	}
	ret = 0;

out:
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();
	dev_put(wg->dev);
out_nodev:
	if (info->attrs[WGDEVICE_A_PRIVATE_KEY])
		memzero_explicit(nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]),
				 nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]));
	return ret;
}

static int netlink_yulong_init(struct sk_buff *skb, struct genl_info *info){
    uint8_t comm_id = 0;
    pid_t communication_pid = 0;
    if(info->attrs[WGACL_A_COMMUNICATION_ID]){
        comm_id = nla_get_u8(info->attrs[WGACL_A_COMMUNICATION_ID]);
    }
    if(info->attrs[WGACL_A_PID]){
        communication_pid = nla_get_u32(info->attrs[WGACL_A_PID]);
    }
    set_yulongd_pid(info->snd_portid);
    pr_info("comm_id[%d], communication_pid[%u], portid[%02X]\n",
            comm_id, communication_pid, info->snd_portid);
    return 0;
}

static int netlink_login_response(struct sk_buff *skb, struct genl_info *info){
    uint32_t daddr, new_daddr;
    uint16_t source, dest;
    uint8_t protocol;
    uint32_t sid;
    pid_t pid;
    uint64_t start_time;
    int request_seq = -1;
    int err = 0;
    struct identity_entry *entry = NULL;
    struct login_hashtable_entry *login_entry = NULL;
    struct nat_addr *addr;
    unsigned char otp_key[OTP_KEY_LEN + 1] = {0};
    LOGI("login response\n");
    if(!info->attrs[WGACL_A_PID] ||
    !info->attrs[WGACL_A_UUID] ||
    !info->attrs[WGACL_A_OTP_KEY]||
    nla_len(info->attrs[WGACL_A_OTP_KEY]) != OTP_KEY_LEN||
    !info->attrs[WGACL_A_DST_IP]||
    !info->attrs[WGACL_A_SRC_PORT]||
    !info->attrs[WGACL_A_DST_PORT]||
    !info->attrs[WGACL_A_STARTTIME]||
    !info->attrs[WGACL_A_SEQ]||
    !info->attrs[WGACL_A_PROTOCOL]||
    !info->attrs[WGACL_A_NEW_DADDR]
    ){
        if(info->attrs[WGACL_A_SEQ]){
            LOGI("seq[%d]", nla_get_s32(info->attrs[WGACL_A_SEQ]));
            request_seq = nla_get_s32(info->attrs[WGACL_A_SEQ]);
            login_wakeup(request_seq);
        }
        LOGI("login failed\n");
        return 0;
    }
    pid = nla_get_u32(info->attrs[WGACL_A_PID]);
    sid = nla_get_u32(info->attrs[WGACL_A_UUID]);
    memcpy(otp_key, nla_data(info->attrs[WGACL_A_OTP_KEY]), OTP_KEY_LEN);
    daddr = nla_get_u32(info->attrs[WGACL_A_DST_IP]);
    source = nla_get_u16(info->attrs[WGACL_A_SRC_PORT]);
    dest = nla_get_u16(info->attrs[WGACL_A_DST_PORT]);
    start_time = nla_get_u64(info->attrs[WGACL_A_STARTTIME]);
    request_seq = nla_get_s32(info->attrs[WGACL_A_SEQ]);
    protocol = nla_get_u8(info->attrs[WGACL_A_PROTOCOL]);
    new_daddr = nla_get_u8(info->attrs[WGACL_A_NEW_DADDR]);
    do{
        login_entry = kzalloc(sizeof(struct login_hashtable_entry), GFP_KERNEL);
        if(login_entry){
            login_entry->key.pid = pid;
            login_entry->key.daddr = daddr;
            login_entry->key.dest = dest;
            login_entry->key.protocol = protocol;
            login_entry->identity.sid = sid;
            memcpy(login_entry->identity.otp_key, otp_key, OTP_KEY_LEN);
            context()->login_hashtable->add(context()->login_hashtable, login_entry);
        }else{
            err = 1;
            break;
        }
        entry = kzalloc(sizeof(struct identity_entry), GFP_KERNEL);
        if(entry){
            entry->key.saddr = wg_virtual_local_addr();
            entry->key.daddr = daddr;
            entry->key.source = source;
            entry->key.dest = dest;
            entry->key.protocol = protocol;
            entry->leaf.sid = sid;
            entry->leaf.code = 0;
            entry->type = PROTOCOL_TYPE_YULONG;
            memcpy(entry->leaf.otp_key, otp_key, OTP_KEY_LEN);
            context()->egress_id_hashtable->add(context()->egress_id_hashtable, entry);
        }else{
            err = 2;
            break;
        }

        addr = kzalloc(sizeof(struct nat_addr), GFP_KERNEL);
        if(addr){
            addr->original_daddr = htonl(dest);
            addr->new_daddr = new_daddr;

            context()->nat_table->insert(context()->nat_table, sid, addr);
        }else{
            err = 3;
            break;
        }

    } while (0);
    if(err != 0){
        LOGE("save login info failed, request seq[%d], err[%d]\n", request_seq, err);
    }else{
        LOGI("login done\n");
    }
    login_wakeup(request_seq);

    return 0;
}

#ifndef COMPAT_CANNOT_USE_CONST_GENL_OPS
static const
#else
static
#endif
struct genl_ops genl_ops[] = {
	{
		.cmd = WG_CMD_GET_DEVICE,
#ifndef COMPAT_CANNOT_USE_NETLINK_START
		.start = wg_get_device_start,
#endif
		.dumpit = wg_get_device_dump,
		.done = wg_get_device_done,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	}, {
		.cmd = WG_CMD_SET_DEVICE,
		.doit = wg_set_device,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	},{
        .cmd = WG_CMD_INIT,
        .doit = netlink_yulong_init,
    },{
        .cmd = WG_CMD_HOOK_LOGIN_RESPONSE,
        .doit = netlink_login_response,
    }
};

struct genl_family genl_family
#ifndef COMPAT_CANNOT_USE_GENL_NOPS
__ro_after_init = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
#else
= {
#endif
	.name = WG_GENL_NAME,
	.version = WG_GENL_VERSION,
	.maxattr = WGDEVICE_A_MAX,
	.module = THIS_MODULE,
#ifndef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
	.policy = device_policy,
#endif
	.netnsok = true
};

int __init wg_genetlink_init(void)
{
	return genl_register_family(&genl_family);
}

void __exit wg_genetlink_uninit(void)
{
	genl_unregister_family(&genl_family);
}
