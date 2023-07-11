/******************************************************************
    > File Name: yulong.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/16 14:24:47

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#ifndef YULONG_KM_YULONG_H
#define YULONG_KM_YULONG_H

#include <linux/types.h>
#include "log.h"
#include "cache_common.h"
#include "ylflow.h"
#include <linux/if.h>
#include <linux/inet.h>
#define OPTION_LENGTH       (32)
#define LEVEL_INVALID       (0x7FFFFFFF)
#define DOMAIN_ID_INVALID   (0x7FFFFFFF)
#define MAGIC_ID            0xA5A55A5A
#define POLICY_LIVE         (30)
#define HASH_LEN            (32)
#define STEP                (60)
#define INVALID_SID         (UINT_MAX)
#define OTP_CODE_LENGTH     (6)
#define OTP_KEY_LENGTH      (32)
enum node_type{
    NODE_TYPE_YULONG = 0,
    NODE_TYPE_DACS = 1,
};

enum permission_bypass{
    PERMISSION_BYPASS_DISABLE = 0,
    PERMISSION_BYPASS_ENABLE = 1,
};
enum reject_original_packet{
    REJECT_ORIGINAL_PACKET_DISABLE = 0,
    REJECT_ORIGINAL_PACKET_ENABLE = 1
};
enum auth_type{
    AUTH_TYPE_SINGLE_SIDE = 0,// client identity auth
    AUTH_TYPE_DOUBLE_SIDE = 1,
    AUTH_TYPE_DACS_SIDE = 2,
};
enum inner_packet_type {
    PACKET_TYPE_OUTBOUND = 0,
    PACKET_TYPE_INBOUND = 1
};
struct net_tuple{
    uint32_t saddr, daddr;
    uint16_t source, dest;
    uint8_t protocol;
    uint8_t syn;
};
enum YL_REDIRECT{
    DO_NOT_NEED_REDIRECT = 0,
    REDIRECT = 1,
};
/**
 * this header will attached to each skb in L3
 * */
struct yulong_header{
    __le32 magic_id;
    __le32 leaf_code;
    //__le32 node_code;
    __le32 packet_type:8,
    auth_type:8,
    padding_len:8,
    length:8;
    __le32 leaf_sid;
    //__le32 node_sid;
    u8 option[0];/*for domain name*/
}__aligned(1);

struct yulong_context{
    bool enable_hook;
    bool enable_check_permission;
    bool enable_debug;

    struct identity_hashtable *egress_id_hashtable;
    struct identity_hashtable *ingress_id_hashtable;
    struct login_hashtable *login_hashtable;
    struct rbtree_cache_table *acl_table;
    struct rbtree_cache_table *otp_key_table;
    struct dacs_permission_table *permission_table;

    struct mutex lock;

    struct ylflow_table *flow_table;

    struct rbtree_cache_table *nat_table;

    struct list_head nic_name_list;
    struct list_head device_list;
    rwlock_t nic_name_rwlock;

    uint32_t yulongd_pid;
};

struct nic_node{
    struct list_head list;
    char name[IFNAMSIZ];
};

int yulong_init(bool enable_hook, bool enable_check_permission, bool enable_debug);
void yulong_exit(void);
struct yulong_context* context(void);

uint32_t wg_virtual_local_addr(void);
void set_wg_virtual_local_addr(uint32_t addr);
bool is_bypass_nic(const char *name);

void set_yulongd_pid(pid_t pid);
pid_t get_yulongd_pid(void);

__be32 lookup_redirect_addr(const struct net_tuple *tuple, enum inner_packet_type *pkt_type);

struct identity_entry* find_id_entry_by_tuple(const struct net_tuple *tuple,
        enum inner_packet_type *pkt_type);

struct identity_entry* cache_identity(const struct net_tuple *tuple,
        const struct yulong_header* header,
                bool is_published);

#endif //YULONG_KM_YULONG_H
