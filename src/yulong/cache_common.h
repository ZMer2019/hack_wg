/******************************************************************
    > File Name: cache_common.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/17 17:04:35

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#ifndef YULONG_KM_CACHE_COMMON_H
#define YULONG_KM_CACHE_COMMON_H

#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/siphash.h>
#include <linux/skbuff.h>
#include <linux/inet.h>


#define OTP_KEY_LEN         (32)

/**
 * rbtree general api
 * */
/**
 * acl data declare
 * */
enum acl{
    ACL_DENY,
    ACL_ACCEPT,
    ACL_UNKNOWN
};
struct acl_data{
    enum acl a;
    time_t timestamp;
};
/**
 * otp key declare
 * */
struct otp_key{
    unsigned char otp_key[OTP_KEY_LEN];
};
struct nat_addr{
    uint32_t original_daddr;
    uint32_t redirect_daddr;
};
enum protocol_type{
    PROTOCOL_TYPE_ORIGINAL = 0,
    PROTOCOL_TYPE_YULONG = 1,
    PROTOCOL_TYPE_DACS = 2,
};

struct rbtree_cache_node{
    uint32_t key;
    void *data;
    struct rb_node node;
};
struct rbtree_cache_table{
    struct rb_root root;
    rwlock_t lock;
    struct rbtree_cache_node*(*lookup)(struct rbtree_cache_table* table, uint32_t key);
    int (*insert)(struct rbtree_cache_table* table, uint32_t key, void *data);
    void (*del)(struct rbtree_cache_table* table, uint32_t key);
};

struct rbtree_cache_table * rbtree_cache_table_alloc(void);
void rbtree_cache_table_free(struct rbtree_cache_table *table);

struct rbtree_cache_node *lookup(struct rbtree_cache_table* table, uint32_t key);
int insert(struct rbtree_cache_table* table, uint32_t key, void *data);
void del(struct rbtree_cache_table* table, uint32_t key);

/**
 * hashtable general api
 * */
struct yulong_hlist_head{
    struct hlist_head head;
    struct mutex lock;
};
static inline void __yulong_hash_init(struct yulong_hlist_head *ht, unsigned int sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++){
        INIT_HLIST_HEAD(&ht[i].head);
        mutex_init(&ht[i].lock);
    }

}

#define YULONG_DECLARE_HASHTABLE(name, bits) struct yulong_hlist_head name[1 << (bits)]
#define yulong_hash_init(hashtable) __yulong_hash_init(hashtable, HASH_SIZE(hashtable))
enum entry_flag{
    FLAG_LOGIN = 1,
    FLAG_NEW = 2,
};

// for login cache
struct login_key{
    pid_t pid;
    uint32_t daddr;
    uint16_t dest;
    uint8_t protocol;
};
struct identity_info{
    uint32_t sid, code;
    unsigned char otp_key[OTP_KEY_LEN + 1];
};
struct login_hashtable_entry{
    struct hlist_node hnode;
    struct login_key key;
    struct identity_info identity;
};
struct login_hashtable{
    DECLARE_HASHTABLE(hashtable, 10);
    siphash_key_t key;
    struct mutex lock;
    void(*add)(struct login_hashtable*, struct login_hashtable_entry*);
    struct login_hashtable_entry* (*lookup)(struct login_hashtable*, pid_t, uint32_t, uint16_t,uint8_t);
};
struct login_hashtable* login_hashtable_alloc(void);
void login_hashtable_add(struct login_hashtable *table, struct login_hashtable_entry *entry);
struct login_hashtable_entry* login_hashtable_lookup(struct login_hashtable* table, pid_t pid,
        uint32_t daddr, uint16_t dest, uint8_t protocol);

struct identity_key{
    uint32_t saddr, daddr;
    uint16_t source, dest;
    uint8_t protocol;
};
struct identity_entry{
    struct hlist_node hnode;
    struct identity_key key;
    struct identity_info leaf;
    //struct identity_info node;
    uint64_t timestamp;
    enum protocol_type type;
};
struct identity_hashtable{
    DECLARE_HASHTABLE(hashtable, 15);
    siphash_key_t key;
    char name[64];
    //struct mutex lock;
    rwlock_t lock;
    uint64_t size;
    void (*add)(struct identity_hashtable *table, struct identity_entry *entry);
    struct identity_entry* (*lookup)(struct identity_hashtable *table,
            uint32_t, uint32_t, uint16_t, uint16_t, uint8_t);
};

struct identity_hashtable* identity_hashtable_alloc(const char *name);
void identity_hashtable_add(struct identity_hashtable *table, struct identity_entry *entry);
struct identity_entry* identity_hashtable_lookup(struct identity_hashtable *table, uint32_t saddr,uint32_t daddr,
        uint16_t source, uint16_t dest, uint8_t protocol);

struct permission_entry{
    struct hlist_node hnode;
    struct identity_key key;
    enum acl a;
    uint64_t timestamp;
};
struct dacs_permission_table{
    DECLARE_HASHTABLE(hashtable, 15);
    siphash_key_t key;
    char name[64];
    rwlock_t lock;
    uint64_t size;
    void (*add)(struct dacs_permission_table *table, struct permission_entry *entry);
    struct permission_entry* (*lookup)(struct dacs_permission_table *table,
                                     uint32_t, uint32_t, uint16_t, uint16_t, uint8_t);
};
struct dacs_permission_table* dacs_permission_hashtable_alloc(const char *name);
void dacs_permission_hashtable_add(struct dacs_permission_table *table, struct permission_entry *entry);
struct permission_entry* dacs_permission_hashtable_lookup(struct dacs_permission_table *table, uint32_t saddr,uint32_t daddr,
                                                 uint16_t source, uint16_t dest, uint8_t protocol);

int cache_common_init(void);
void cache_common_exit(void);

#endif //YULONG_KM_CACHE_COMMON_H
