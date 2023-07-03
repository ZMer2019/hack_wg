//
// Created by edward on 23-7-3.
//

#ifndef YULONG_KM_CACHE_COMMON_H
#define YULONG_KM_CACHE_COMMON_H

#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/siphash.h>
#include <linux/skbuff.h>
#include <linux/inet.h>


struct identity_key{
    uint32_t saddr, daddr;
    uint16_t source, dest;
    uint8_t protocol;
};

struct identity_entry{
    struct hlist_node hnode;
    struct identity_key key;
    uint32_t sid;
    uint32_t real_daddr;
};

struct identity_hastable{
    DECLARE_HASHTABLE(hashtable, 15);
    siphash_key_t key;
    rwlock_t lock;
    void(*add)(struct identity_hastable *table, struct identity_entry *entry);
    struct identity_entry* (*lookup)(struct identity_hastable *table,
            uint32_t saddr, uint32_t daddr, uint16_t source, uint16_t dest, uint8_t protocol);
};

struct identity_hastable* identity_hashtable_alloc(void);
void identity_hashtable_add(struct identity_hastable *table,
        struct identity_entry *entry);
struct identity_entry* identity_hashtable_lookup(struct identity_hastable *table,
                                                 uint32_t saddr, uint32_t daddr,
                                                 uint16_t source, uint16_t dest, uint8_t protocol);


#endif //YULONG_KM_CACHE_COMMON_H
