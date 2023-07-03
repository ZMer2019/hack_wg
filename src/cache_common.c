//
// Created by edward on 23-7-3.
//

#include "cache_common.h"


struct identity_hastable* identity_hashtable_alloc(void){
    struct identity_hastable *table = kzalloc(sizeof(struct identity_hastable), GFP_KERNEL);
    if(!table){
        return NULL;
    }
    hash_init(table->hashtable);
    get_random_bytes(&table->key, sizeof(siphash_key_t));
    rwlock_init(&table->lock);
    table->add = identity_hashtable_add;
    table->lookup = identity_hashtable_lookup;
    return table;
}

static struct hlist_head* identity_bucket(struct identity_hastable *table,struct identity_key *key){
    u64 a, b, c, index, slot;
    a = (key->saddr << 16) + key->source;
    b = (key->daddr << 16) + key->dest;
    c = key->protocol;
    index = siphash_3u64(a, b, c, &table->key);
    slot = index % (HASH_SIZE(table->hashtable));
    return &table->hashtable[slot];
}

void identity_hashtable_add(struct identity_hastable *table,
                            struct identity_entry *entry){
    write_lock(&table->lock);
    hlist_add_head_rcu(&entry->hnode, identity_bucket(table, &entry->key));
    write_unlock(&table->lock);
}
struct identity_entry* identity_hashtable_lookup(struct identity_hastable *table,
                                                 uint32_t saddr, uint32_t daddr,
                                                 uint16_t source, uint16_t dest, uint8_t protocol){
    struct identity_entry *iter = NULL, *entry = NULL;
    struct identity_key key = {saddr, daddr, source, dest, protocol};
    read_lock(&table->lock);
    hlist_for_each_entry(iter, identity_bucket(table, &key), hnode){
        if(iter->key.saddr == key.saddr &&
        iter->key.daddr == key.daddr &&
        iter->key.source == key.source&&
        iter->key.dest == key.dest &&
        iter->key.protocol == key.protocol){
            entry = iter;
            break;
        }
    }
    read_unlock(&table->lock);
    return entry;
}