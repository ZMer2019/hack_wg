/******************************************************************
    > File Name: cache_common.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/17 17:04:35

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#include <linux/rcutree.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/ip.h>

#include "cache_common.h"
#include "log.h"
static struct kmem_cache *rbtree_node_kmem_cache;
struct rbtree_cache_table * rbtree_cache_table_alloc(void){
    struct rbtree_cache_table *table = kzalloc(sizeof(struct rbtree_cache_table), GFP_KERNEL);
    if(!table){
        LOGE("allocate memory error\n");
        return NULL;
    }
    table->root = RB_ROOT;
    rwlock_init(&table->lock);
    table->lookup = lookup;
    table->insert = insert;
    table->del = del;
    return table;
}
static void _delete(struct rb_node *node){
    struct rbtree_cache_node *tmp = NULL;
    if(node != NULL){
        _delete(node->rb_left);
        _delete(node->rb_right);
        tmp = rb_entry(node, struct rbtree_cache_node, node);
        if(rbtree_node_kmem_cache != NULL && tmp != NULL){
            if(tmp->data){
                kfree(tmp->data);
            }
            kmem_cache_free(rbtree_node_kmem_cache, tmp);
        }
        node = NULL;
    }
}

void rbtree_cache_table_free(struct rbtree_cache_table *table){
    write_lock(&table->lock);
    _delete(table->root.rb_node);
    write_unlock(&table->lock);
}

struct rbtree_cache_node *lookup(struct rbtree_cache_table* table, uint32_t key){
    struct rb_node *parent = NULL;
    struct rbtree_cache_node *iter = NULL, *result = NULL;
    parent = table->root.rb_node;
    read_lock(&table->lock);
    while (parent){
        iter = rb_entry(parent, struct rbtree_cache_node, node);
        if(key < iter->key){
            parent = parent->rb_left;
        }else if(key > iter->key){
            parent = parent->rb_right;
        }else{
            result = iter;
            break;
        }
    }
    read_unlock(&table->lock);
    return result;
}
int insert(struct rbtree_cache_table* table, uint32_t key, void *data){
    struct rb_node **p = &table->root.rb_node;
    struct rb_node *parent = NULL;
    struct rbtree_cache_node *temp = NULL;
    struct rbtree_cache_node *new = NULL;
    write_lock(&table->lock);
    while (*p != NULL){
        parent = *p;
        temp = rb_entry(parent, struct rbtree_cache_node, node);
        if(key < temp->key){
            p = &parent->rb_left;
        }else if(key > temp->key){
            p = &parent->rb_right;
        }else{
            if(data){
                if(temp->data){
                    kfree(temp->data);
                }
                temp->data = data;
            }
            write_unlock(&table->lock);
            return 0;
        }
    }
    new = kmem_cache_zalloc(rbtree_node_kmem_cache, GFP_KERNEL);
    if(new == NULL){
        write_unlock(&table->lock);
        LOGE("allocate memory failed\n");
        return -ENOMEM;
    }
    new->key = key;
    new->data = data;
    rb_link_node(&new->node, parent, p);
    rb_insert_color(&new->node, &table->root);
    write_unlock(&table->lock);
    return 0;
}
void del(struct rbtree_cache_table* table, uint32_t key){
    struct rb_node *parent = NULL;
    struct rbtree_cache_node *result = NULL;
    parent = table->root.rb_node;
    write_lock(&table->lock);
    while (parent){
        result = rb_entry(parent, struct rbtree_cache_node, node);
        if(key < result->key){
            parent = parent->rb_left;
        }else if(key > result->key){
            parent = parent->rb_right;
        }else{
            rb_erase(&result->node, &table->root);
            if(result->data){
                kfree(result->data);
            }
            kmem_cache_free(rbtree_node_kmem_cache, result);
            result = NULL;
            break;
        }
    }
    write_unlock(&table->lock);
}

struct login_hashtable* login_hashtable_alloc(void){
    struct login_hashtable* table = kvmalloc(sizeof(struct login_hashtable), GFP_KERNEL);
    if(!table){
        return NULL;
    }
    get_random_bytes(&table->key, sizeof(siphash_key_t));
    hash_init(table->hashtable);
    mutex_init(&table->lock);
    table->add = login_hashtable_add;
    table->lookup = login_hashtable_lookup;
    return table;
}
static struct hlist_head* login_bucket(struct login_hashtable *table, pid_t pid, uint32_t daddr, uint16_t dest, uint8_t protocol){
    uint64_t index = 0, slot;
    index = siphash_4u32(pid, daddr, dest,protocol, &table->key);
    slot = index % HASH_SIZE(table->hashtable);
    return &table->hashtable[slot];
}
void login_hashtable_add(struct login_hashtable *table, struct login_hashtable_entry *entry){
    mutex_lock(&table->lock);
    hlist_add_head_rcu(&entry->hnode,
                       login_bucket(table, entry->key.pid, entry->key.daddr, entry->key.dest, entry->key.protocol));
    mutex_unlock(&table->lock);
}
struct login_hashtable_entry* login_hashtable_lookup(struct login_hashtable* table, pid_t pid,
        uint32_t daddr, uint16_t dest, uint8_t protocol){
    struct login_hashtable_entry *iter = NULL, *entry = NULL;
    rcu_read_lock_bh();
    hlist_for_each_entry_rcu_bh(iter, login_bucket(table, pid, daddr, dest, protocol), hnode){
        if(pid == iter->key.pid && daddr == iter->key.daddr && dest == iter->key.dest && protocol == iter->key.protocol){
            entry = iter;
            break;
        }
    }
    rcu_read_unlock_bh();
    return entry;
}

struct identity_hashtable* identity_hashtable_alloc(const char *name){
    struct identity_hashtable *table = kzalloc(sizeof(struct identity_hashtable), GFP_KERNEL);
    if(!table){
        return NULL;
    }
    hash_init(table->hashtable);
    memcpy(table->name, name, sizeof(table->name)-1);
    get_random_bytes(&table->key, sizeof(siphash_key_t));
    //mutex_init(&table->lock);
    rwlock_init(&table->lock);
    table->size = 0;
    table->add = identity_hashtable_add;
    table->lookup = identity_hashtable_lookup;
    return table;
}
static struct hlist_head* identity_bucket(struct identity_hashtable *table, struct identity_key *key){
    u64 a, b, c, index, slot;
    a = (key->saddr << 16) + key->source;
    b = (key->daddr << 16) + key->dest;
    c = key->protocol;
    index = siphash_3u64(a, b, c, &table->key);
    slot = index % (HASH_SIZE(table->hashtable));
    return &table->hashtable[slot];
}
void identity_hashtable_add(struct identity_hashtable *table, struct identity_entry *entry){
    //mutex_lock(&table->lock);
    write_lock(&table->lock);
    hlist_add_head_rcu(&entry->hnode, identity_bucket(table, &entry->key));
    table->size++;
    //mutex_unlock(&table->lock);
#if 0
    if(table->size % 100 == 0){
        LOGI("%s[%llu]\n",table->name, table->size);
    }
#endif
    write_unlock(&table->lock);
}
struct identity_entry* identity_hashtable_lookup(struct identity_hashtable *table, uint32_t saddr,uint32_t daddr,
                                                 uint16_t source, uint16_t dest, uint8_t protocol){
    struct identity_entry *iter = NULL, *entry = NULL;
    struct identity_key key = {saddr, daddr, source, dest, protocol};
    //rcu_read_lock_bh();
    read_lock(&table->lock);
    hlist_for_each_entry(iter, identity_bucket(table, &key), hnode){
        if(iter->key.saddr == key.saddr &&
        iter->key.daddr == key.daddr &&
        iter->key.source == key.source &&
        iter->key.dest == key.dest&&
        iter->key.protocol == key.protocol){
            entry = iter;
            break;
        }
    }
    //rcu_read_unlock_bh();
    read_unlock(&table->lock);
    return entry;
}

struct dacs_permission_table* dacs_permission_hashtable_alloc(const char *name){
    struct dacs_permission_table *table = kzalloc(sizeof(struct dacs_permission_table), GFP_KERNEL);
    if(!table){
        return NULL;
    }
    hash_init(table->hashtable);
    memcpy(table->name, name, sizeof(table->name)-1);
    get_random_bytes(&table->key, sizeof(siphash_key_t));
    //mutex_init(&table->lock);
    rwlock_init(&table->lock);
    table->size = 0;
    table->add = dacs_permission_hashtable_add;
    table->lookup = dacs_permission_hashtable_lookup;
    return table;
}
static struct hlist_head* permission_bucket(struct dacs_permission_table *table, struct identity_key *key){
    u64 a, b, c, index, slot;
    a = (key->saddr << 16) + key->source;
    b = (key->daddr << 16) + key->dest;
    c = key->protocol;
    index = siphash_3u64(a, b, c, &table->key);
    slot = index % (HASH_SIZE(table->hashtable));
    return &table->hashtable[slot];
}
void dacs_permission_hashtable_add(struct dacs_permission_table *table, struct permission_entry *entry){
    write_lock(&table->lock);
    hlist_add_head_rcu(&entry->hnode, permission_bucket(table, &entry->key));
    table->size++;
    write_unlock(&table->lock);
}
struct permission_entry* dacs_permission_hashtable_lookup(struct dacs_permission_table *table, uint32_t saddr,uint32_t daddr,
                                                          uint16_t source, uint16_t dest, uint8_t protocol){
    struct permission_entry *iter = NULL, *entry = NULL;
    struct identity_key key = {saddr, daddr, source, dest, protocol};
    //rcu_read_lock_bh();
    read_lock(&table->lock);
    hlist_for_each_entry(iter, permission_bucket(table, &key), hnode){
        if(iter->key.saddr == key.saddr &&
           iter->key.daddr == key.daddr &&
           iter->key.source == key.source &&
           iter->key.dest == key.dest&&
           iter->key.protocol == key.protocol){
            entry = iter;
            break;
        }
    }
    //rcu_read_unlock_bh();
    read_unlock(&table->lock);
    return entry;
}
int cache_common_init(void){
    rbtree_node_kmem_cache = KMEM_CACHE(rbtree_cache_node, 0);
    if(!rbtree_node_kmem_cache){
        return -ENOMEM;
    }
    return 0;
}
void cache_common_exit(void){
    rcu_barrier();
    kmem_cache_destroy(rbtree_node_kmem_cache);
}