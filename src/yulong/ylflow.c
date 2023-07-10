//
// Created by root on 5/25/23.
//

#include "ylflow.h"
#include <linux/memory.h>
#include <linux/slab.h>

static struct kmem_cache* flow_node_cache;
static void swap_endian(u8 *dst, const u8 *src, u8 bits)
{
    if (bits == 32) {
        *(u32 *)dst = be32_to_cpu(*(const __be32 *)src);
    } else if (bits == 128) {
        ((u64 *)dst)[0] = be64_to_cpu(((const __be64 *)src)[0]);
        ((u64 *)dst)[1] = be64_to_cpu(((const __be64 *)src)[1]);
    }
}

static void copy_and_assign_cidr(struct ylflow_node *node,
                                 const u8 *src,
                                 u8 cidr, u8 bits){
    node->cidr = cidr;
    node->bit_at_a = cidr / 8U;
#ifdef __LITTLE_ENDIAN
    node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
    node->bit_at_b = 7U - (cidr % 8U);
    node->bitlen = bits;
    memcpy(node->bits, src, bits / 8U);
}
static inline void connect_node(struct ylflow_node __rcu **parent,
        u8 bit, struct ylflow_node *node){
    node->parent_bit_packed = (unsigned long)parent | bit;
    rcu_assign_pointer(*parent, node);
}
static unsigned int fls128(u64 a, u64 b)
{
    return a ? fls64(a) + 64U : fls64(b);
}
static inline u8 choose(struct ylflow_node *node, const u8 *key)
{
    return (key[node->bit_at_a] >> node->bit_at_b) & 1;
}
static u8 common_bits(const struct ylflow_node *node, const u8 *key,
                      u8 bits)
{
    if (bits == 32)
        return 32U - fls(*(const u32 *)node->bits ^ *(const u32 *)key);
    else if (bits == 128)
        return 128U - fls128(
                *(const u64 *)&node->bits[0] ^ *(const u64 *)&key[0],
                *(const u64 *)&node->bits[8] ^ *(const u64 *)&key[8]);
    return 0;
}
static bool prefix_matches(const struct ylflow_node *node, const u8 *key,
        u8 bits){
    return common_bits(node, key, bits) >= node->cidr;
}
static bool node_placement(struct ylflow_node __rcu *trie,
                           const u8 *key,
                           u8 cidr, u8 bits, struct ylflow_node **rnode,
                           struct mutex *lock){
    struct ylflow_node *node = rcu_dereference_protected(trie, lockdep_is_held(lock));
    struct ylflow_node *parent = NULL;
    bool exact = false;
    while(node && node->cidr <= cidr && prefix_matches(node, key, bits)){
        parent = node;
        if(parent->cidr == cidr){
            exact = true;
            break;
        }
        node = rcu_dereference_protected(parent->bit[choose(parent, key)],
                                         lockdep_is_held(lock));
    }
    *rnode = parent;
    return exact;
}
static inline void choose_and_connect_node(struct ylflow_node *parent, struct ylflow_node *node)
{
    u8 bit = choose(parent, node->bits);
    connect_node(&parent->bit[bit], bit, node);
}
static int node_add(struct ylflow_node __rcu **trie,
        u8 bits, const u8 *key, u8 cidr, struct mutex *lock){
    struct ylflow_node *node, *parent, *down, *newnode;
    u8 *flag = kzalloc(sizeof(u8), GFP_KERNEL);
    if(unlikely(!flag)){
        return -ENOMEM;
    }
    if(unlikely(cidr > bits)){
        return -EINVAL;
    }
    if(!rcu_access_pointer(*trie)){
        node = kmem_cache_zalloc(flow_node_cache, GFP_KERNEL);
        if(unlikely(!node)){
            return -ENOMEM;
        }
        RCU_INIT_POINTER(node->flag, flag);
        copy_and_assign_cidr(node, key, cidr, bits);
        connect_node(trie, 2, node);
        return 0;
    }
    if(node_placement(*trie, key, cidr, bits, &node, lock)){
        rcu_assign_pointer(node->flag, flag);
        return 0;
    }
    newnode = kmem_cache_zalloc(flow_node_cache, GFP_KERNEL);
    if(unlikely(!newnode)){
        return -ENOMEM;
    }
    RCU_INIT_POINTER(newnode->flag, flag);
    copy_and_assign_cidr(newnode, key, cidr, bits);
    if(!node){
        down = rcu_dereference_protected(*trie, lockdep_is_held(lock));
    }else{
        const u8 bit = choose(node, key);
        down = rcu_dereference_protected(node->bit[bit], lockdep_is_held(lock));
        if (!down) {
            connect_node(&node->bit[bit], bit, newnode);
            return 0;
        }
    }
    cidr = min(cidr, common_bits(down, key, bits));
    parent = node;

    if (newnode->cidr == cidr) {
        choose_and_connect_node(newnode, down);
        if (!parent)
            connect_node(trie, 2, newnode);
        else
            choose_and_connect_node(parent, newnode);
        return 0;
    }
    node = kmem_cache_zalloc(flow_node_cache, GFP_KERNEL);
    if(unlikely(!node)){
        kfree(flag);
        kmem_cache_free(flow_node_cache, newnode);
        return -ENOMEM;
    }
    copy_and_assign_cidr(node, newnode->bits, cidr, bits);

    choose_and_connect_node(node, down);
    choose_and_connect_node(node, newnode);
    if (!parent)
        connect_node(trie, 2, node);
    else
        choose_and_connect_node(parent, node);
    return 0;
}
static int ylflow_insert_v4(struct ylflow_table *table,
                            const struct in_addr *ip, u8 cidr, struct mutex *lock){
    u8 key[4] __aligned(__alignof(u32));
    ++table->seq;
    swap_endian(key, (const u8*)ip, 32);
    return node_add(&table->root4, 32, key, cidr, lock);
}
static struct ylflow_node *find_node(struct ylflow_node *trie, u8 bits,
                                         const u8 *key)
{
    struct ylflow_node *node = trie, *found = NULL;

    while (node && prefix_matches(node, key, bits)) {
        if (rcu_access_pointer(node->flag))
            found = node;
        if (node->cidr == bits)
            break;
        node = rcu_dereference_bh(node->bit[choose(node, key)]);
    }
    return found;
}
static bool lookup(struct ylflow_node __rcu *root, u8 bits, const void *be_ip){
    u8 ip[16] __aligned(__alignof(u64));
    struct ylflow_node *node;
    u8 *flag = NULL;
    bool found = false;
    swap_endian(ip, be_ip, bits);
    rcu_read_lock_bh();
retry:
    node = find_node(rcu_dereference_bh(root), bits, ip);
    if(node){
        flag = rcu_dereference_bh(node->flag);
        if(!flag){
            goto retry;
        }
    }
    rcu_read_unlock_bh();
    if(flag){
        found = true;
    }
    return found;
}
static bool ylflow_lookup(struct ylflow_table *table,u32 be_ip){
    return lookup(table->root4, 32, &be_ip);
}
struct ylflow_table* ylflow_table_alloc(void){
    struct ylflow_table *table = kzalloc(sizeof(struct ylflow_table), GFP_KERNEL);
    if(!table){
        return NULL;
    }
    table->root4 = NULL;
    table->insert = ylflow_insert_v4;
    table->lookup = ylflow_lookup;
    table->seq = 1;
    flow_node_cache = KMEM_CACHE(ylflow_node, 0);
    if(!flow_node_cache){
        kfree(table);
        table = NULL;
        return NULL;
    }
    return table;
}
static void push_rcu(struct ylflow_node **stack,
                     struct ylflow_node __rcu *p, unsigned int *len)
{
    if (rcu_access_pointer(p)) {
        WARN_ON(IS_ENABLED(DEBUG) && *len >= 128);
        stack[(*len)++] = rcu_dereference_raw(p);
    }
}
static void root_free_rcu(struct rcu_head *rcu){
    struct ylflow_node *node, *stack[128] = {
            container_of(rcu, struct ylflow_node, rcu)
    };
    unsigned int len = 1;
    while(len > 0 && (node = stack[--len])){
        push_rcu(stack, node->bit[0], &len);
        push_rcu(stack, node->bit[1], &len);
        kmem_cache_free(flow_node_cache, node);
    }
}
void ylflow_table_free(struct ylflow_table *table, struct mutex *lock){
    struct ylflow_node __rcu *old4 = table->root4;
    ++table->seq;
    RCU_INIT_POINTER(table->root4, NULL);
    if(rcu_access_pointer(old4)){
        struct ylflow_node *node = rcu_dereference_protected(old4,
                lockdep_is_held(lock));
        call_rcu(&node->rcu, root_free_rcu);
    }
    rcu_barrier();
    kmem_cache_destroy(flow_node_cache);
}

