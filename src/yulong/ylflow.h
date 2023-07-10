//
// Created by root on 5/25/23.
//

#ifndef YULONG_KM_YLFLOW_H
#define YULONG_KM_YLFLOW_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

struct ylflow_node{
    u8 __rcu *flag;
    struct ylflow_node __rcu *bit[2];
    u8 cidr, bit_at_a, bit_at_b, bitlen;
    u8 bits[16] __aligned(__alignof(u64));

    unsigned long parent_bit_packed;

    struct rcu_head rcu;

};
struct ylflow_table{
    struct ylflow_node __rcu *root4;
    u64 seq;
    int (*insert)(struct ylflow_table *table,
                  const struct in_addr *ip, u8 cidr, struct mutex *lock);
    bool (*lookup)(struct ylflow_table *table, u32 daddr);
}__aligned(4);

struct ylflow_table* ylflow_table_alloc(void);
void ylflow_table_free(struct ylflow_table *table, struct mutex *lock);



#endif //YULONG_KM_YLFLOW_H
