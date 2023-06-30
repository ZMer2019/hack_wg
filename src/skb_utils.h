//
// Created by edward on 23-6-30.
//

#ifndef YULONG_KM_SKB_UTILS_H
#define YULONG_KM_SKB_UTILS_H

#include <linux/socket.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>
#include <linux/inet.h>


#define LOGI(fmt, ...) pr_info("[%s:%u]" fmt , __FUNCTION__, __LINE__,##__VA_ARGS__)
#define L3_TOT_LEN_OFFSET   (0 + offsetof(struct iphdr, tot_len))
#define L3_CSUM_OFFSET   (0 + offsetof(struct iphdr, check))
#define L3_DADDR_OFFSET     (0 + offsetof(struct iphdr, daddr))
#define L3_SADDR_OFFSET     (0 + offsetof(struct iphdr, saddr))

int skb_adjust_room(struct sk_buff *skb, s32 len_diff);
int skb_store_bytes(struct sk_buff *skb, u32 offset,
                    const void * from, u32 len);
int skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len);
int l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags);
void print_binary(const char *data, int len, const char *func, int line);

#endif //YULONG_KM_SKB_UTILS_H
