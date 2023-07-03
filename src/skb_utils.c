//
// Created by edward on 23-6-30.
//

#include "skb_utils.h"


static int skb_generic_push(struct sk_buff *skb, u32 off, u32 len){
    skb_push(skb, len);
    memmove(skb->data, skb->data + len, off);
    memset(skb->data + off, 0, len);
    return 0;
}

static int skb_net_hdr_push(struct sk_buff *skb, u32 off, u32 len){
    bool trans_same = skb->transport_header == skb->network_header;
    int ret;

    ret = skb_generic_push(skb, off, len);
    if(likely(!ret)){
        skb->mac_header -= len;
        skb->network_header -= len;
        if(trans_same)
            skb->transport_header = skb->network_header;
    }
    return ret;
}

static u32 skb_net_base_len(const struct sk_buff *skb){
    switch (skb_protocol(skb, true)) {
        case htons(ETH_P_IP):
            return sizeof(struct iphdr);
        case htons(ETH_P_IPV6):
            return sizeof(struct ipv6hdr);
        default:
            return ~0U;
    }
}
static int skb_net_grow(struct sk_buff *skb, u32 len_diff){
    u32 off = skb_mac_header_len(skb) + skb_net_base_len(skb);
    int ret;

    if(skb_is_gso(skb) && !skb_is_gso_tcp(skb))
        return -ENOTSUPP;

    ret = skb_cow(skb, len_diff);
    if(unlikely(ret < 0))
        return ret;

    ret = skb_net_hdr_push(skb, off, len_diff);
    if(unlikely(ret < 0))
        return ret;

    if(skb_is_gso(skb)){
        struct skb_shared_info *shinfo = skb_shinfo(skb);
        skb_decrease_gso_size(shinfo, len_diff);
        shinfo->gso_type |= SKB_GSO_DODGY;
        shinfo->gso_segs = 0;
    }
    return 0;
}

static int skb_generic_pop(struct sk_buff *skb, u32 off, u32 len){
    if(unlikely(!pskb_may_pull(skb, off + len)))
        return -ENOMEM;

    skb_postpull_rcsum(skb, skb->data + off, len);
    memmove(skb->data + len, skb->data, off);
    __skb_pull(skb, len);
    return 0;
}

static int skb_net_hdr_pop(struct sk_buff *skb, u32 off, u32 len){
    bool trans_same = skb->transport_header == skb->network_header;
    int ret;

    ret = skb_generic_pop(skb, off, len);
    if(likely(!ret)){
        skb->mac_header += len;
        skb->network_header += len;
        if(trans_same)
            skb->transport_header = skb->network_header;
    }
    return ret;
}
static int skb_net_shrink(struct sk_buff *skb, u32 len_diff){
    u32 off = skb_mac_header_len(skb) + skb_net_base_len(skb);
    int ret;

    if(skb_is_gso(skb) && !skb_is_gso_tcp(skb))
        return -ENOTSUPP;
    ret = skb_unclone(skb, GFP_KERNEL);
    if(unlikely(ret < 0))
        return ret;

    ret = skb_net_hdr_pop(skb, off, len_diff);
    if(unlikely(ret < 0))
        return ret;

    if(skb_is_gso(skb)){
        struct skb_shared_info *shinfo = skb_shinfo(skb);
        skb_increase_gso_size(shinfo, len_diff);
        shinfo->gso_type |= SKB_GSO_DODGY;
        shinfo->gso_segs = 0;
    }
    return 0;
}
int skb_adjust_room(struct sk_buff *skb, s32 len_diff){
    bool trans_same = skb->transport_header == skb->network_header;
    u32 len_cur, len_diff_abs = abs(len_diff);
    u32 len_min = skb_net_base_len(skb);
    u32 len_max = SKB_MAX_ALLOC;
    __be16 proto = skb_protocol(skb, true);
    bool shrink = len_diff < 0;
    int ret;

    if(unlikely(len_diff_abs > 0xfffU))
        return -EFAULT;
    if(unlikely(proto != htons(ETH_P_IP) && proto != htons(ETH_P_IPV6)))
        return -ENOTSUPP;

    len_cur = skb->len - skb_network_offset(skb);

    if(skb_transport_header_was_set(skb) && !trans_same)
        len_cur = skb_network_header_len(skb);
    if ((shrink && (len_diff_abs >= len_cur ||
                    len_cur - len_diff_abs < len_min)) ||
        (!shrink && (skb->len + len_diff_abs > len_max &&
                     !skb_is_gso(skb))))
        return -ENOTSUPP;

    ret = shrink ? skb_net_shrink(skb, len_diff_abs) : skb_net_grow(skb, len_diff_abs);
    return ret;
}

static inline int try_make_writable(struct sk_buff *skb, unsigned int write_len){
    return skb_ensure_writable(skb, write_len);
}

int skb_store_bytes(struct sk_buff *skb, u32 offset,
                           const void * from, u32 len){
    void *ptr;

    if(unlikely(offset > INT_MAX))
        return -EFAULT;

    if(unlikely(try_make_writable(skb, offset + len)))
        return -EFAULT;

    ptr = skb->data + offset;

    memcpy(ptr, from, len);
    return 0;
}

int skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len){
    void *ptr;
    if(unlikely(offset > INT_MAX))
        goto err_clear;
    ptr = skb_header_pointer(skb, offset, len, to);
    if(unlikely(!ptr))
        goto err_clear;
    if(ptr != to)
        memcpy(to, ptr, len);
    return 0;
    err_clear:
    memset(to, 0, len);
    return -EFAULT;
}

#define HDR_FIELD_MASK  0xfULL
int l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags){
    __sum16 *ptr;

    if(unlikely(flags & ~(HDR_FIELD_MASK)))
        return -EINVAL;
    if(unlikely(offset > 0xffff || offset &1))
        return -EINVAL;
    if(unlikely(try_make_writable(skb, offset + sizeof(*ptr))))
        return -EFAULT;
    ptr = (__sum16*)(skb->data + offset);
    switch (flags & HDR_FIELD_MASK) {
        case 0:
            if(unlikely(from != 0))
                return -EINVAL;
            csum_replace_by_diff(ptr, to);
            break;
        case 2:
            csum_replace2(ptr, from, to);
            break;
        case 4:
            csum_replace4(ptr, from, to);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}
int l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags){
    bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
    bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
    bool do_mforce = flags & BPF_F_MARK_ENFORCE;
    __sum16 *ptr;
    if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE |
                           BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK)))
        return -EINVAL;
    if (unlikely(offset > 0xffff || offset & 1))
        return -EFAULT;
    if (unlikely(try_make_writable(skb, offset + sizeof(*ptr))))
        return -EFAULT;
    ptr = (__sum16 *)(skb->data + offset);
    if (is_mmzero && !do_mforce && !*ptr)
        return 0;
    switch (flags & BPF_F_HDR_FIELD_MASK) {
        case 0:
            if (unlikely(from != 0))
                return -EINVAL;

            inet_proto_csum_replace_by_diff(ptr, skb, to, is_pseudo);
            break;
        case 2:
            inet_proto_csum_replace2(ptr, skb, from, to, is_pseudo);
            break;
        case 4:
            inet_proto_csum_replace4(ptr, skb, from, to, is_pseudo);
            break;
        default:
            return -EINVAL;
    }

    if (is_mmzero && !*ptr)
        *ptr = CSUM_MANGLED_0;
    return 0;
}
void print_binary(const char *data, int len, const char *func, int line){
    int i;
    uint8_t *tmp = NULL;
    if(tmp == NULL){
        tmp = kzalloc(102400,GFP_KERNEL);
        if(tmp == NULL){
            return;
        }
    }
    //uint8_t tmp[1024] = {0};
    for(i = 0; i < len; i++){
        sprintf(tmp + 2*i,"%02X", (uint8_t)data[i]);
    }
    tmp[2*i] = 0;
    pr_info("[%s:%d]len=%d, %s\n", func, line,len,tmp);
    kfree(tmp);
}

static __be32 package_opt_sid(u16 sid){
    __be32 value;
    struct opt_sid os;
    os.type = IPOPT_SID;
    os.length = 4;
    os.sid = sid;
    value = *(uint32_t*)&os;
    value = htonl(value);
    //LOGI("%02X\n", value);
    return value;
}

bool add_ip_options(struct sk_buff *skb,int ip_offset, u16 sid, enum options_type type){
    struct iphdr ip;
    struct iphdr *ip_ptr = NULL;
    int options_offset = 0;
    uint16_t old_tot_len, new_tot_len;
    uint8_t header_len, tmp;
    uint16_t old_header, new_header;
    __be32 old_daddr, new_daddr, target;
    __be32 value = 0;
    switch (type) {
        case OPT_TYPE_SID:
            value = package_opt_sid(sid);
            break;
        default:
            break;
    }
    target = in_aton("192.168.31.47");
    new_daddr = in_aton("10.50.0.2");
    if(skb_load_bytes(skb, ip_offset, &tmp, sizeof(uint8_t)) < 0){
        LOGI("load byte failed\n");
        return false;
    }
    if(skb_load_bytes(skb, ip_offset, &old_header, sizeof(uint16_t)) < 0){
        LOGI("load byte failed\n");
        return false;
    }
    if(skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        LOGI("load byte failed\n");
        return false;
    }
    old_daddr = ip.daddr;
    header_len = ip.ihl;
    if(header_len == 6){
        return true;
    }
    if(old_daddr != target){
        return false;
    }
    options_offset = ip_offset + (header_len << 2);
    old_tot_len = ntohs(ip.tot_len);
    if(skb_adjust_room(skb, 4) < 0){
        LOGI("extend room failed\n");
        return false;
    }
    new_tot_len = old_tot_len + 4;
    new_tot_len = htons(new_tot_len);
    old_header = ntohs(old_header);
    new_header = old_header & 0xF0FF;
    header_len += 1;
    tmp = tmp & 0xF0;
    tmp += header_len;
    new_header = (tmp << 8) | new_header;
    new_header = htons(new_header);
    old_header = htons(old_header);
    skb_store_bytes(skb, options_offset, &value, sizeof(uint32_t));
    skb_store_bytes(skb, L3_TOT_LEN_OFFSET, &new_tot_len, sizeof(uint16_t));
    skb_store_bytes(skb, ip_offset, &new_header, sizeof(uint16_t));
    skb_store_bytes(skb, L3_DADDR_OFFSET, &new_daddr, sizeof(__be32));
    ip_ptr = (struct iphdr*)(skb->data + ip_offset);
    ip_send_check(ip_ptr);
    print_binary(skb->data, skb->len, __FUNCTION__ , __LINE__);
    return true;
}
bool do_nat(struct sk_buff *skb){
    struct iphdr *ip = (struct iphdr*)skb->data;
    __be32 target = in_aton("192.168.31.47");
    __be32 new_saddr = in_aton("10.50.0.2");
    if(ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP){
        return true;
    }
    if(ip->saddr == target){
        skb_store_bytes(skb, L3_SADDR_OFFSET, &new_saddr, sizeof(__be32));
        ip_send_check(ip);
    }
    return true;
}
static uint32_t virtual_local_ip;
void set_virtual_local_ip(uint32_t local){
    virtual_local_ip = local;
}
uint32_t get_virtual_local_ip(void){
    return virtual_local_ip;
}