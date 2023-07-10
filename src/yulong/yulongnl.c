//
// Created by edward on 23-7-5.
//

#include "yulongnl.h"
#include "log.h"
#include "netlink.h"
#include "uapi/wireguard.h"
#include "sys_wait.h"
static atomic_t _login_request_seq = ATOMIC_INIT(0);
int netlink_login_request(pid_t pid, uint64_t start_time,
                          uint16_t source, uint32_t daddr, uint16_t dest,uint8_t protocol,
                          pid_t comm_pid){
    struct sk_buff *skb;
    size_t size;
    void *head;
    int err;
    int request_seq = atomic_inc_return(&_login_request_seq);
    size = nla_total_size(sizeof(pid_t) + sizeof(uint64_t) +
                          sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t)+
                          sizeof(uint8_t) + sizeof(int));
    skb = genlmsg_new(size, GFP_KERNEL);
    if(!skb){
        LOGE("allocate skb error\n");
        return -ENOMEM;
    }
    head = genlmsg_put(skb, comm_pid, 0, &genl_family, 0, WG_CMD_HOOK_LOGIN_REQUEST);

    if(!head){
        LOGE("genlmsg_put failed\n");
        kfree_skb(skb);
        return -ENOMEM;
    }
    do{
        err = nla_put_u32(skb, WGACL_A_PID, pid);
        if(err != 0){
            break;
        }
        err = nla_put_u64_64bit(skb, WGACL_A_STARTTIME, start_time, 0);
        if(err != 0){
            break;
        }
        err = nla_put_u32(skb, WGACL_A_DST_IP, daddr);
        if(err != 0){
            break;
        }
        err = nla_put_u16(skb, WGACL_A_DST_PORT, dest);
        if(err != 0){
            break;
        }
        err = nla_put_u16(skb, WGACL_A_SRC_PORT, source);
        if(err != 0){
            break;
        }
        err = nla_put_u8(skb, WGACL_A_PROTOCOL, protocol);
        if(err != 0){
            break;
        }
        err = nla_put_s32(skb, WGACL_A_SEQ, request_seq);
        if(err != 0){
            break;
        }
    } while (0);
    if(err != 0){
        LOGE("make msg error\n");
        kfree_skb(skb);
        return err;
    }
    head = genlmsg_data(nlmsg_data(nlmsg_hdr(skb)));
    genlmsg_end(skb, head);
    err = genlmsg_unicast(&init_net, skb, comm_pid);
    if(err < 0){
        LOGE("genlmsg_unicast error[%d], yulong_pid[%d]\n", err, comm_pid);
        return err;
    }
    LOGI("netlink login request, comm_pid[%d]\n", comm_pid);
    login_wait(request_seq);
    return 0;
}