/****************************************************************************************
    > File Name: connect.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 16:05:26
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/


#include "hook.h"
#include "hook_common.h"
#include "log.h"
#include "yulongnl.h"
#include "yulong.h"
PT_REGS_SYSCALL_FUNC sys_org_connect;

void switch_hooked_connect(struct system_map *org_system_call_table) {
    sys_org_connect = (void *)(org_system_call_table->addr)[__NR_connect];
    disable_write_protection();
    (org_system_call_table->addr)[__NR_connect] = (unsigned long)hooked_connect;
    enable_write_protection();
#if 0
    printk(KERN_INFO "hooked connect success, table addr:%p, org_connect addr:%p, hooked connect addr:%p",
           org_system_call_table->addr, sys_org_connect, hooked_connect);
#endif
}

void switch_org_connect(struct system_map *org_system_call_table) {
    if (sys_org_connect != NULL) {
        disable_write_protection();
        (org_system_call_table->addr)[__NR_connect] = (unsigned long)sys_org_connect;
        enable_write_protection();
#if 0
        printk(KERN_INFO "unhooked connect success, table addr:%p, org_connect addr:%p, hooked connect addr:%p",
               org_system_call_table->addr, sys_org_connect, hooked_connect);
#endif
    }
}

asmlinkage long hooked_connect(const struct pt_regs* res){
    int fd;
    int type;
    int prepare_ret;
    unsigned int uaddr_len;
    struct net_tuple tuple = {0};
    struct sockaddr *uaddr = NULL;
    struct sockaddr_in *addr_in = NULL;
    struct socket *sock = NULL;
    struct sock *sk = NULL;
    struct fd f;
    struct sockaddr_storage addr;
    pid_t tgid;
    struct login_hashtable_entry *login_entry = NULL;
    struct identity_entry *entry = NULL;
    //int ret;
    //ktime_t start = 0, end = 0, interval = 0;

    if(app_bypass(current->comm) || !context()->enable_hook){
        return sys_org_connect(res);
    }

    do{
        fd = GET_ARG_FROM_REGS(res,int, 0);
        uaddr = GET_ARG_FROM_REGS(res,struct sockaddr *, 1);
        uaddr_len = GET_ARG_FROM_REGS(res,unsigned int, 2);

        // bypass yulongd
        tgid = current->tgid;
        if(unlikely(current->tgid == get_yulongd_pid())){
            break;
        }
        type = get_socket_type_by_fd(fd);
        if((type & SOCK_STREAM) != SOCK_STREAM && (type & SOCK_DGRAM) != SOCK_DGRAM){
            break;
        }

        if (uaddr == NULL) {
            break;
        }
        if(!copy_user_addr(uaddr, uaddr_len, &addr)) {
            break;
        }

        addr_in = (struct sockaddr_in *)&addr;
        if(AF_INET != addr_in->sin_family){
            break;
        }
        if(!context()->flow_table->lookup(context()->flow_table, addr_in->sin_addr.s_addr)){
            break;
        }
        f = fdget(fd);
        sock = dacs_sock_from_file(f.file);
        if (NULL == sock) {
            fdput(f);
            break;
        }
        sk = sock->sk;
        if (NULL == sk) {
            fdput(f);
            break;
        }
        sk->sk_prot->no_autobind = 0;
        prepare_ret = inet_autobind(sock->sk);
        fdput(f);
        if (0 != prepare_ret) {
            LOGE("[connect] inet_autobind failed, prepare_ret = %d", prepare_ret);
            break;
        }

        tuple.source = ((struct inet_sock *)sk)->inet_num;
        tuple.dest= ntohs(addr_in->sin_port);
        /**
         * todo: Check route table to set saddr
         * */
        tuple.saddr = wg_virtual_local_addr();
        tuple.daddr = __be32_to_cpu(addr_in->sin_addr.s_addr);
        if((type & SOCK_STREAM) == SOCK_STREAM){
            tuple.protocol = IPPROTO_TCP;
        }else if((type & SOCK_DGRAM) == SOCK_DGRAM){
            tuple.protocol = IPPROTO_UDP;
        }
        //start = ktime_get();
        login_entry = context()->login_hashtable->lookup(context()->login_hashtable, tgid, tuple.daddr, tuple.dest, tuple.protocol);
        if(!login_entry){
            netlink_login_request(tgid, 0, tuple.source, tuple.daddr,
                                        tuple.dest, tuple.protocol, get_yulongd_pid());
        }else{
            entry = context()->egress_id_hashtable->lookup(context()->egress_id_hashtable, wg_virtual_local_addr(), tuple.daddr, tuple.source,
                                                           tuple.dest, tuple.protocol);
            if(!entry){
                entry = kzalloc(sizeof(struct identity_entry), GFP_KERNEL);
                if(entry){
                    entry->key.saddr = wg_virtual_local_addr();
                    entry->key.daddr = tuple.daddr;
                    entry->key.source = tuple.source;
                    entry->key.dest = tuple.dest;
                    entry->key.protocol = tuple.protocol;
                    entry->leaf.sid = login_entry->identity.sid;
                    memcpy(entry->leaf.otp_key, login_entry->identity.otp_key, OTP_KEY_LEN);
                    context()->egress_id_hashtable->add(context()->egress_id_hashtable, entry);
                }
            }else{
                entry->leaf.sid = login_entry->identity.sid;
                entry->timestamp = ktime_to_timespec(ktime_get()).tv_sec;
            }
        }
    } while (0);

    return sys_org_connect(res);
}