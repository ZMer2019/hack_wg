/************************************************************
    > File Name: sendto.c
    > Author: yuemingxing
    > Mail: yuemingxing@datacloak.com
    > Create Time: 2022-08-23 11:44:59
**************************************************************/

#include "hook.h"
#include "yulongnl.h"
#include "log.h"
#include "cache_common.h"
#include "hook_common.h"
PT_REGS_SYSCALL_FUNC syscall_original_sendto;

void switch_hooked_sendto(struct system_map *org_system_call_table){
    syscall_original_sendto = (void*)(org_system_call_table->addr)[__NR_sendto];
    disable_write_protection();
    (org_system_call_table->addr)[__NR_sendto] = (unsigned long) hooked_sendto;
    enable_write_protection();
    LOGI("hook sendto success, table addr:%p, org_sendto addr:%p, hooked socket addr:%p",
         org_system_call_table->addr, syscall_original_sendto, hooked_sendto);
}
void switch_org_sendto(struct system_map *org_system_call_table){
    if(syscall_original_sendto!= NULL){
        disable_write_protection();
        (org_system_call_table->addr)[__NR_sendto] = (unsigned long)syscall_original_sendto;
        enable_write_protection();
        LOGI("unhooked sendto success, table addr:%p, org_socket addr:%p, hooked socket addr:%p",
             org_system_call_table->addr, syscall_original_sendto, hooked_sendto);
    }
}

asmlinkage long hooked_sendto(const struct pt_regs* res){
    int fd;
    struct sockaddr* dest_addr = NULL;
    int dest_addr_len = 0;
    int type;
    struct sockaddr_storage addr_storage;
    struct sockaddr_in *addr_in = NULL;
    struct socket *sock = NULL;
    struct fd f;
    struct sock *sk = NULL;
    int prepare_ret;
    struct net_tuple tuple;

    //unsigned char *p = NULL;
    struct login_hashtable_entry *login_entry = NULL;
    struct identity_entry *entry = NULL;
    pid_t tgid;
    if(app_bypass(current->comm) || !context()->enable_hook){

        return syscall_original_sendto(res);
    }
    do{
        tgid = current->tgid;
        if(unlikely(current->tgid == get_yulongd_pid())){
            break;
        }
        fd = GET_ARG_FROM_REGS(res, int, 0);
        type = get_socket_type_by_fd(fd);
        if((type & SOCK_STREAM) != SOCK_STREAM && (type & SOCK_DGRAM) != SOCK_DGRAM){
            break;
        }
        dest_addr = GET_ARG_FROM_REGS(res, struct sockaddr*, 4);
        dest_addr_len = GET_ARG_FROM_REGS(res, unsigned int, 5);
        if(dest_addr == NULL){
            //if((type & SOCK_DGRAM) == SOCK_DGRAM){
            //    break;
            //}
            break;
        }
        if(!(copy_user_addr(dest_addr, dest_addr_len, &addr_storage))){
            HOOK_LOGE("copy dest addr failed\n");
            break;
        }
        addr_in = (struct sockaddr_in*)&addr_storage;
        if(addr_in->sin_family != AF_INET){
            break;
        }
        f = fdget(fd);
        sock = dacs_sock_from_file(f.file);
        if(sock == NULL){
            fdput(f);
            break;
        }
        sk = sock->sk;
        prepare_ret = inet_autobind(sk);
        fdput(f);
        if(prepare_ret != 0){
            break;
        }
        tuple.source = ((struct inet_sock*)sk)->inet_num;
        tuple.dest = ntohs(addr_in->sin_port);
        tuple.saddr = wg_virtual_local_addr();
        tuple.daddr = be32_to_cpu(addr_in->sin_addr.s_addr);
        if((type & SOCK_STREAM) == SOCK_STREAM){
            tuple.protocol = IPPROTO_TCP;
        }else if((type & SOCK_DGRAM) == SOCK_DGRAM){
            tuple.protocol = IPPROTO_UDP;
        }
        if(!context()->flow_table->lookup(context()->flow_table, addr_in->sin_addr.s_addr)){
            break;
        }
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
    }while(0);
    return syscall_original_sendto(res);
}