/****************************************************************************************
    > File Name: hook_common.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 16:03:16
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#ifndef YULONG_KM_HOOK_COMMON_H
#define YULONG_KM_HOOK_COMMON_H

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
/*
 * SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
 * */
#if 0
static char *SOCK_TYPE[] = {"UNKNOWN","SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW",
                            "SOCK_RDM", "SOCK_SEQPACKET", "SOCK_DCCP","","","",
                            "SOCK_PACKET"};

static char* socket_type(int type){
    if((type & SOCK_STREAM) == SOCK_STREAM){
        return SOCK_TYPE[SOCK_STREAM];
    }
    if((type & SOCK_DGRAM) == SOCK_DGRAM){
        return SOCK_TYPE[SOCK_DGRAM];
    }
    if((type & SOCK_RAW) == SOCK_RAW){
        return SOCK_TYPE[SOCK_RAW];
    }
    if((type & SOCK_RDM) == SOCK_RDM){
        return SOCK_TYPE[SOCK_RDM];
    }
    if((type & SOCK_SEQPACKET) == SOCK_SEQPACKET){
        return SOCK_TYPE[SOCK_SEQPACKET];
    }
    if((type & SOCK_DCCP) == SOCK_DCCP){
        return SOCK_TYPE[SOCK_DCCP];
    }
    if((type & SOCK_PACKET) == SOCK_PACKET){
        return SOCK_TYPE[SOCK_PACKET];
    }
    return SOCK_TYPE[0];
}
#endif
static bool copy_user_addr(void __user *uaddr, int ulen,
                           struct sockaddr_storage *kaddr) {
    if (ulen < 0 || ulen > sizeof(struct sockaddr_storage)) {
        return false;
    }
    if (ulen == 0) {
        return true;
    }
    if (copy_from_user(kaddr, uaddr, ulen)) {
        return false;
    }

    return true;
}

static int get_socket_type_by_fd(int fd) {
    struct file *file = NULL;
    struct socket *st_sock = NULL;
    short int socket_type = -1;

    file = fget(fd);
    if (file != NULL && file->private_data != NULL) {
        st_sock = (struct socket *)file->private_data;
        socket_type = st_sock->type;
        fput(file);
        file = NULL;
    }

    return socket_type;
}

static struct socket *dacs_sock_from_file(struct file *file) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 11, 0)
    return sock_from_file(file);
#else
    int err = 0;
    return sock_from_file(file, &err);
#endif
}

static int inet_autobind(struct sock *sk) {
    struct inet_sock *inet;
    /* We may need to bind the socket. */
    lock_sock(sk);
    inet = (struct inet_sock *)sk; // inet_sk(sk);
    if (!inet->inet_num) {
        if(sk->sk_prot && sk->sk_prot->get_port){
            if (sk->sk_prot->get_port(sk, 0)) {
                release_sock(sk);
                return -EAGAIN;
            }
            inet->inet_sport = htons(inet->inet_num);
        }else{
            return -1;
        }
    }
    release_sock(sk);
    return 0;
}

static bool app_bypass(const char *name){
    if(strncmp(name, "ping", 4) == 0){
        return true;
    }
    return false;
}

#endif //YULONGMK_HOOK_COMMON_H
