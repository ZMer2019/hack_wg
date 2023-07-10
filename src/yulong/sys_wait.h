/******************************************************************
    > File Name: sys_wait.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/17 17:02:45

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#ifndef YULONG_KM_SYS_WAIT_H
#define YULONG_KM_SYS_WAIT_H
#include <linux/wait.h>
struct wait_cookie{
    int id;
    bool ack;
};

struct wait_wq{
    wait_queue_head_t wq;
};

int sys_wait_init(void);
void sys_wait_exit(void);

int do_wait(int id);
void do_wakeup(int id);

// just for login
int login_wait(int id);
void login_wakeup(int id);
#endif //YULONG_KM_SYS_WAIT_H
