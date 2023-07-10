/******************************************************************
    > File Name: sys_wait.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/17 17:02:45

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#include "sys_wait.h"
#include "cache_common.h"
#include "log.h"
#include <linux/sched.h>

#define MAX_HASH_SIZE       (1<<15)
#define ACK_DONE            (1)
#define MAX_TIMEOUT         (3)
enum queue_type{
    QUEUE_TYPE_LOGIN = 0,
    QUEUE_TYPE_ACL_REQUEST = 1,
};

struct cookie_table{
    enum queue_type type;
    uint8_t hash_table[MAX_HASH_SIZE];
};
static atomic_t timeout_count = ATOMIC_INIT(0);

static struct cookie_table *login_table = NULL;
static struct cookie_table *acl_request_table = NULL;
DECLARE_WAIT_QUEUE_HEAD(login_queue);
DECLARE_WAIT_QUEUE_HEAD(acl_request_queue);

/**
 * @attention id is an atomic++ param!!!
 * */
static int _do_wait(int64_t id, struct cookie_table *table, struct wait_queue_head* queue){
    int err;
    int wait_ret;
    uint64_t jiff;
    bool need_repeat = false;
    int repeat_count = 0;
    int current_timeout = 0;
    int slot = 0;
    jiff = msecs_to_jiffies(500);
    slot = id % MAX_HASH_SIZE;
    table->hash_table[slot] = false;
    do{
        need_repeat = false;
        wait_ret = wait_event_interruptible_timeout(*queue, table->hash_table[slot], jiff);
        switch (wait_ret) {
            case 0:
            LOGI("event has timeout, id[%llu]\n", id);
                err = -EFAULT;
                if(table->type == QUEUE_TYPE_ACL_REQUEST){
                    current_timeout = atomic_inc_return(&timeout_count);
                    if(current_timeout >= MAX_TIMEOUT){
                        atomic_set(&timeout_count, 0);
                    }
                }
                break;
            case 1:
            LOGI("event has timeout and ack occur!\n");
                err = 0;
                break;
            case -ERESTARTSYS:
                need_repeat = true;
                repeat_count++;
                err = -1;
                break;
            default:
                err = 0;
                break;
        }
    }while (need_repeat && (repeat_count < 3));
    table->hash_table[slot] = true;
    return err;
}

static void _do_wakeup(int id, struct cookie_table *table, struct wait_queue_head *queue){
    int slot = id % MAX_HASH_SIZE;
    table->hash_table[slot] = true;
    wake_up_interruptible(queue);
}

int sys_wait_init(void){
    int err = 0;
    login_table = kzalloc(sizeof (struct cookie_table), GFP_KERNEL);
    if(!login_table){
        err = -ENOMEM;
        goto login_table_err;
    }
    login_table->type = QUEUE_TYPE_LOGIN;

    acl_request_table = kzalloc(sizeof(struct cookie_table), GFP_KERNEL);
    if(!acl_request_table){
        err = -ENOMEM;
        goto acl_request_table_err;
    }
    acl_request_table->type = QUEUE_TYPE_ACL_REQUEST;
    return 0;

acl_request_table_err:
    kfree(login_table);
login_table_err:
    return err;
}
void sys_wait_exit(void){
    wake_up_interruptible(&login_queue);
    wake_up_interruptible(&acl_request_queue);
    if(login_table){
        kfree(login_table);
    }
    if(acl_request_table){
        kfree(acl_request_table);
    }
}

int do_wait(int id){
    return _do_wait(id, acl_request_table, &acl_request_queue);
}
void do_wakeup(int id){
    _do_wakeup(id, acl_request_table, &acl_request_queue);
}

int login_wait(int id){
    return _do_wait(id, login_table, &login_queue);
}
void login_wakeup(int id){
    _do_wakeup(id, login_table, &login_queue);
}