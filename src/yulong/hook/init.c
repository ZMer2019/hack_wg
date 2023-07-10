/****************************************************************************************
    > File Name: init.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 16:03:59
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#include "init.h"
#include "log.h"
#include "hook.h"
struct symbol_finder *dacs_sym_finder = NULL;
struct system_map *org_system_call_table = NULL;

int kernel_hook_init(void) {
    dacs_sym_finder = (struct symbol_finder*)kmalloc(sizeof(*dacs_sym_finder), GFP_KERNEL);
    org_system_call_table = (struct system_map *)kmalloc(sizeof(*org_system_call_table), GFP_KERNEL);

    if(!dacs_sym_finder || !org_system_call_table){
        LOGE("allocate memory failed\n");
        return -ENOMEM;
    }
    memset(dacs_sym_finder, 0, sizeof(struct symbol_finder));
    memset(org_system_call_table, 0, sizeof(struct system_map));
    if (init_global_finder(dacs_sym_finder)){
        LOGE("init dacs_sym_finder failed !\n");
        return -1;
    }
    if (init_org_system_call_table(dacs_sym_finder, org_system_call_table)){
        LOGE("init org_system_call_table failed !\n");
        return -1;
    }
    add_hook();
    //LOGE("add kernel hook success");
    return 0;
}

void kernel_hook_uninit(void) {
    remove_hook();
    if(NULL != dacs_sym_finder) {
        kfree(dacs_sym_finder);
    }
    if(NULL != org_system_call_table) {
        kfree(org_system_call_table);
    }
    LOGI("remove kernel hook success");
}

void add_hook(void) {
    //switch_hooked_socket(org_system_call_table);
    switch_hooked_connect(org_system_call_table);
    switch_hooked_sendto(org_system_call_table);
    //switch_hooked_sendmsg(org_system_call_table);
}

void remove_hook(void) {
    //switch_org_socket(org_system_call_table);
    switch_org_connect(org_system_call_table);
    switch_org_sendto(org_system_call_table);
    //switch_org_sendmsg(org_system_call_table);
}
