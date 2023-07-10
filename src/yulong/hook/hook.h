/****************************************************************************************
    > File Name: hook.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 15:56:26
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#ifndef YULONG_KM_HOOK_H
#define YULONG_KM_HOOK_H
#include "syscall_map.h"
//connect
asmlinkage long hooked_connect(const struct pt_regs* res);
void switch_hooked_connect(struct system_map *org_system_call_table);
void switch_org_connect(struct system_map *org_system_call_table);

asmlinkage long hooked_sendto(const struct pt_regs* res);
void switch_hooked_sendto(struct system_map *org_system_call_table);
void switch_org_sendto(struct system_map *org_system_call_table);
#endif //YULONGMK_HOOK_H
