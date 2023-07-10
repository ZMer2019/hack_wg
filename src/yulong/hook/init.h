/****************************************************************************************
    > File Name: init.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 16:03:59
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#ifndef YULONG_KM_INIT_H
#define YULONG_KM_INIT_H
#include "syscall_map.h"


int kernel_hook_init(void);
void kernel_hook_uninit(void);

void add_hook(void);
void remove_hook(void);
#endif //YULONGMK_INIT_H
