/****************************************************************************************
    > File Name: syacall_map.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 15:58:28
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#ifndef YULONG_KM_SYSCALL_MAP_H
#define YULONG_KM_SYSCALL_MAP_H

#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>

typedef long (*PT_REGS_SYSCALL_FUNC)(const struct pt_regs *);

typedef unsigned long (*Lookup)(const char *name);
struct symbol_finder{
    Lookup find;
};
struct system_map {
    unsigned long *addr;
};

int init_global_finder(struct symbol_finder *dacs_sym_finder);
int init_org_system_call_table(struct symbol_finder *dacs_sym_finder, struct system_map *org_system_call_table);

unsigned long dacs_regs_get_register(struct pt_regs *regs, unsigned int offset);
unsigned long dacs_regs_get_kernel_argument(struct pt_regs *regs, unsigned int n);

inline void mywrite_cr0(unsigned long cr0);
void enable_write_protection(void);
void disable_write_protection(void);

#define GET_ARG_FROM_REGS(res, type, index)                                         \
    (type) dacs_regs_get_kernel_argument((struct pt_regs *)res, index)
#define _KALLSYMS_LOOKUP_NAME "kallsyms_lookup_name+0x0"
#define MAX_REG_OFFSET (offsetof(struct pt_regs, ss))

#endif //YULONGMK_SYSCALL_MAP_H
