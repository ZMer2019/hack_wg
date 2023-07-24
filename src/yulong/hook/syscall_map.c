/****************************************************************************************
    > File Name: syacall_map.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 15:58:28
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#include "syscall_map.h"
#include "log.h"
int init_global_finder(struct symbol_finder *dacs_sym_finder) {
    //search for kernel symbols dynamicly
    int i;
    int find = 0;
    unsigned long addr;
    char name[NAME_MAX];
    for (i = -10; i < 10; ++i) {
        memset(name, 0, NAME_MAX);
        addr = (unsigned long)kallsyms_lookup_name + (i * sizeof(void *));
        sprint_symbol(name, addr);
        LOGI("name[%s]\n", name);
        if (0 == strncmp(name, _KALLSYMS_LOOKUP_NAME, strlen(_KALLSYMS_LOOKUP_NAME))) {
            //set lookup functions to util
            dacs_sym_finder->find = (Lookup)addr;
            LOGI("kallsyms_lookup_name addr : %lx", (unsigned long)(dacs_sym_finder->find));
            find = 1;
            break;
        }
    }
    return find;
}

int init_org_system_call_table(struct symbol_finder *dacs_sym_finder, struct system_map *org_system_call_table){
    if(!dacs_sym_finder->find){
        LOGI("dacs_sym_finder->find is NULL\n");
        return -1;
    }
    org_system_call_table->addr = (unsigned long *)((dacs_sym_finder->find)("sys_call_table"));
    if (org_system_call_table->addr != NULL) {
        //LOGI("method1: dacs_sym_finder.find successful. org_system_call_table = 0x%lx \n", (unsigned long)(org_system_call_table->addr));
    } else {
        LOGE("find sys_call_table failed\n");
        return -1;
    }
    return 0;
}

unsigned long dacs_regs_get_register(struct pt_regs *regs, unsigned int offset) {
    if (unlikely(offset > MAX_REG_OFFSET))
        return 0;
    return *(unsigned long *)((unsigned long)regs + offset);
}

unsigned long dacs_regs_get_kernel_argument(struct pt_regs *regs, unsigned int n) {
    static const unsigned int argument_offs[] = {
            offsetof(struct pt_regs, di), offsetof(struct pt_regs, si),
            offsetof(struct pt_regs, dx), offsetof(struct pt_regs, cx),
            offsetof(struct pt_regs, r8), offsetof(struct pt_regs, r9),
    };

#define NR_REG_ARGUMENTS 6

    if (n < NR_REG_ARGUMENTS) {
        return dacs_regs_get_register(regs, argument_offs[n]);
    }
    return 0;
}

inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}

void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}