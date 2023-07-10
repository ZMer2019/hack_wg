/******************************************************************
    > File Name: yulong.c
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2023/02/16 14:24:47

    Copyright (c) 2023 datacloak. All rights reserved.
******************************************************************/

#include "yulong.h"
#include "init.h"
#include "log.h"
#include "sys_wait.h"
#include "cache_common.h"
#include "device.h"
static struct yulong_context *_context = NULL;
static uint32_t _wg_virtual_local_addr = 0;

/**
 * because of hooking, yulong context cannot init with wg_device
 * */
int yulong_init(bool enable_hook, bool enable_check_permission, bool enable_debug){
    int ret = 0;
    if(cache_common_init() != 0){
        return -ENOMEM;
    }

    _context = kzalloc(sizeof(struct yulong_context), GFP_KERNEL);
    if(!_context){
        return -ENOMEM;
    }
    mutex_init(&_context->lock);
    _context->enable_hook = enable_hook;
    _context->enable_check_permission = enable_check_permission;
    _context->enable_debug = enable_debug;
    if(_context->enable_hook){
        LOGI("hook enabled.\n");
    }else{
        LOGI("hook disabled.\n");
    }
    if(_context->enable_check_permission){
        LOGI("check permission enabled.\n");
    }else{
        LOGI("check permission disabled.\n");
    }
    do{
        _context->login_hashtable = login_hashtable_alloc();
        if(!_context->login_hashtable){
            ret = -ENOMEM;
            break;
        }
        _context->egress_id_hashtable = identity_hashtable_alloc("egress table");
        if(!_context->egress_id_hashtable){
            ret = -ENOMEM;
            break;
        }
        _context->ingress_id_hashtable = identity_hashtable_alloc("ingress table");
        if(!_context->ingress_id_hashtable){
            ret = -ENOMEM;
            break;
        }
        _context->permission_table = dacs_permission_hashtable_alloc("dacs permission");
        if(!_context->permission_table){
            ret = -ENOMEM;
            break;
        }
        _context->acl_table = rbtree_cache_table_alloc();
        if(!_context->acl_table){
            ret = -ENOMEM;
            break;
        }
        _context->otp_key_table = rbtree_cache_table_alloc();
        if(!_context->otp_key_table){
            ret = -ENOMEM;
            break;
        }
        _context->nat_table = rbtree_cache_table_alloc();
        if(!_context->nat_table){
            ret = -ENOMEM;
            break;
        }
        _context->flow_table = ylflow_table_alloc();
        if(!_context->flow_table){
            ret = -ENOMEM;
            break;
        }
        if(sys_wait_init() != 0){
            ret = -ENOMEM;
            break;
        }

        if(kernel_hook_init() != 0){
            ret = -ENOMEM;
            break;
        }
        INIT_LIST_HEAD(&_context->nic_name_list);
        INIT_LIST_HEAD(&_context->device_list);
        rwlock_init(&_context->nic_name_rwlock);
    } while (0);
    if(ret != 0){
        if(_context){
            if(_context->login_hashtable){
                kfree(_context->login_hashtable);
            }
            if(_context->egress_id_hashtable){
                kfree(_context->egress_id_hashtable);
            }
            if(_context->ingress_id_hashtable){
                kfree(_context->ingress_id_hashtable);
            }
            if(_context->permission_table){
                kfree(_context->permission_table);
            }
            if(_context->acl_table){
                kfree(_context->acl_table);
            }
            if(_context->otp_key_table){
                kfree(_context->otp_key_table);
            }
            if(_context->flow_table){
                ylflow_table_free(_context->flow_table, &_context->lock);
                kfree(_context->flow_table);
            }
            kfree(_context);
        }
        sys_wait_exit();
        kernel_hook_uninit();
        cache_common_exit();
    }
    pr_info("yulong initialized succeed\n");
    return ret;
}
void yulong_exit(void){
    LOGI("yulong exit\n");
    kernel_hook_uninit();
    sys_wait_exit();
    if(_context){
        if(_context->login_hashtable){
            kfree(_context->login_hashtable);
        }
        if(!_context->egress_id_hashtable){
            kfree(_context->egress_id_hashtable);
        }
        if(!_context->ingress_id_hashtable){
            kfree(_context->ingress_id_hashtable);
        }
        if(!_context->permission_table){
            kfree(_context->permission_table);
        }
        if(!_context->acl_table){
            kfree(_context->acl_table);
        }
        if(!_context->otp_key_table){
            kfree(_context->otp_key_table);
        }
        kfree(_context);
    }
    cache_common_exit();
    pr_info("yulong exit\n");
}

struct yulong_context* context(void){
    return _context;
}

uint32_t wg_virtual_local_addr(void){
    return _wg_virtual_local_addr;
}
void set_wg_virtual_local_addr(uint32_t addr){
    _wg_virtual_local_addr = addr;
}
bool is_bypass_nic(const char *name){
    bool ret = false;
    struct nic_node *temp = NULL;
    read_lock(&context()->nic_name_rwlock);
    list_for_each_entry(temp, &context()->nic_name_list, list){
        if(strcmp(temp->name, name) == 0){
            ret = true;
            break;
        }
    }
    read_unlock(&context()->nic_name_rwlock);
    return ret;
}

__be32 lookup_redirect_addr(const struct net_tuple *tuple){
    struct identity_entry *entry;
    struct identity_hashtable *table;
    struct nat_addr *addr = NULL;
    uint32_t ret = 0;
    table = context()->egress_id_hashtable;
    entry = table->lookup(table, tuple->saddr, tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    if(!entry){
        table = context()->ingress_id_hashtable;
        entry = table->lookup(table, tuple->saddr, tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    }
    if(entry){
        addr = (struct nat_addr*)context()->nat_table->lookup(context()->nat_table, entry->leaf.sid);
        if(addr){
            ret = addr->new_daddr;
        }
    }
    if(ret != 0){
        LOGI("[%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]=>[%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]\n",
             (tuple->saddr>>24)&0xFF,(tuple->saddr>>16)&0xFF,(tuple->saddr>>8)&0xFF,(tuple->saddr>>0)&0xFF, tuple->source,
             (tuple->daddr>>24)&0xFF,(tuple->daddr>>16)&0xFF,(tuple->daddr>>8)&0xFF,(tuple->daddr>>0)&0xFF, tuple->dest,
             (tuple->saddr>>24)&0xFF,(tuple->saddr>>16)&0xFF,(tuple->saddr>>8)&0xFF,(tuple->saddr>>0)&0xFF, tuple->source,
             (ret >> 0)&0xFF, (ret >> 8)&0xF, (ret >> 16)&0xFF, (ret >> 24)&0xFF, tuple->dest);
    }

    return ret;
}

void set_yulongd_pid(pid_t pid){
    _context->yulongd_pid = pid;
}
pid_t get_yulongd_pid(void){
    return _context->yulongd_pid;
}