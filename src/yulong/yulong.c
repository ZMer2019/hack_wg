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
#include "yulongnl.h"
static struct yulong_context *_context = NULL;
static uint32_t _wg_virtual_local_addr = 0;
static char* INVALID_OTP_KEY = "00000000"
                               "00000000"
                               "00000000"
                               "00000000";
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

__be32 lookup_redirect_addr(uint32_t sid, enum packet_point point){
    struct nat_addr *addr = NULL;
    uint32_t ret = 0;
    struct rbtree_cache_node *node = NULL;
    LOGI("sid[%d]\n", sid);
    node = context()->nat_table->lookup(context()->nat_table, sid);
    if(!node){
        netlink_redirect_addr_request(sid, get_yulongd_pid());
        node = context()->nat_table->lookup(context()->nat_table, sid);
    }
    if(node){
        if(!node->data){
            return 0;
        }
        addr = (struct nat_addr*)node->data;
        if(point == PACKET_POINT_LOGIN){
            ret = addr->redirect_daddr;
        }
        if(point == PACKET_POINT_END_OF_TUNNEL){
            ret = addr->original_daddr;
        }
    }
    return ret;
}

void set_yulongd_pid(pid_t pid){
    _context->yulongd_pid = pid;
}
pid_t get_yulongd_pid(void){
    return _context->yulongd_pid;
}

struct identity_entry* find_id_entry_by_tuple(const struct net_tuple *tuple,
                                              enum inner_packet_type *pkt_type){
    struct identity_hashtable *egress_table, *ingress_table;
    struct identity_entry *egress_entry, *ingress_entry, *entry = NULL;
    egress_table = context()->egress_id_hashtable;
    ingress_table = context()->ingress_id_hashtable;

    egress_entry = egress_table->lookup(egress_table, tuple->saddr, tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    ingress_entry = ingress_table->lookup(ingress_table, tuple->saddr, tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    if(egress_entry){
        entry = egress_entry;
        *pkt_type = PACKET_TYPE_OUTBOUND;
    }
    if(ingress_entry){
        entry = ingress_entry;
        *pkt_type = PACKET_TYPE_INBOUND;
    }
    return entry;
}
static struct identity_entry *create_entry(const struct net_tuple *tuple){
    struct identity_entry *entry = kzalloc(sizeof(struct identity_entry), GFP_KERNEL);
    if(!entry){
        LOGE("allocate memory failed\n");
        return NULL;
    }

    entry->key.saddr = tuple->saddr;
    entry->key.daddr = tuple->daddr;
    entry->key.source = tuple->source;
    entry->key.dest = tuple->dest;
    entry->key.protocol = tuple->protocol;
    memcpy(entry->leaf.otp_key, INVALID_OTP_KEY, OTP_KEY_LENGTH);
    entry->timestamp = ktime_to_timespec(ktime_get()).tv_sec;
    return entry;
}
static struct identity_entry* save(struct identity_hashtable *table,
        const struct net_tuple *tuple,
        uint32_t sid, uint32_t code){
    struct identity_entry *entry = NULL;
    if(unlikely(!tuple)){
        return NULL;
    }
    entry = create_entry(tuple);
    if(!entry){
        return NULL;
    }
    entry->leaf.sid = sid;
    entry->leaf.code = code;
    entry->login_node = true;
    table->add(table, entry);
    return entry;
}
static void revert(const struct net_tuple *src, struct net_tuple *dest){
    dest->saddr = src->daddr;
    dest->daddr = src->saddr;
    dest->source = src->dest;
    dest->dest = src->source;
    dest->protocol = src->protocol;
    dest->syn = src->syn;
}
struct identity_entry* cache_identity(const struct net_tuple *tuple,
                    const struct yulong_header* header,
                    bool is_end_of_tunnel){
    struct identity_hashtable *egress_table = context()->egress_id_hashtable;
    struct identity_hashtable *ingress_table = context()->ingress_id_hashtable;
    struct identity_entry *entry = NULL;
    LOGI("pkt_type[%d]\n", header->packet_type);
    if(header->packet_type == PACKET_TYPE_OUTBOUND){
        entry = egress_table->lookup(egress_table, tuple->saddr,
                                     tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    }
    if(header->packet_type == PACKET_TYPE_INBOUND){
        entry = ingress_table->lookup(ingress_table, tuple->saddr,
                                     tuple->daddr, tuple->source, tuple->dest, tuple->protocol);
    }
    if(entry){
        entry->timestamp = ktime_to_timespec(ktime_get()).tv_sec;
        entry->leaf.sid = header->leaf_sid;
        entry->leaf.code = header->leaf_code;
    }else{
        if(header->packet_type == PACKET_TYPE_OUTBOUND){
            if(is_end_of_tunnel){
                struct net_tuple revert_tuple = {0};
                revert(tuple, &revert_tuple);
                entry = ingress_table->lookup(ingress_table,
                                             revert_tuple.saddr, revert_tuple.daddr,
                                             revert_tuple.source, revert_tuple.dest,
                                             revert_tuple.protocol);
                if(!entry){
                    entry = save(ingress_table, &revert_tuple, header->leaf_sid, header->leaf_code);
                    if(!entry){
                        LOGE("save error:\n");
                        return NULL;
                    }
                }else{
                    entry->timestamp = ktime_to_timespec(ktime_get()).tv_sec;
                    entry->leaf.sid = header->leaf_sid;
                    entry->leaf.code = header->leaf_code;
                }
            }
            entry = save(egress_table, tuple, header->leaf_sid, header->leaf_code);
            if(!entry){
                LOGE("save error:\n");
                return NULL;
            }
        }
        if(header->packet_type == PACKET_TYPE_INBOUND){
            entry = save(ingress_table, tuple, header->leaf_sid, header->leaf_code);
            if(!entry){
                LOGE("save error:\n");
                return NULL;
            }
        }
    }
    return entry;
}