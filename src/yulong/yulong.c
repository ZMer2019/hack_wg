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
#include "skb_utils.h"
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

uint32_t lookup_redirect_addr(uint32_t sid, enum packet_point point){
#if 0
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
            ret = ntohl(in_aton("10.50.0.1"));
            ret = addr->redirect_daddr;
        }
        if(point == PACKET_POINT_END_OF_TUNNEL){
            ret = ntohl(in_aton("192.168.31.74"));
            ret = addr->original_daddr;
        }
    }
    return ret;
#endif
    uint32_t ret = 0;
    if(point == PACKET_POINT_LOGIN){
        ret = ntohl(in_aton("10.50.0.1"));
        //ret = ntohl(in_aton("192.168.31.74"));
    }
    if(point == PACKET_POINT_END_OF_TUNNEL){
        ret = ntohl(in_aton("192.168.31.74"));
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
        uint32_t sid, uint32_t code, bool need_modify_addr){
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
    entry->need_modify_addr = need_modify_addr;
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
    LOGE("to be save, [%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]\n",
         (tuple->saddr>>24&0xFF),(tuple->saddr>>16&0xFF),(tuple->saddr>>8&0xFF),(tuple->saddr>>0&0xFF),tuple->source,
         (tuple->daddr>>24&0xFF),(tuple->daddr>>16&0xFF),(tuple->daddr>>8&0xFF),(tuple->daddr>>0&0xFF),tuple->dest);
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
                    entry = save(ingress_table, &revert_tuple, header->leaf_sid, header->leaf_code, true);// for return packet
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
            entry = save(egress_table, tuple, header->leaf_sid, header->leaf_code, false);
            if(!entry){
                LOGE("save error:\n");
                return NULL;
            }
        }
        if(header->packet_type == PACKET_TYPE_INBOUND){
            entry = save(ingress_table, tuple, header->leaf_sid, header->leaf_code, false);
            if(!entry){
                LOGE("save error:\n");
                return NULL;
            }
        }
    }
    return entry;
}
struct identity_entry *cache_identity2(struct identity_hashtable *table, uint32_t saddr, uint32_t daddr,
        uint16_t source, uint16_t dest, uint8_t protocol,uint32_t sid, bool need_modify_addr, const char *otp_key){
    struct identity_entry *entry = NULL;
    entry = kzalloc(sizeof(struct identity_entry), GFP_KERNEL);
    if(entry){
        entry->key.saddr = saddr;
        entry->key.daddr = daddr;
        entry->key.source = source;
        entry->key.dest = dest;
        entry->key.protocol = protocol;
        entry->leaf.sid = sid;
        entry->leaf.code = 0;
        entry->type = PROTOCOL_TYPE_YULONG;
        entry->need_modify_addr = need_modify_addr;
        if(otp_key){
            memcpy(entry->leaf.otp_key, otp_key, OTP_KEY_LEN);
        }
        table->add(table, entry);
        LOGI("%d.%d.%d.%d:%d->%d.%d.%d.%d:%d\n",
             (entry->key.saddr>>24)&0xFF,(entry->key.saddr>>16)&0xFF,
             (entry->key.saddr>>8)&0xFF,(entry->key.saddr>>0)&0xFF,entry->key.source,
             (entry->key.daddr>>24)&0xFF,(entry->key.daddr>>16)&0xFF,
             (entry->key.daddr>>8)&0xFF,(entry->key.daddr>>0)&0xFF,entry->key.dest)
    }
    return entry;
}
int login_data_mock(pid_t pid, uint64_t start_time,
                    uint16_t source, uint32_t daddr,
                    uint16_t dest,uint8_t protocol){
    int err = 0;
    struct identity_entry *entry = NULL;
    struct login_hashtable_entry *login_entry = NULL;
    struct nat_addr *addr;
    uint32_t sid = 1;
    uint32_t redirect_daddr = ntohl(in_aton("10.50.0.1"));
    unsigned char otp_key[OTP_KEY_LEN + 1] = {0};
    do{
        login_entry = kzalloc(sizeof(struct login_hashtable_entry), GFP_KERNEL);
        if(login_entry){
            login_entry->key.pid = pid;
            login_entry->key.daddr = daddr;
            login_entry->key.dest = dest;
            login_entry->key.protocol = protocol;
            login_entry->identity.sid = sid;
            memcpy(login_entry->identity.otp_key, otp_key, OTP_KEY_LEN);
            context()->login_hashtable->add(context()->login_hashtable, login_entry);
        }else{
            err = 1;
            break;
        }
        entry = cache_identity2(context()->egress_id_hashtable,get_virtual_local_ip(),
                                daddr, source, dest, protocol, sid, true, otp_key);
        if(!entry){
            err = 2;
            break;
        }

        addr = kzalloc(sizeof(struct nat_addr), GFP_KERNEL);
        if(addr){
            addr->original_daddr = daddr;
            addr->redirect_daddr = redirect_daddr;
            LOGI("sid[%d],redirect_daddr[%d.%d.%d.%d]\n", sid,(addr->redirect_daddr>>24)&0xFF,
                 (addr->redirect_daddr>>16)&0xFF,
                 (addr->redirect_daddr>>8)&0xFF,
                 (addr->redirect_daddr>>0)&0xFF)
            context()->nat_table->insert(context()->nat_table, sid, addr);
        }else{
            err = 3;
            break;
        }

    } while (0);
    if(err != 0){
        LOGE("save login info failed, request err[%d]\n", err);
    }else{
        LOGI("login done\n");
    }
    return 0;
}