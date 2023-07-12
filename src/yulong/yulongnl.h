//
// Created by edward on 23-7-5.
//

#ifndef HACK_WG_YULONGNL_H
#define HACK_WG_YULONGNL_H

#include <net/genetlink.h>

int netlink_login_request(pid_t pid, uint64_t start_time,
                          uint16_t source, uint32_t daddr,
                          uint16_t dest,uint8_t protocol, pid_t comm_pid);


int netlink_redirect_addr_request(uint32_t sid, pid_t comm_pid);

#endif //HACK_WG_YULONGNL_H
