/****************************************************************************************
    > File Name: log.h
    > Author: yuemingxing
    > Email: yuemingxing@datacloak.com
    > Created Time: 2022/11/30 15:58:28
    Copyright (c) 2022 datacloak. All rights reserved.
****************************************************************************************/

#ifndef YULONG_KM_LOG_H
#define YULONG_KM_LOG_H
#include "yulong.h"
#define DEBUG_ALL 1


#define LOGI(fmt, ...) { \
if(context()->enable_debug){\
    pr_info("[%s:%u]" fmt , __FUNCTION__, __LINE__,##__VA_ARGS__); \
    }\
}

#define LOGE(fmt, ...) { \
if(context()->enable_debug){\
    pr_err("[%s:%u]" fmt , __FUNCTION__, __LINE__,##__VA_ARGS__); \
    }\
}


#define HOOK_LOGI(fmt, ...) pr_info("[%s:%u]" fmt , __FUNCTION__, __LINE__,##__VA_ARGS__)
#define HOOK_LOGE(fmt, ...) pr_err("[%s:%u]" fmt , __FUNCTION__, __LINE__,##__VA_ARGS__)



#endif //YULONGMK_LOG_H
