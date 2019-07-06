#ifndef KCPP_DEFINES_H
#define KCPP_DEFINES_H

#include "zf_log.h"

#define LOGV(...) ZF_LOGV(__VA_ARGS__)
#define LOGD(...) ZF_LOGD(__VA_ARGS__)
#define LOGI(...) ZF_LOGI(__VA_ARGS__)
#define LOGW(...) ZF_LOGW(__VA_ARGS__)
#define LOGE(...) ZF_LOGE(__VA_ARGS__)
#define LOGF(...) do { \
    ZF_LOGF(__VA_ARGS__); \
    abort(); \
    } while(0)


#define LOCK_GUARD(o) std::lock_guard<std::mutex> __lock(o)
#define BUF_SIZE 8192

#endif //KCPP_DEFINES_H
