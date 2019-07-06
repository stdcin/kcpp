#ifndef KCPP_KCP_H
#define KCPP_KCP_H

#include <cstdint>
#include <mutex>
#include <atomic>

class kcp {
 public:
    typedef int (*output_t)(const char *buf, int len, struct IKCPCB *kcp, void *user);
    kcp(uint32_t convid, output_t output, void *user);
    ~kcp();
    struct IKCPCB *raw_kcp() const;
    int recv(char *buffer, int len);
    int send(const char *buffer, int len);
    int peek_size();
    uint32_t check();
    bool writable();
    int input(const uint8_t *data, size_t size);
    void update();
//    void set_nodelay(int nodelay, int interval, int resend, int nc);
//    void set_wndsize(int sndwnd, int rcvwnd);

 private:
    uint32_t current_ts() const;
    std::mutex mutex_;
    struct IKCPCB *kcp_;
};

#endif //KCPP_KCP_H
