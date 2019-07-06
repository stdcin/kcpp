#include "kcp.h"
#include <algorithm>
#include "defines.h"
#include "utils.h"
#include "ikcp.h"

kcp::kcp(uint32_t convid, kcp::output_t output, void *user) {
    kcp_ = ikcp_create(convid, user);
    kcp_->stream = 1;
    kcp_->output = output;
}

kcp::~kcp() {
    ikcp_release(kcp_);
}

struct IKCPCB *kcp::raw_kcp() const {
    return kcp_;
}

int kcp::recv(char *buffer, int len) {
    LOCK_GUARD(mutex_);
    int n = ikcp_recv(kcp_, buffer, len);
    return n;
}

int kcp::send(const char *buffer, int len) {
    LOCK_GUARD(mutex_);
    int n = ikcp_send(kcp_, buffer, len);
    return n;
}

int kcp::peek_size() {
    LOCK_GUARD(mutex_);
    int n = ikcp_peeksize(kcp_);
    return n;
}

uint32_t kcp::check() {
    LOCK_GUARD(mutex_);
    return ikcp_check(kcp_, current_ts());
}

bool kcp::writable() {
    LOCK_GUARD(mutex_);

    IUINT32 cwnd = std::min(kcp_->snd_wnd, kcp_->rmt_wnd);
    if (kcp_->nocwnd == 0) {
        cwnd = std::min(kcp_->cwnd, cwnd);
    }
    bool b = ikcp_waitsnd(kcp_) < cwnd;
//    bool b = ikcp_waitsnd(kcp_) < 2 * kcp_->snd_wnd;
    return b;
}

int kcp::input(const uint8_t *data, size_t size) {
    LOCK_GUARD(mutex_);
    int n = ikcp_input(kcp_, (const char *) data, size);
    return n;
}

void kcp::update() {
    LOCK_GUARD(mutex_);
    ikcp_update(kcp_, current_ts());
}

uint32_t kcp::current_ts() const {
    uint32_t current = static_cast<uint32_t>(unix_timestamp_ms() & 0xfffffffful);
    return current;
}


