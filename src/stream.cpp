#include <cassert>
#include "stream.h"
#include "defines.h"
#include "session.h"
#include "utils.h"

stream::stream(uint32_t sid, bufferevent *bev, time_duration_type ttl)
    : sid_(sid), bev_(bev), ttl_(ttl), closed_(false) {

    die_after(ttl_);
}

evbuffer *stream::in() const {
    return bufferevent_get_input(bev_);
}

evbuffer *stream::out() const {
    return bufferevent_get_output(bev_);
}

void stream::close() {
    LOCK_GUARD(mutex_);
    assert(bev_);
    if (!closed_) {
        bufferevent_free(bev_);
        bev_ = nullptr;
        closed_ = true;
    }
}

void stream::shutdown_read() {
    LOCK_GUARD(mutex_);
    evutil_socket_t fd = bufferevent_getfd(bev_);
    if (fd != -1) {
#ifdef _WIN32
        int n = shutdown(fd, SD_RECEIVE);
        if (n != 0) {
            LOGD("shutdown(SD_RECEIVE) err: %d", WSAGetLastError());
        }
#else
        shutdown(fd, SHUT_RD);
#endif
    }

    state_ |= shut_read;
}

void stream::shutdown_write() {
    LOCK_GUARD(mutex_);
    if (!fin_sent_) {
        state_ |= shut_write;
    }
}

void stream::die_after(time_duration_type sec) {
    LOCK_GUARD(mutex_);
    deadline_ = std::chrono::system_clock::now() + sec;
}

const stream::time_point_type stream::deadline() {
    LOCK_GUARD(mutex_);
    return deadline_;
}



