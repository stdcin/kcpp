#ifndef KCPP_STREAM_H
#define KCPP_STREAM_H

#include <cstdint>
#include <mutex>
#include <atomic>
#include <chrono>
#include <event2/bufferevent.h>

class stream {
 public:
    enum stream_state {
        shut_read = 1 << 0,
        shut_write = 1 << 1,
    };

    typedef std::chrono::time_point<std::chrono::system_clock> time_point_type;
    typedef std::chrono::milliseconds time_duration_type;

    stream(uint32_t sid, bufferevent *bev, time_duration_type ttl);
    uint32_t sid() const { return sid_; }
    const std::atomic<uint32_t> &state() const { return state_; }
    const std::atomic<bool> &is_fin_sent() const { return fin_sent_; }
    void set_fin_sent() { fin_sent_ = true; }
    bufferevent *bev() const { return bev_; }
    evbuffer *in() const;
    evbuffer *out() const;
    const time_point_type deadline();
    void shutdown_read();
    void shutdown_write();

    /**
     * release bufferevent
     */
    void close();

    /**
     *  set stream deadline
     * @param sec
     */
    void die_after(time_duration_type sec);

 private:
    uint32_t sid_;
    bufferevent *bev_;
    std::mutex mutex_;
    const time_duration_type ttl_;

    std::atomic<bool> closed_ = {false};
    std::atomic<bool> fin_sent_ = {false};
    std::atomic<uint32_t> state_ = {0};
    time_point_type deadline_;
};

#endif //KCPP_STREAM_H
