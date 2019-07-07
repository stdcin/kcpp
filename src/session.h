#ifndef KCPP_SESSION_H
#define KCPP_SESSION_H

#include <unordered_map>
#include <thread>
#include <chrono>
#include <mutex>
#include <functional>
#include <queue>
#include "message_buffer.h"
#include "sock_address.h"
#include "stream.h"

struct configuration;
class frame;
class kcp;
class trans_layer;
class session {
 public:
    typedef std::chrono::time_point<std::chrono::system_clock> time_point_type;
    typedef std::chrono::milliseconds time_duration_type;

    explicit session(uint32_t convid, const configuration &config,
                     trans_layer &trans, const sock_address &epaddr);
    ~session();
    // set session target address
    void session_target(const sock_address &target_addr, event_base *base);
    stream *open_stream(bufferevent *buffer);
    void update();
    void kcp_input(const uint8_t *data, size_t size);
    bool closed() const { return closed_; }
    const configuration &get_config() const { return config_; }
    static session *dial(const configuration &config, trans_layer &trans, const sock_address &raddr);

 private:
    void write_frame(const frame &frame);
    bool read_frame_header();
    bool read_frame_data();
    bool process_frame();
    /**
     *  set session deadline
     * @param sec
     */
    void die_after(time_duration_type sec);
    static int kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user);
    static void listener_event_cb(bufferevent *bev, short events, void *ctx);

    bool client_;
    std::atomic<bool> closed_ = {false};
    const configuration &config_;
    event_base *base_;
    std::unordered_map<uint32_t, stream *> streams_;
    std::mutex streams_mutex_;
    uint32_t next_stream_id_;
    kcp *kcp_;
    char *kcp_buf_;
    trans_layer &trans_layer_;
    sock_address endpoint_addr_;
    sock_address target_addr_; //target server
    time_point_type keep_alive_time_point_;
    time_point_type deadline_;

    MessageBuffer frame_header_buffer_;
    MessageBuffer frame_data_buffer_;
    evbuffer *input_buffer_;
};
#endif //KCPP_SESSION_H
