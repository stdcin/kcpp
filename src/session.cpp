#include "session.h"
#include <algorithm>
#include <climits>
#include <event2/buffer.h>
#include "defines.h"
#include "utils.h"
#include "configuration.h"
#include "trans_layer.h"
#include "kcp.h"
#include "ikcp.h"
#include "frame.h"

#ifndef STREAM_TTL
#define STREAM_TTL 100
#endif
#ifndef MAX_FRAME_SIZE
#define MAX_FRAME_SIZE 4096
#endif

session::session(uint32_t convid, const configuration &config, trans_layer &trans, const sock_address &epaddr)
    : trans_layer_(trans), config_(config), endpoint_addr_(epaddr),
      frame_header_buffer_(frame::header_size), frame_data_buffer_(BUF_SIZE) {

    kcp_buf_ = new char[BUF_SIZE];
    client_ = true;
    if (client_) {
        next_stream_id_ = 1;
    } else {
        next_stream_id_ = 0;
    }

    input_buffer_ = evbuffer_new();
    kcp_ = new kcp(convid, kcp_output, this);
    ikcp_wndsize(kcp_->raw_kcp(), config.sndwnd, config.rcvwnd);
    ikcp_nodelay(kcp_->raw_kcp(), config.nodelay, config.interval, config.resend, config.nc);
    ikcp_setmtu(kcp_->raw_kcp(), config.mtu - trans_layer::header_size());

    keep_alive_time_point_ = std::chrono::system_clock::now();
    this->die_after(std::chrono::seconds(config.sessionttl));
    LOGD("new session(%x): %s", convid, endpoint_addr_.to_string().c_str());
}

session::~session() {
    delete[] kcp_buf_;
    delete kcp_;
    evbuffer_free(input_buffer_);
}

void session::session_target(const sock_address &target_addr, event_base *base) {
    client_ = false;
    target_addr_ = target_addr;
    base_ = base;
}

stream *session::open_stream(bufferevent *buffer) {
    LOCK_GUARD(streams_mutex_);
    next_stream_id_ += 2;
    stream *s = new stream(next_stream_id_, buffer, std::chrono::seconds(STREAM_TTL));
    streams_[s->sid()] = s;
    frame f(frame::syn, s->sid());
    write_frame(f);
    LOGI("stream opened: %u", s->sid());
    return s;
}

void session::update() {
    int n;

    if (closed_)
        return;

    //write streams data to kcp
    while (kcp_->writable()) {
        LOCK_GUARD(streams_mutex_);
        bool idle = true;
        for (auto &pair : streams_) {
            if (!kcp_->writable()) {
                idle = false;
                break;
            }
            stream *stream = pair.second;
            size_t buffer_len = evbuffer_get_length(stream->in());
            if (buffer_len > 0) {
                frame f(frame::psh, stream->sid());
                f.len = std::min((size_t) MAX_FRAME_SIZE, buffer_len);
                f.data = evbuffer_pullup(stream->in(), f.len);
                write_frame(f);
                evbuffer_drain(stream->in(), f.len);
                idle = false;
            } else if (stream->state() & stream::shut_write
                && (!stream->is_fin_sent())
                && buffer_len == 0) {
                // send fin frame to lower
                frame f(frame::fin, stream->sid());
                write_frame(f);
                stream->set_fin_sent();
                LOGD("write fin frame: %u", stream->sid());
                idle = false;
            }
        }
        if (idle) {
            // session keep alive
            auto now = std::chrono::system_clock::now();
            if (now > keep_alive_time_point_ + std::chrono::seconds(config_.keepalive)) {
                keep_alive_time_point_ = now;
                LOGD("session keep alive: write nop frame -> %s", endpoint_addr_.to_string().c_str());
                frame nop(frame::nop, 0);
                write_frame(nop);
            }
            break;
        }
    }

    // read from kcp
    while (true) {
        n = kcp_->peek_size();
        assert(n < BUF_SIZE);
        if (n <= 0)
            break;
        n = kcp_->recv(kcp_buf_, BUF_SIZE);
        assert(n > 0);
        evbuffer_add(input_buffer_, kcp_buf_, n);
        //reset session deadline
        this->die_after(std::chrono::seconds(config_.sessionttl));
    }

    // process partial frame
    while (true) {
        size_t buffer_len = evbuffer_get_length(input_buffer_);
        if (buffer_len == 0)
            break;
        if (!read_frame_header())
            break;
        if (!read_frame_data())
            break;

        process_frame();
        frame_header_buffer_.Reset();
        frame_data_buffer_.Reset();
        assert(frame_header_buffer_.GetBufferSize() == frame::header_size);
        assert(frame_header_buffer_.GetRemainingSpace() == frame::header_size);
        assert(frame_header_buffer_.GetActiveSize() == 0);
    }

    // close streams
    {
        LOCK_GUARD(streams_mutex_);
        for (auto it = streams_.cbegin(); it != streams_.cend();) {
            stream *s = it->second;

            bool set = false;
            auto now = std::chrono::system_clock::now();
            if ((s->state() & stream::shut_read && s->state() & stream::shut_write) // 已发送fin并且收到fin
                && s->is_fin_sent()
                && evbuffer_get_length(s->in()) == 0 && evbuffer_get_length(s->out()) == 0) // bufferevent 已空
            {
                // stream closed gracefully
                set = true;
            } else if (now > s->deadline()) {
                // stream timeout
                set = true;
                LOGD("stream timeout: %u", s->sid());
            }
            if (set) {
                LOGI("stream closed: %u", s->sid());
                s->close();
                streams_.erase(it++);
                delete s;
            } else {
                ++it;
            }
        }
    }

    {
        // close this session if reaches deadline
        auto now = std::chrono::system_clock::now();
        if (now > deadline_) {
            LOCK_GUARD(streams_mutex_);
            for (auto &pair : streams_) {
                stream *s = pair.second;
                s->close();
                delete s;
            }
            streams_.clear();
            LOGI("session deadline reached, close session: %s", endpoint_addr_.to_string().c_str());
            closed_ = true;
        }
    }

    //kcp update
    kcp_->update();
}

int session::kcp_output(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    session *sess = static_cast<session *>(user);
    if (len < 0)
        return -1;

    raw_packet *packet = new raw_packet(sess->endpoint_addr_, (uint8_t *) buf, len);
    sess->trans_layer_.send_packet(packet);

    return 0;
}

session *session::dial(const configuration &config, trans_layer &trans, const sock_address &raddr) {
    if (!trans.connect()) {
        return nullptr;
    }
    uint32_t convid = random_uint(1000, UINT_MAX);
    session *s = new session(convid, config, trans, raddr);
    frame nop(frame::nop, 0);
    s->write_frame(nop);
    return s;
}

void session::listener_event_cb(bufferevent *bev, short events, void *ctx) {
    stream *s = static_cast<stream *>(ctx);
    if (events & BEV_EVENT_CONNECTED) {
        LOGD("connected to remote, stream: %u", s->sid());
    } else if (events & BEV_EVENT_EOF) {
        LOGD("remote EOF, stream: %u", s->sid());
        // remote EOF, stream shutdown write
        s->shutdown_write();
    } else if (events & BEV_EVENT_ERROR) {
        LOGI("remote connect err: %u", s->sid());
        s->shutdown_write();
        s->die_after(std::chrono::seconds(3));
    } else {
        LOGD("remote unknown event: 0x%x", events);
        s->shutdown_write();
        s->die_after(std::chrono::seconds(3));
    }

}

void session::kcp_input(const uint8_t *data, size_t size) {
    kcp_->input(data, size);
}

void session::write_frame(const frame &frame) {
    assert(frame.len <= MAX_FRAME_SIZE);

    std::vector<uint8_t> bytes = frame::header_to_bytes(frame);
    assert(bytes.size() == frame::header_size);
    // send frame header
    kcp_->send((const char *) bytes.data(), bytes.size());
    if (frame.len > 0) {
        //send frame data
        kcp_->send((const char *) frame.data, frame.len);
    }
}

//std::string session::endpoint_address() const {
//    return sockaddr_tostring(&endpoint_addr_);
//}

bool session::read_frame_header() {
    int n;
    if (frame_header_buffer_.GetRemainingSpace() > 0) {
        std::size_t size = std::min(evbuffer_get_length(input_buffer_), frame_header_buffer_.GetRemainingSpace());
        n = evbuffer_remove(input_buffer_, frame_header_buffer_.GetWritePointer(), size);
        assert(n == size);
        frame_header_buffer_.WriteCompleted(size);
    }
    if (frame_header_buffer_.GetRemainingSpace() == 0) {
        frame f;
        frame::bytes_to_header(f, frame_header_buffer_.GetReadPointer());
        if (f.len > 0) {
            if (f.len > MAX_FRAME_SIZE) {
                LOGF("frame len too large: %s", f.to_string().c_str());
            }
            if (frame_data_buffer_.GetBufferSize() != f.len) {
                frame_data_buffer_.Resize(f.len);
            }
        }
    }

    bool done = frame_header_buffer_.GetRemainingSpace() == 0;
    if (!done) {
        // Couldn't receive the whole data this time.
        assert(evbuffer_get_length(input_buffer_) == 0);
    }
    return done;
}

bool session::read_frame_data() {
    int n;
    frame f;
    frame::bytes_to_header(f, frame_header_buffer_.GetReadPointer());
    if (f.len == 0)
        return true;

    if (frame_data_buffer_.GetRemainingSpace() > 0) {
        std::size_t size = std::min(evbuffer_get_length(input_buffer_), frame_data_buffer_.GetRemainingSpace());
        n = evbuffer_remove(input_buffer_, frame_data_buffer_.GetWritePointer(), size);
        assert(n == size);
        frame_data_buffer_.WriteCompleted(size);
    }

    bool done = frame_data_buffer_.GetRemainingSpace() == 0;
    if (!done) {
        // Couldn't receive the whole data this time.
        assert(evbuffer_get_length(input_buffer_) == 0);
    }
    return done;
}

void session::die_after(time_duration_type sec) {
    deadline_ = std::chrono::system_clock::now() + sec;
}

bool session::process_frame() {
    frame f;
    frame::bytes_to_header(f, frame_header_buffer_.GetReadPointer());
    f.data = frame_data_buffer_.GetReadPointer();

    LOCK_GUARD(streams_mutex_);
    if (f.cmd == frame::syn) {
        // server accept stream
        if (client_) {
            LOGF("client does not support syn");
        }
        auto it = streams_.find(f.sid);
        if (it == streams_.end()) {
            assert(base_ != nullptr);
            bufferevent *bev = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
            assert(bev != nullptr);
            bufferevent_setwatermark(bev, EV_READ, 0, config_.rdbuf);
            stream *s = new stream(f.sid, bev, std::chrono::seconds(STREAM_TTL));
            streams_[s->sid()] = s;
            LOGI("stream opened: %u", s->sid());
            LOGD("%s connecting to %s", endpoint_addr_.to_string().c_str(), target_addr_.to_string().c_str());
            // connect to remote
            bufferevent_setcb(bev, nullptr, nullptr, listener_event_cb, s);
            bufferevent_enable(bev, EV_READ | EV_WRITE);
            bufferevent_socket_connect(bev, (sockaddr *) &target_addr_, target_addr_.len());
        }
    } else if (f.cmd == frame::fin) {
        // fin received, all data has been received, graceful shutdown in progress
        auto it = streams_.find(f.sid);
        if (it != streams_.end()) {
            it->second->shutdown_read();
            LOGD("fin received, stream shutdown read: %u", it->second->sid());
        }
    } else if (f.cmd == frame::psh) {
        auto it = streams_.find(f.sid);
        if (it != streams_.end() && f.len > 0) {
            stream *s = it->second;
            if (s->state() & stream::shut_read) {
                LOGW("broken pipe: %u", s->sid());
            } else {
                bufferevent_write(s->bev(), f.data, f.len);
                //reset stream deadline
                s->die_after(std::chrono::seconds(STREAM_TTL));
            }
        }
    } else if (f.cmd == frame::nop) {
        LOGD("NOP from %s", endpoint_addr_.to_string().c_str());
    } else {
        LOGF("unknown frame: %s", f.to_string().c_str());
    }
    return true;
}



