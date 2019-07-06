#include <cstdio>
#include <cstring>
#include <cassert>
#include <list>
#include <thread>
#include <chrono>
#include <mutex>

#ifdef __unix__

#include <signal.h>

#endif

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include "defines.h"
#include "config_t.h"
#include "utils.h"
#include "sock_address.h"
#include "session.h"
#include "udp_layer.h"
#ifndef KCPP_DISABLE_TCP
#include "tcp_layer.h"
#endif

class client {
 public:
    client(trans_layer &trans, const sock_address &raddr)
        : trans_layer_(trans), raddr_(raddr), packets_(1024), config_(nullptr) {
    }

    void config(const config_t &cfg) { config_ = &cfg; }

    session *acquire_connection() {
        LOCK_GUARD(sessions_mutex_);
        for (session *sess : sessions_) {
            if (!sess->closed())
                return sess;
        }
        return nullptr;
    }

    void start() {
        std::thread update_thread([this]() {
            while (!closed_) {
                update_sessions();
                //todo
                int interval = std::min(config_->interval, 15);
                std::this_thread::sleep_for(std::chrono::milliseconds(interval));
            }
        });

        std::thread input_thread([this]() {
            while (!closed_) {
                kcp_input();
            }
        });

        update_thread.detach();
        input_thread.detach();
    }

 private:
    /**
     *   kcp_input sessions
     */
    void kcp_input() {
        int n = trans_layer_.read_packets(packets_, true);
        if (n > 0) {
            LOCK_GUARD(sessions_mutex_);
            for (int i = 0; i < n; i++) {
                raw_packet *packet = packets_[i];
                uint32_t convid = *(uint32_t *) packet->data.data();
                for (session *sess : sessions_) {
                    if (!sess->closed()) {
                        sess->kcp_input(packet->data.data(), packet->data.size());
                    }
                }
                delete packet;
            }
        }
    }

    /**
     * update sessions
     */
    void update_sessions() {
        LOCK_GUARD(sessions_mutex_);

        int active_session_count = 0;
        for (session *sess : sessions_) {
            if (!sess->closed())
                active_session_count++;
        }
        if (active_session_count == 0) {
            // dial new session
            // todo: trans-layer reset
            session *new_session = session::dial(*config_, trans_layer_, raddr_);
            if (new_session != nullptr) {
                sessions_.push_back(new_session);
            }
        }

        //update sessions
        for (session *sess : sessions_) {
            if (!sess->closed()) {
                sess->update();
            }
        }

        //delete closed sessions
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            session *sess = *it;
            if (sess->closed()) {
                sessions_.erase(it++);
                delete sess;
                LOGD("delete session");
            } else {
                ++it;
            }
        }
    }

    bool closed_ = false;
    const config_t *config_;
    const sock_address &raddr_;
    trans_layer &trans_layer_;
    std::mutex sessions_mutex_;
    std::list<session *> sessions_;
    std::vector<raw_packet *> packets_;
};

static void accept_cb(evconnlistener *listener, evutil_socket_t fd, sockaddr *address, int socklen, void *ctx);
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void event_cb(struct bufferevent *bev, short events, void *ctx);

static void
accept_cb(evconnlistener *listener, evutil_socket_t fd, sockaddr *address, int socklen, void *ctx) {
    client *cli = static_cast<client *>(ctx);
    session *sess = cli->acquire_connection();
    if (sess) {
        event_base *base = evconnlistener_get_base(listener);
        bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
        assert(bev);
        stream *s = sess->open_stream(bev);
        bufferevent_setwatermark(bev, EV_READ, 0, static_cast<size_t>(sess->get_config().rdbuf));
        bufferevent_enable(bev, EV_READ | EV_WRITE);
        bufferevent_setcb(bev, nullptr, nullptr, event_cb, s);
    } else {
        LOGI("no available session");
        evutil_closesocket(fd);
    }
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    LOGE("accept error: %s, shutting down", evutil_socket_error_to_string(err));
    event_base_loopexit(base, nullptr);
}

static void
event_cb(struct bufferevent *bev, short events, void *ctx) {
    stream *s = static_cast<stream *>(ctx);
    if (events & BEV_EVENT_ERROR) {
        //LOGD("client BEV_EVENT_ERROR");
    } else if (events & BEV_EVENT_EOF) {
        //LOGD("client BEV_EVENT_EOF");
    } else {
        LOGD("events: %d", events);
    }

    // client EOF
    s->shutdown_write();
    LOGD("stream EOF: %u", s->sid());
}

int main(int argc, char const *argv[]) {
    config_t config;
    event_base *base;
    sock_address raddr, laddr;
    trans_layer *trans;

    default_local_config(config);
    if (!parse_local_config(config, argc, argv)) {
        return -1;
    }

    zf_log_set_output_level(config.loglvl);
    zf_log_set_output_v(ZF_LOG_PUT_CTX | ZF_LOG_PUT_SRC | ZF_LOG_PUT_MSG, 0, zf_log_out_stderr_callback);

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
    evthread_use_windows_threads();
#endif
#ifdef __unix__
    evthread_use_pthreads();
    signal(SIGPIPE, SIG_IGN);
#endif

    if (!parse_sockaddr_port(config.remoteaddr.c_str(), &raddr.storage())) {
        return -1;
    }
    std::string bddr = config.localaddr;
    if (bddr.find(':') == 0) {
        bddr.insert(0, "0.0.0.0");
    }
    if (!parse_sockaddr_port(bddr.c_str(), &laddr.storage())) {
        return -1;
    }

    if (config.tcp) {
#ifndef KCPP_DISABLE_TCP
        trans = new tcp_layer(raddr, config.iface, true);
#else
        LOGF("tcp disabled");
#endif
    } else {
        trans = new udp_layer(raddr, true);
    }
    trans->config(config);
    if (!trans->start()) {
        return -1;
    }

    client c(*trans, raddr);
    c.config(config);
    c.start();

    base = event_base_new();
    evconnlistener *listener = evconnlistener_new_bind(base, accept_cb, &c,
                                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                                       (sockaddr *) &laddr.storage(), laddr.len());
    evconnlistener_set_error_cb(listener, accept_error_cb);

    LOGI("listening on %s", laddr.to_string().c_str());
    event_base_dispatch(base);

    trans->stop();
    LOGI("bye.");

#ifdef _WIN32
    WSACleanup();
#endif // _WIN32
    return 0;
}