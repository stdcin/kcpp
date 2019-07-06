#include <cstdio>
#include <cstring>
#include <cassert>
#include <unordered_map>
#ifdef __unix__
#include <signal.h>
#endif
#include <event2/event.h>
#include <event2/thread.h>

#include "defines.h"
#include "config_t.h"
#include "session.h"
#include "utils.h"
#include "udp_layer.h"
#ifndef KCPP_DISABLE_TCP
#include "tcp_layer.h"
#endif

class server {
 public:
    server(trans_layer &trans, const sock_address &taddr)
        : packets_(1024), trans_layer_(trans), taddr_(taddr), config_(nullptr) {

        event_config *config = event_config_new();
        base_ = event_base_new_with_config(config);
        event_config_free(config);
    }

    ~server() {
        event_base_free(base_);
    }

    void config(const config_t &cfg) { config_ = &cfg; }

    void run() {
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

        //keep event_loop alive
        timeval t = {100, 0};
        event *ev = event_new(base_, -1, EV_PERSIST, server::cb_func, nullptr);
        event_add(ev, &t);
        // libevent loop
        event_base_loop(base_, 0 /* EVLOOP_NO_EXIT_ON_EMPTY */);
        LOGI("event_base_loop done");
    }

 private:
    // kcp_input sessions
    void kcp_input() {
        int n = trans_layer_.read_packets(packets_, true);
        if (n > 0) {
            LOCK_GUARD(sessions_mutex_);
            for (int i = 0; i < n; i++) {
                raw_packet *packet = packets_[i];
                uint32_t convid = *(uint32_t *) packet->data.data();
                auto it = sessions_.find(packet->remote);
                if (it == sessions_.end()) {
                    // new session
                    session *sess = new session(convid, *config_, trans_layer_, packet->remote);
                    sess->session_target(taddr_, base_);
                    sessions_[packet->remote] = sess;
                    sess->kcp_input(packet->data.data(), packet->data.size());
                } else {
                    session *sess = it->second;
                    sess->kcp_input(packet->data.data(), packet->data.size());
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

        //update sessions
        for (auto &pair : sessions_) {
            session *sess = pair.second;
            sess->update();
        }

        //delete closed sessions
        for (auto it = sessions_.cbegin(); it != sessions_.cend();) {
            session *sess = it->second;
            if (sess->closed()) {
                sessions_.erase(it++);
                delete sess;
                LOGD("delete session");
            } else {
                ++it;
            }
        }
    }

    static void cb_func(evutil_socket_t fd, short what, void *arg) {
    }

    bool closed_ = false;
    const config_t *config_;
    event_base *base_;
    const sock_address &taddr_; //target server
    trans_layer &trans_layer_;
    std::mutex sessions_mutex_;
    std::unordered_map<sock_address, session *> sessions_;
    std::vector<raw_packet *> packets_;
};

int main(int argc, char const *argv[]) {
    config_t config;
    sock_address taddr, laddr;
    trans_layer *trans;

    default_server_config(config);
    if (!parse_server_config(config, argc, argv)) {
        return -1;
    }

    zf_log_set_output_level(config.loglvl);
    zf_log_set_output_v(ZF_LOG_PUT_CTX | ZF_LOG_PUT_SRC | ZF_LOG_PUT_MSG, 0, zf_log_out_stderr_callback);

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
    evthread_use_windows_threads();
#endif
#ifdef __unix__
    evthread_use_pthreads();
    signal(SIGPIPE, SIG_IGN);
#endif

    if (!parse_sockaddr_port(config.remoteaddr.c_str(), &taddr.storage())) {
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
        trans = new tcp_layer(laddr, config.iface, false);
#else
        LOGF("tcp disabled");
#endif
    } else {
        trans = new udp_layer(laddr, false);
    }
    trans->config(config);
    if (!trans->start()) {
        return -1;
    }

    LOGI("listening on %s", laddr.to_string().c_str());
    server serv(*trans, taddr);
    serv.config(config);
    serv.run();

    trans->stop();
    printf("bye.\n");

#ifdef _WIN32
    WSACleanup();
#endif // _WIN32

    return 0;
}