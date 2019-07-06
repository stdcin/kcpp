#include "udp_layer.h"
#include <thread>
#include <event2/event.h>
#include "defines.h"
#include "utils.h"
#include "config_t.h"

udp_layer::udp_layer(const sock_address &saddr, bool client)
    : saddr_(saddr), is_client_(client), closed_(false) {
}

udp_layer::~udp_layer() = default;

bool udp_layer::start() {
    fd_ = socket(AF_INET /*AF_UNSPEC*/, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0)
        return false;

    if (!is_client_) {
        evutil_make_listen_socket_reuseable(fd_);

        int opt = 1;
#ifdef SO_NOSIGPIPE
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        size_t len = get_sockaddr_len((sockaddr *) &saddr_);
        if (bind(fd_, (const sockaddr *) &saddr_, len)) {
            evutil_closesocket(fd_);
            LOGF("udp bind err");
            return false;
        }
    }

    if (setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, (const char *) &config_->sockbuf, sizeof(config_->sockbuf)) == -1) {
        LOGE("setsockopt err");
        return false;
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, (const char *) &config_->sockbuf, sizeof(config_->sockbuf)) == -1) {
        LOGE("setsockopt err");
        return false;
    }

    std::thread send_thread([this]() {
        this->send_packets_task();
    });
    std::thread read_thread([this]() {
        this->read_packets_task();
    });
    send_thread.detach();
    read_thread.detach();

    return true;
}

void udp_layer::stop() {
    closed_ = true;
}

bool udp_layer::connect() {
    return true;
}

void udp_layer::read_packets_task() {

    int n;
    sock_address from;
    socklen_t from_len;
    char *buf = new char[BUF_SIZE];
    uint8_t *plaintext_buf = new uint8_t[crypto_buf_size];

    while (!closed_) {
        if (is_client_) {
            from = saddr_;
            from_len = from.len();
        } else {
            from_len = sizeof(from);
        }
        n = recvfrom(fd_, buf, BUF_SIZE, 0, (sockaddr *) &from.storage(), &from_len);

        if (is_client_ && n < 0) {
            //todo: fix me
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

#ifdef _WIN32
        if (n < 0) {
            int err = WSAGetLastError();
            LOGE("recvfrom err: %d", err);
        }
#endif // _WIN32
        if (n > 0) {
            //LOGD("recvfrom %s %d bytes", sockaddr_tostring(&from).c_str(), n);
            raw_packet *packet = process_input_packet(from, reinterpret_cast<const uint8_t *>(buf), n, plaintext_buf);
            if (packet != nullptr) {
                rcv_queue_.enqueue(packet);
            }
        }
    }

    delete[] buf;
    delete[] plaintext_buf;
}

void udp_layer::send_packets_task() {
    uint8_t *plaintext_buf = new uint8_t[crypto_buf_size];
    uint8_t *ciphertext_buf = new uint8_t[crypto_buf_size];
    while (!closed_) {

        raw_packet *packet = nullptr;
        snd_queue_.wait_dequeue(packet);

        int n = process_output_packet(*packet, plaintext_buf, ciphertext_buf);
        if (n > 0) {
            sendto(fd_, (const char *) ciphertext_buf, n, 0,
                   (const sockaddr *) &packet->remote.storage(), packet->remote.len());
            // LOGD("send to %s %d bytes", packet->remote.to_string().c_str(), n);
        }
        delete packet;
    }

    delete[] plaintext_buf;
    delete[] ciphertext_buf;
}

int udp_layer::read_packets(std::vector<raw_packet *> &packets, bool block) {
    if (block)
        return rcv_queue_.wait_dequeue_bulk(packets.data(), packets.size());
    else
        return rcv_queue_.try_dequeue_bulk(packets.data(), packets.size());
}

void udp_layer::send_packet(raw_packet *packet) {
    snd_queue_.enqueue(packet);
}





