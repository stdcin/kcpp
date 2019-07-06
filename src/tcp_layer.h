#ifndef KCPP_TCP_LAYER_H
#define KCPP_TCP_LAYER_H

#include "trans_layer.h"
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <tins/tins.h>
#include "sock_address.h"

struct tcp_stream {
    typedef std::chrono::system_clock::time_point time_point_type;
    typedef std::chrono::milliseconds time_duration_type;
    void die_after(time_duration_type t);

    uint16_t src_port;
    uint16_t dst_port;
    Tins::IPv4Address src_ip;
    Tins::IPv4Address dst_ip;
    uint16_t ip_id;
    uint32_t seq_number;
    uint32_t ack_number;
    std::atomic<bool> established;
    time_point_type deadline;
};

class tcp_layer : public trans_layer {
 public:
    typedef tcp_stream::time_point_type time_point_type;
    typedef tcp_stream::time_duration_type time_duration_type;

    tcp_layer(const sock_address &saddr, const std::string &iface, bool client);
    ~tcp_layer() override;
    bool start() override;
    void stop() override;
    bool connect() override;
    int read_packets(std::vector<raw_packet *> &packets, bool block) override;
    void send_packet(raw_packet *packet) override;

 private:
    void read_packets_task() override;
    void send_packets_task() override;
    // remove expired tcp_streams
    void expire_streams_task();
    bool handle_dummy_packet(const Tins::PDU &pdu);
    bool handle_packet(const Tins::PDU &pdu);
    bool process_packet(const Tins::IP &ip, const Tins::TCP &tcp);
    bool update_firewall_rules();
    void send_tcp_packet(tcp_stream &s, const uint8_t *data, size_t len, uint32_t flags);
    void send_tcp_packet(tcp_stream &s, uint32_t flags);

    bool closed_;
    bool is_client_;
    queue_type snd_queue_;
    queue_type rcv_queue_;
    moodycamel::BlockingConcurrentQueue<Tins::IP *> pdu_queue_;
    std::thread loop_thread_;
    std::string interface_;
    Tins::PacketSender *sender_;
    Tins::Sniffer *sniffer_;
    const sock_address &saddr_;
    Tins::IPv4Address *server_ip_addr_;
    Tins::IPv4Address *dns_ip_addr_;
    Tins::IPv4Address *src_ip_addr_;
    uint16_t server_port_;
    Tins::EthernetII *eth_;
    std::atomic<bool> initialized_ = {false};

    std::mutex streams_mutex_;
    std::unordered_map<sock_address, tcp_stream *> tcp_streams_;
    std::atomic<uint16_t> client_src_port_;
    uint8_t *plaintext_buf_;
};

#endif //KCPP_TCP_LAYER_H
