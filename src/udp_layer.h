#ifndef KCPP_UDP_LAYER_H
#define KCPP_UDP_LAYER_H

#include "trans_layer.h"

class udp_layer : public trans_layer {
 public:
    udp_layer(const sock_address &saddr, bool client);
    ~udp_layer() override;
    bool start() override;
    void stop() override;
    bool connect() override;
    int read_packets(std::vector<raw_packet *> &packets, bool block) override;
    void send_packet(raw_packet *packet) override;

 private:
    void read_packets_task() override;

    void send_packets_task() override;

    bool closed_;
    bool is_client_;
    int fd_;
    const sock_address &saddr_;
    queue_type snd_queue_;
    queue_type rcv_queue_;
};

#endif //KCPP_UDP_LAYER_H
