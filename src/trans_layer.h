#ifndef KCPP_TRANS_LAYER_H
#define KCPP_TRANS_LAYER_H

#include <vector>
#include "moodycamel/blockingconcurrentqueue.h"
#include "raw_packet.h"

class crypto;
struct config_t;
class trans_layer {
 public:
    typedef moodycamel::BlockingConcurrentQueue<raw_packet *> queue_type;
    trans_layer();
    virtual ~trans_layer();
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual bool connect() = 0;
    virtual int read_packets(std::vector<raw_packet *> &packets, bool block) = 0;
    virtual void send_packet(raw_packet *packet) = 0;
    void config(const config_t &cfg);
    const config_t &config() const { return *config_; }
    constexpr static int header_size() { return 4 + 4; }

 protected:
    /**
     * 收包循环
     */
    virtual void read_packets_task() = 0;

    /**
     * 发包循环
     */
    virtual void send_packets_task() = 0;

    int process_output_packet(const raw_packet &packet, uint8_t *plaintext, uint8_t *out) const;
    raw_packet *process_input_packet(const sock_address &from, const uint8_t *data, size_t n, uint8_t *out) const;

    const int mtu_max_size = 1500;
    const size_t crypto_buf_size = 2048;
    const config_t *config_;
    crypto *crypto_;
};

#endif //KCPP_TRANS_LAYER_H
