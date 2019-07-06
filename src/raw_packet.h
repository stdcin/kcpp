#ifndef KCPP_RAW_PACKET_H
#define KCPP_RAW_PACKET_H

#include <cstdint>
#include <vector>
#include "sock_address.h"

class raw_packet {
 public:
    raw_packet(const sock_address &remote, const uint8_t *data, int len) : remote(remote), len(len), data() {
        this->data.insert(this->data.end(), data, data + len);
    }

    int len;
    std::vector<uint8_t> data;
    sock_address remote;
};

#endif //KCPP_RAW_PACKET_H
