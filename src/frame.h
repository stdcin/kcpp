#ifndef KCPP_FRAME_H
#define KCPP_FRAME_H

#include <cstdint>
#include <string>
#include <vector>

// VERSION(1B) | CMD(1B) | LENGTH(2B) | STREAMID(4B) | DATA(LENGTH)
struct frame {
public:
    enum cmd_t {
        syn = 1 << 0,
        fin = 1 << 1,
        psh = 1 << 2,
        nop = 1 << 3
    };
    static const int header_size = 1 + 1 + 2 + 4;
    static const uint8_t version = 1;


    frame(cmd_t cmd, uint32_t sid)
            : ver(version), cmd(cmd), sid(sid), len(0) {
    }

    frame() : frame(nop, 0) {
    }

    std::string to_string() const;
    static std::vector<uint8_t> header_to_bytes(const frame &f);
    static void bytes_to_header(frame &f, const void *data);

    uint8_t ver;
    uint8_t cmd;
    uint16_t len;
    uint32_t sid;
    uint8_t *data = nullptr;
};

#endif //KCPP_FRAME_H
