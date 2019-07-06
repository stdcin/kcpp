#include "frame.h"

std::string frame::to_string() const {
    const char *name = "unk";
    switch (cmd) {
        case frame::syn:
            name = "syn";
            break;
        case frame::psh:
            name = "psh";
            break;
        case frame::fin:
            name = "fin";
            break;
        case frame::nop:
            name = "nop";
            break;
    }

    char buf[128];
    sprintf(buf, "ver=%d, cmd=%s, len=%d, sid=%u", ver, name, len, sid);
    return buf;
}


void frame::bytes_to_header(frame &f, const void *data) {
    uint8_t *p = (uint8_t *) data;
    uint8_t ver = *p;
    p++;
    uint8_t cmd = *p;
    p++;
    uint16_t len = *(uint16_t *) p;  //todo: little endian
    p += 2;
    uint32_t sid = *(uint32_t *) p;

    f.ver = ver;
    f.cmd = cmd;
    f.len = len;
    f.sid = sid;
    f.data = nullptr;
}

std::vector<uint8_t> frame::header_to_bytes(const frame &f) {
    std::vector<uint8_t> ret(header_size);
    char *p = (char *) ret.data();
    *(uint8_t *) p = f.ver;
    p++;
    *(uint8_t *) p = f.cmd;
    p++;
    *(uint16_t *) p = f.len; //todo: little endian
    p += 2;
    *(uint32_t *) p = f.sid;
    return ret;
}

