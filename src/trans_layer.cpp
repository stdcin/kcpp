#include "trans_layer.h"
#include <cstring>
#include "crypto.h"
#include "defines.h"
#include "config_t.h"

trans_layer::trans_layer()
    : config_(nullptr), crypto_(nullptr) {
}

trans_layer::~trans_layer() {
    if (crypto_) {
        delete crypto_;
    }
}

void trans_layer::config(const config_t &cfg) {
    config_ = &cfg;
    if (cfg.crypt == "aes") {
        crypto_ = new crypto_aes256_cfb;
    } else if (cfg.crypt == "aes-128") {
        crypto_ = new crypto_aes128_cfb;
    } else if (cfg.crypt == "aes-192") {
        crypto_ = new crypto_aes192_cfb;
    } else if (cfg.crypt == "none") {
        crypto_ = nullptr;
    } else if (cfg.crypt.empty()) {
        crypto_ = nullptr;
    } else {
        LOGF("invalid crypt method: %s", cfg.crypt.c_str());
    }

    if (crypto_ != nullptr) {
        if (!crypto_->password(cfg.key)) {
            LOGF("crypto::password() err");
        }
    }
}

// nonce(4) | crc32(4) | payload(len)
int trans_layer::process_output_packet(const raw_packet &packet, uint8_t *plaintext, uint8_t *out) const {
    uint8_t *p;
    int n = 0;
    do {
        if (crypto_ != nullptr) {
            p = plaintext;
        } else {
            p = out;
        }
        if (packet.len + header_size() > mtu_max_size) {
            LOGD("payload size(%d) too large", packet.len);
            break;
        }

        // nonce
        crypto_random_bytes(p, 4);
        p += 4;

        // crc32
        uint32_t crc32 = crypto_crc32(packet.data.data(), packet.len);
        memcpy(p, &crc32, sizeof(crc32)); //todo: fix endian
        p += 4;

        // payload
        memcpy(p, packet.data.data(), packet.len);

        // encrypt
        if (crypto_ != nullptr) {
            size_t ciphertext_len = crypto_buf_size;
            if (crypto_->encrypt(plaintext, header_size() + packet.len, out, ciphertext_len)) {
                n = ciphertext_len;
                break;
            }
        } else {
            n = header_size() + packet.len;
            break;
        }
    } while (false);
    return n;
}

// nonce(4) | crc32(4) | payload(len)
raw_packet *trans_layer::process_input_packet(const sock_address &from,
                                              const uint8_t *data, size_t n, uint8_t *out) const {
    do {
        size_t plaintext_len;
        uint8_t *p;
        if (n == 0 || n > mtu_max_size) {
            LOGD("invalid input size(%zu)", n);
            break;
        }

        if (crypto_ != nullptr) {
            plaintext_len = crypto_buf_size;
            p = out;
            if (!crypto_->decrypt(data, n, out, plaintext_len)) {
                break;
            }
        } else {
            plaintext_len = n;
            p = const_cast<uint8_t *>(data);
        }
        if (plaintext_len < header_size()) {
            break;
        }
        p += 4;
        uint32_t crc32 = *(uint32_t *) p; //todo: fix endian

        p += 4;
        uint8_t *payload = p;
        int payload_size = plaintext_len - header_size();
        if (payload_size <= 0) {
            break;
        }

        uint32_t checksum = crypto_crc32(payload, payload_size);
        if (checksum != crc32) {
            // LOGW("invalid checksum %X/%X %s", crc32, checksum, from.to_string().c_str());
            break;
        }
        raw_packet *packet = new raw_packet(from, payload, payload_size);
        return packet;

    } while (false);
    return nullptr;
}

