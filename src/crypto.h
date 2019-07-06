#ifndef KCPP_CRYPTO_H
#define KCPP_CRYPTO_H
#include <vector>
#include <cstdint>
#include <string>

struct evp_cipher_st;
class crypto {
 public:
    typedef std::vector<uint8_t> key_type;

    bool password(std::string password);
    const key_type &key() const { return key_; }
    int block_size() const { return block_size_; }
    int key_size() const { return key_size_; }
    bool encrypt(const uint8_t *plaintext, size_t plaintext_len, uint8_t *out, size_t &out_len) const;
    bool decrypt(const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out, size_t &out_len) const;
 protected:
    crypto(int key_size, int block_size);
    int key_size_;
    int block_size_;
    evp_cipher_st *cipher_;
    key_type key_;
};

// cbc
class crypto_aes128_cbc : public crypto {
 public:
    crypto_aes128_cbc();
};
class crypto_aes192_cbc : public crypto {
 public:
    crypto_aes192_cbc();
};
class crypto_aes256_cbc : public crypto {
 public:
    crypto_aes256_cbc();
};

// cfb
class crypto_aes128_cfb : public crypto {
 public:
    crypto_aes128_cfb();
};
class crypto_aes192_cfb : public crypto {
 public:
    crypto_aes192_cfb();
};
class crypto_aes256_cfb : public crypto {
 public:
    crypto_aes256_cfb();
};

void crypto_random_bytes(uint8_t *buf, int n);
uint32_t crypto_crc32(const uint8_t *data, size_t n);

#endif //KCPP_CRYPTO_H
