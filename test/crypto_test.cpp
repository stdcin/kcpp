#include "gtest/gtest.h"
#include "crypto.h"

const char *PASSWORD = "123456";

TEST(CryptoTest, TestPbkdf2) {
    std::string password = PASSWORD;

    crypto_aes256_cbc a1;
    EXPECT_TRUE(a1.password(password));

    crypto_aes256_cbc a2;
    EXPECT_TRUE(a2.password(password));

    crypto_aes256_cbc a3;
    EXPECT_TRUE(a3.password("password3"));

    EXPECT_TRUE(a1.key() == a2.key());
    EXPECT_FALSE(a1.key() == a3.key());
}

static void test_simple1(crypto *co) {
    std::string message =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras urna ex, efficitur at molestie a, varius at urna.";
    std::string password = PASSWORD;
    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext(1024);
    std::vector<uint8_t> plaintext2(1024);

    co->password(password);
    size_t ciphertext_len = ciphertext.size();
    EXPECT_TRUE(co->encrypt(plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext_len));
    EXPECT_GE(ciphertext_len, plaintext.size());

    ciphertext.resize(ciphertext_len);
    size_t plaintext_len = plaintext2.size();
    EXPECT_TRUE(co->decrypt(ciphertext.data(), ciphertext_len, plaintext2.data(), plaintext_len));
    plaintext2.resize(plaintext_len);
    EXPECT_EQ(plaintext_len, message.size());
    EXPECT_TRUE(plaintext2 == plaintext);
}

TEST(CryptoTest, Simple1) {
    std::vector<crypto *> vec;
    vec.push_back(new crypto_aes128_cbc);
    vec.push_back(new crypto_aes192_cbc);
    vec.push_back(new crypto_aes256_cbc);
    vec.push_back(new crypto_aes128_cfb);
    vec.push_back(new crypto_aes192_cfb);
    vec.push_back(new crypto_aes256_cfb);
    for (auto co: vec) {
        test_simple1(co);
        delete co;
    }
}

static void test_aes_cbc(crypto *co) {
    std::string message = "The quick brown fox jumps over the lazy dog!!!!!"; //48
    std::string password = PASSWORD;
    EXPECT_EQ(message.size() % co->block_size(), 0);

    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext(1024);
    std::vector<uint8_t> plaintext2(1024);

    EXPECT_TRUE(co->password(password));
    size_t ciphertext_len = ciphertext.size();
    EXPECT_TRUE(co->encrypt(plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext_len));
    EXPECT_EQ(ciphertext_len % co->block_size(), 0);
    EXPECT_EQ(ciphertext_len, message.size() + co->block_size());

    ciphertext.resize(ciphertext_len);
    size_t plaintext_len = plaintext2.size();
    EXPECT_TRUE(co->decrypt(ciphertext.data(), ciphertext_len, plaintext2.data(), plaintext_len));

    plaintext2.resize(plaintext_len);
    EXPECT_EQ(plaintext_len, message.size());
    EXPECT_TRUE(plaintext2 == plaintext);
}

TEST(CryptoTest, CBC) {
    std::vector<crypto *> vec;
    vec.push_back(new crypto_aes128_cbc);
    vec.push_back(new crypto_aes192_cbc);
    vec.push_back(new crypto_aes256_cbc);
    for (auto co: vec) {
        test_aes_cbc(co);
        delete co;
    }
}

void test_wrong_password(crypto *co) {
    std::string message = "The quick brown fox jumps over the lazy dog";
    std::string password = PASSWORD;
    const std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext(1024);
    std::vector<uint8_t> plaintext2(1024);
    co->password(password);

    size_t ciphertext_len = ciphertext.size();
    EXPECT_TRUE(co->encrypt(plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext_len));
    EXPECT_GE(ciphertext_len, plaintext.size());

    co->password("wrong_password");

    ciphertext.resize(ciphertext_len);
    size_t plaintext_len = plaintext2.size();
    co->decrypt(ciphertext.data(), ciphertext_len, plaintext2.data(), plaintext_len);
    plaintext2.resize(plaintext_len);
    EXPECT_FALSE(plaintext == plaintext2);
}

TEST(CryptoTest, WrongPassword) {
    std::vector<crypto *> vec;
    vec.push_back(new crypto_aes128_cbc);
    vec.push_back(new crypto_aes192_cbc);
    vec.push_back(new crypto_aes256_cbc);
    vec.push_back(new crypto_aes128_cfb);
    vec.push_back(new crypto_aes192_cfb);
    vec.push_back(new crypto_aes256_cfb);
    for (auto co: vec) {
        test_wrong_password(co);
        delete co;
    }
}

static void test_checksum(crypto *co) {
    const int plaintext_size = 1500;
    uint8_t *plaintext = new uint8_t[plaintext_size];
    std::string password = PASSWORD;
    std::vector<uint8_t> ciphertext(plaintext_size * 2);
    std::vector<uint8_t> plaintext2(plaintext_size * 2);
    EXPECT_TRUE(co->password(password));

    for (int i = 0; i < 5000; i++) {

        crypto_random_bytes(plaintext, plaintext_size);
        uint32_t checksum1 = crypto_crc32(plaintext, plaintext_size);

        size_t ciphertext_len = ciphertext.size();
        EXPECT_TRUE(co->encrypt(plaintext, plaintext_size, ciphertext.data(), ciphertext_len));
        EXPECT_GE(ciphertext_len, plaintext_size);

        size_t plaintext_len = plaintext2.size();
        EXPECT_TRUE(co->decrypt(ciphertext.data(), ciphertext_len, plaintext2.data(), plaintext_len));
        EXPECT_EQ(plaintext_len, plaintext_size);

        uint32_t checksum2 = crypto_crc32(plaintext2.data(), plaintext_len);
        EXPECT_EQ(checksum1, checksum2);
    }

    delete[] plaintext;
}

TEST(CryptoTest, checksum) {
    std::vector<crypto *> vec;
    vec.push_back(new crypto_aes128_cbc);
    vec.push_back(new crypto_aes192_cbc);
    vec.push_back(new crypto_aes256_cbc);
    vec.push_back(new crypto_aes128_cfb);
    vec.push_back(new crypto_aes192_cfb);
    vec.push_back(new crypto_aes256_cfb);
    for (auto co: vec) {
        test_checksum(co);
        delete co;
    }
}