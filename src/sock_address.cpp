#include "sock_address.h"
#ifdef __unix__
#include <arpa/inet.h>
#endif
#include <cstring>
#include "utils.h"

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

sock_address::sock_address() {
    memset(&storage_, 0, sizeof(storage_));
}
sock_address::sock_address(const sockaddr_storage &storage)
    : storage_(storage) {
}

sock_address::sock_address(uint32_t ipv4, uint16_t port) {
    memset(&storage_, 0, sizeof(storage_));
    sockaddr_in *addr = reinterpret_cast<sockaddr_in *>(&storage_);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = ipv4;
}

bool sock_address::operator<(const sock_address &rhs) const {
    return memcmp(&storage_, &rhs.storage(), sizeof storage_) < 0;
}

bool sock_address::operator==(const sock_address &rhs) const {
    return memcmp(&storage_, &rhs.storage(), sizeof storage_) == 0;
}

bool sock_address::operator!=(const sock_address &rhs) const {
    return !(rhs == *this);
}

bool sock_address::is_ipv4() const {
    return storage_.ss_family == AF_INET;
}

bool sock_address::is_ipv6() const {
    return storage_.ss_family == AF_INET6;
}

int sock_address::family() const {
    return storage_.ss_family;
}

int sock_address::len() const {
    return get_sockaddr_len(&storage_);
}

uint16_t sock_address::port() const {
    if (is_ipv4()) {
        const sockaddr_in *in = (const sockaddr_in *) &storage_;
        return ntohs(in->sin_port);
    } else if (is_ipv6()) {
        const sockaddr_in6 *in6 = (const sockaddr_in6 *) &storage_;
        return ntohs(in6->sin6_port);
    } else {
        return 0;
    }
}

std::string sock_address::to_string() const {
    return sockaddr_tostring(&storage_);
}

std::string sock_address::ip_string() const {
    if (is_ipv4()) {
        char ip[INET_ADDRSTRLEN];
        sockaddr_in *in = (sockaddr_in *) &storage_;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
        return ip;
    } else if (is_ipv6()) {
        char ip[INET6_ADDRSTRLEN];
        sockaddr_in6 *in6 = (sockaddr_in6 *) &storage_;
        inet_ntop(AF_INET, &in6->sin6_addr, ip, sizeof ip);
        return ip;
    }
    return std::string();
}

const sockaddr_storage &sock_address::storage() const {
    return storage_;
}

sockaddr_storage &sock_address::storage() {
    return storage_;
}

// http://ctips.pbworks.com/w/page/7277591/FNV%20Hash
static uint32_t fnv32(const void *buf, size_t len) {
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
    uint32_t hash = FNV_OFFSET_32;
    const char *p = static_cast<const char *>(buf);
    for (int i = 0; i < len; i++) {
        hash = hash ^ (p[i]); // xor next byte into the bottom of the hash
        hash = hash * FNV_PRIME_32; // Multiply by prime number found to work well
    }
    return hash;
}

size_t std::hash<sock_address>::operator()(const sock_address &k) const {
    return fnv32(&k.storage(), sizeof k.storage());
}

