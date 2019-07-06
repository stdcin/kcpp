#ifndef KCPP_SOCK_ADDRESS_H
#define KCPP_SOCK_ADDRESS_H

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <string>
#include <cstdint>

class sock_address {
 public:
    sock_address();
    explicit sock_address(const sockaddr_storage &storage);
    /**
     *
     * @param ipv4  ipv4 address
     * @param port port
     */
    explicit sock_address(uint32_t ipv4, uint16_t port);
    bool operator<(const sock_address &rhs) const;
    bool operator==(const sock_address &rhs) const;
    bool operator!=(const sock_address &rhs) const;
    bool is_ipv4() const;
    bool is_ipv6() const;
    int family() const;
    int len() const;
    uint16_t port() const;
    std::string to_string() const;
    std::string ip_string() const;
    const sockaddr_storage &storage() const;
    sockaddr_storage &storage();
 private:
    sockaddr_storage storage_;
};

namespace std {
template<>
struct hash<sock_address> {
    size_t operator()(const sock_address &k) const;
};
}

#endif //KCPP_SOCK_ADDRESS_H
