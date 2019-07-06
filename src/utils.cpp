#include "utils.h"
#include <string>
#include <cstring>
#include <chrono>
#include <random>

#ifdef _WIN32
#include <Ws2ipdef.h>
#include <ws2tcpip.h>
#endif // _WIN32


#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

size_t get_sockaddr_len(const sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

size_t get_sockaddr_len(const sockaddr_storage *addr) {
    return get_sockaddr_len((const sockaddr *) addr);
}

std::string sockaddr_tostring(const sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
        evutil_inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof ip);
        return std::string(ip) + ":" + std::to_string(ntohs(addr_in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
        evutil_inet_ntop(AF_INET, &addr_in6->sin6_addr, ip, sizeof ip);
        return std::string(ip) + ":" + std::to_string(ntohs(addr_in6->sin6_port));
    } else {
        return "invalid addr";
    }
}

std::string sockaddr_tostring(const sockaddr_storage *addr) {
    return sockaddr_tostring((const sockaddr *) addr);
}

uint64_t unix_timestamp_ms() {
    auto now = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return ms;
}

uint32_t random_uint(uint32_t min, uint32_t max) {
    std::random_device rd;     // only used once to initialise (seed) engine
    std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
    std::uniform_int_distribution<unsigned int> uni(min, max); // guaranteed unbiased
    return uni(rng);
}

bool get_sockaddr(const char *host, const char *port, sockaddr_storage *storage) {

    int err;
    evutil_addrinfo hints;
    evutil_addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* v4 or v6 is fine. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

    err = evutil_getaddrinfo(host, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "error while resolving '%s': %s\n", host, evutil_gai_strerror(err));
        return false;
    }

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
            break;
        } else if (rp->ai_family == AF_INET6) {
            memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
            break;
        }
    }
    if (rp == nullptr) {
        fprintf(stderr, "failed to resolve %s\n", host);
        freeaddrinfo(result);
        return false;
    }

    return true;
}


bool parse_sockaddr_port(const char *str, sockaddr_storage *out) {
    std::string s(str);
    size_t colon = s.find(':');
    if (colon != std::string::npos) {
        std::string host = s.substr(0, colon);
        std::string port = s.substr(colon + 1);
        return get_sockaddr(host.c_str(), port.c_str(), out);
    } else {
        return false;
    }
}



