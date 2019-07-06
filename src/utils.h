#ifndef KCPP_UTILS_H
#define KCPP_UTILS_H


#include <stdlib.h>
#include <string>
#include <cstdint>
#include <event2/event.h>

size_t get_sockaddr_len(const sockaddr *addr);

size_t get_sockaddr_len(const sockaddr_storage *addr);

std::string sockaddr_tostring(const sockaddr *addr);

std::string sockaddr_tostring(const sockaddr_storage *addr);

bool parse_sockaddr_port(const char *str, sockaddr_storage *out);

bool get_sockaddr(const char *host, const char *port, sockaddr_storage *storage);

uint64_t unix_timestamp_ms();

uint32_t random_uint(uint32_t min, uint32_t max);

#endif //KCPP_UTILS_H
