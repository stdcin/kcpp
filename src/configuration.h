#ifndef KCPP_CONFIG_H
#define KCPP_CONFIG_H

#include <cstdint>
#include <string>

struct configuration {
    std::string localaddr;
    std::string remoteaddr;
    std::string config;
    std::string key;
    std::string crypt;
    int keepalive;
    int sessionttl;
    int loglvl; // verbose=1, debug=2, info=3, warn=4, error=5, fatal=6
    int sockbuf;
    int rdbuf; //libevent read high-water mark, maximum receive buffer in bytes per stream
    bool tcp;
    std::string iface; //interface

    std::string mode;
    int mtu;
    int sndwnd;
    int rcvwnd;
    int nodelay;
    int interval;
    int resend;
    int nc;
};

void default_local_config(configuration &config);
bool parse_local_config(configuration &config, int argc, const char *const *argv);
void default_server_config(configuration &config);
bool parse_server_config(configuration &config, int argc, const char *const *argv);

#endif //KCPP_CONFIG_H
