#include "configuration.h"
#include <iostream>
#include <fstream>
#include "CLI/CLI11.hpp"
#include "nlohmann/json.hpp"
#include "defines.h"

void default_local_config(configuration &config) {
    config.localaddr = "127.0.0.1:3000";
    config.remoteaddr = "127.0.0.1:19900";
    config.key = "secret_key";
    config.crypt = "aes";
    config.loglvl = 2;
    config.keepalive = 15;
    config.sessionttl = 60;
    config.sockbuf = 1024 * 1024 * 4;
    config.rdbuf = 1024 * 1024 * 2;
    config.tcp = false;

    config.mode = "fast";
    config.mtu = 1350;
    config.sndwnd = 1024;
    config.rcvwnd = 1024;
    config.nodelay = 0;
    config.interval = 40;
    config.resend = 2;
    config.nc = 1;
}

void default_server_config(configuration &config) {
    default_local_config(config);
    config.localaddr = "127.0.0.1:19900";
    config.remoteaddr = "127.0.0.1:1080";
}

template<typename T>
static bool json_get_to(const nlohmann::json &j, const std::string &key, T &to) {
    try {
        j.at(key).get_to(to);
        return true;
    } catch (nlohmann::json::out_of_range &) {
        return false;
    }
}

static bool parse_config(configuration &config, bool client, int argc, const char *const *argv) {
    CLI::App app;
    app.get_formatter()->column_width(40);
    if (client) {
        app.name("kcpp-local");
    } else {
        app.name("kcpp-server");
    }
    if (client) {
        app.add_option("-l,--localaddr", config.localaddr, "local listen address", true);
        app.add_option("-r,--remoteaddr", config.remoteaddr, "kcp server address", true);
    } else {
        app.add_option("-l,--listen", config.localaddr, "server listen address", true);
        app.add_option("-t,--target ", config.remoteaddr, "target server address", true);
    }

    app.add_option("-c", config.config, "config from json file, which will override the command from shell", false);
    app.add_option("--key", config.key, "pre-shared secret between client and server", true);
    app.add_option("--crypt", config.crypt, "aes, aes-128, aes-192, none (CFB mode)", true);
    app.add_option("--loglvl", config.loglvl, "log level: verbose=1, debug=2, info=3, warn=4, error=5, fatal=6", true);
    app.add_option("--keepalive", config.keepalive, "seconds between session heartbeats", true);
    app.add_option("--sessionttl", config.sessionttl, "session ttl", true);
    app.add_option("--sockbuf", config.sockbuf, "per-socket buffer in bytes", true);
    app.add_option("--rdbuf", config.rdbuf,
                   "libevent read high-water mark, maximum receive buffer in bytes per stream", true);
    app.add_flag("--tcp", config.tcp, "using fake tcp instead of udp to send packets");
    app.add_option("--iface", config.iface, "interface name", true);

    app.add_option("--mode", config.mode, "profiles: fast3, fast2, fast, normal, manual", true);
    app.add_option("--mtu", config.mtu, "set maximum transmission unit for packets", true);
    app.add_option("--sndwnd", config.sndwnd, "set send window size(num of packets)", true);
    app.add_option("--rcvwnd", config.rcvwnd, "set receive window size(num of packets)", true);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        app.exit(e);
        return false;
    }

#ifdef _WIN32
	if (config.config.empty()) {
		const std::string file = "config.json";
		std::ifstream ifs(file);
		if (ifs.good()) {
			LOGI("load %s", file.c_str());
			config.config = file;
		}
	}
#endif
    if (!config.config.empty()) {
        std::ifstream ifs(config.config);
        if (!ifs.good()) {
            LOGE("invalid config file");
            return false;
        }

        nlohmann::json j;
        try {
            ifs >> j;
        } catch (nlohmann::json::parse_error &e) {
            LOGE("%s", e.what());
            return false;
        }

        if (client) {
            json_get_to(j, "localaddr", config.localaddr);
            json_get_to(j, "remoteaddr", config.remoteaddr);
        } else {
            json_get_to(j, "listen", config.localaddr);
            json_get_to(j, "target", config.remoteaddr);
        }

        json_get_to(j, "key", config.key);
        json_get_to(j, "crypt", config.crypt);
        json_get_to(j, "keepalive", config.keepalive);
        json_get_to(j, "sessionttl", config.sessionttl);
        json_get_to(j, "loglvl", config.loglvl);
        json_get_to(j, "sockbuf", config.sockbuf);
        json_get_to(j, "rdbuf", config.rdbuf);
        json_get_to(j, "tcp", config.tcp);
        json_get_to(j, "iface", config.iface);

        json_get_to(j, "mode", config.mode);
        json_get_to(j, "mtu", config.mtu);
        json_get_to(j, "sndwnd", config.sndwnd);
        json_get_to(j, "rcvwnd", config.rcvwnd);
        json_get_to(j, "nodelay", config.nodelay);
        json_get_to(j, "interval", config.interval);
        json_get_to(j, "resend", config.resend);
        json_get_to(j, "nc", config.nc);
    }

    if (config.mode == "normal") {
        config.nodelay = 0;
        config.interval = 40;
        config.resend = 2;
        config.nc = 1;
    } else if (config.mode == "fast") {
        config.nodelay = 0;
        config.interval = 30;
        config.resend = 2;
        config.nc = 1;
    } else if (config.mode == "fast2") {
        config.nodelay = 1;
        config.interval = 20;
        config.resend = 2;
        config.nc = 1;
    } else if (config.mode == "fast3") {
        config.nodelay = 1;
        config.interval = 10;
        config.resend = 2;
        config.nc = 1;
    }

    LOGI("listening on: %s", config.localaddr.c_str());
    if (client) {
        LOGI("remote address: %s", config.remoteaddr.c_str());
    } else {
        LOGI("target address: %s", config.remoteaddr.c_str());
    }

    LOGI("crypt: %s", config.crypt.c_str());
    LOGI("nodelay parameters: %d %d %d %d", config.nodelay, config.interval, config.resend, config.nc);
    LOGI("sndwnd: %d  rcvwnd: %d", config.sndwnd, config.rcvwnd);
    LOGI("mtu: %d", config.mtu);
    LOGI("sockbuf: %d", config.sockbuf);
    LOGI("rdbuf: %d", config.rdbuf);
    LOGI("keepalive: %d", config.keepalive);
    LOGI("tcp: %d", config.tcp);

    return true;
}

bool parse_local_config(configuration &config, int argc, const char *const *argv) {
    return parse_config(config, true, argc, argv);
}

bool parse_server_config(configuration &config, int argc, const char *const *argv) {
    return parse_config(config, false, argc, argv);
}