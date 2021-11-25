#include "tcp_layer.h"
#include <iostream>
#include <vector>
#include <chrono>
#ifdef __unix__
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <event2/event.h>
#include "defines.h"
#include "utils.h"
#include "configuration.h"

using namespace Tins;
using namespace std::chrono;

#ifndef DUMMY_IP_ADDRESS
#define DUMMY_IP_ADDRESS "114.114.114.114"
#endif

tcp_layer::tcp_layer(const sock_address &saddr, const std::string &iface, bool client)
    : is_client_(client), closed_(false), interface_(iface), saddr_(saddr), pdu_queue_(1024) {
    sender_ = new PacketSender;
    sniffer_ = nullptr;
    eth_ = nullptr;
    src_ip_addr_ = nullptr;
    server_ip_addr_ = nullptr;
    dns_ip_addr_ = new IPv4Address(DUMMY_IP_ADDRESS);
    plaintext_buf_ = new uint8_t[crypto_buf_size];
}

tcp_layer::~tcp_layer() {
    delete dns_ip_addr_;
    delete server_ip_addr_;
    delete src_ip_addr_;
    delete sniffer_;
    delete sender_;
    delete eth_;
    delete[] plaintext_buf_;
}

bool tcp_layer::start() {
    if (config_->iface.empty()) {
        LOGE("interface cannot be empty");
        for (const NetworkInterface &iface : NetworkInterface::all()) {
            LOGI("%s: [ether %s] [inet %s]", iface.name().c_str(),
                 iface.hw_address().to_string().c_str(),
                 iface.ipv4_address().to_string().c_str());
        }
        return false;
    } else {
        auto interfaces = NetworkInterface::all();
        auto it = interfaces.cbegin();
        for (it = interfaces.cbegin(); it != interfaces.cend(); it++) {
            if (it->name() == config_->iface) {
                break;
            }
        }
        if (it == interfaces.cend()) {
            LOGE("%s cannot be found in the following interfaces:", config_->iface.c_str());
            for (const NetworkInterface &iface : NetworkInterface::all()) {
                LOGI("%s: [ether %s] [inet %s]", iface.name().c_str(),
                     iface.hw_address().to_string().c_str(),
                     iface.ipv4_address().to_string().c_str());
            }
            return false;
        }
    }

    if (!saddr_.is_ipv4()) {
        LOGF("only ipv4 is supported");
        return false;
    }
    server_ip_addr_ = new IPv4Address(saddr_.ip_string());
    server_port_ = saddr_.port();

    //firewall
    if (!update_firewall_rules()) {
        return false;
    }

    sock_address addr;
    if (!get_sockaddr(DUMMY_IP_ADDRESS, "53", &addr.storage())) {
        LOGE("cannot get sockaddr %s", DUMMY_IP_ADDRESS);
        return false;
    }
    if (!addr.is_ipv4()) {
        LOGF("only ipv4 is supported");
        return false;
    }

    // socket
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOGF("socket()");
        return false;
    }

    // sniffer
    sender_->default_interface(interface_);
    SnifferConfiguration config;
    std::string filter_string = "tcp and dst " + dns_ip_addr_->to_string();
    config.set_filter(filter_string);
    config.set_immediate_mode(true);
    LOGD("set filter: %s", filter_string.c_str());
    sniffer_ = new Sniffer(interface_, config);

    // start loop
    std::thread t([&] {
        sniffer_->sniff_loop(bind(&tcp_layer::handle_dummy_packet, this, std::placeholders::_1));
    });
    // connect to dns server
    LOGD("connecting to dummy %s", DUMMY_IP_ADDRESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (::connect(fd, (sockaddr *) &addr.storage(), static_cast<socklen_t>(addr.len())) < 0) {
        LOGE("cannot connect to dummy %s", DUMMY_IP_ADDRESS);
    }
    LOGD("waiting for capture result");
    t.join();
    if (eth_ == nullptr) {
        LOGE("cannot capture dummy packet");
        return false;
    }

    initialized_ = true;
    evutil_closesocket(fd);
    LOGI("local %s [%s], gatway %s",
         eth_->src_addr().to_string().c_str(),
         src_ip_addr_->to_string().c_str(),
         eth_->dst_addr().to_string().c_str());

    // start sniff loop
    if (!is_client_) {
        filter_string = "tcp and dst port " + std::to_string(server_port_);
        sniffer_->set_filter(filter_string);
        LOGD("set sniffer filter: %s", filter_string.c_str());
    }
    loop_thread_ = std::thread([this] {
        sniffer_->sniff_loop(bind(&tcp_layer::handle_packet, this, std::placeholders::_1));
        LOGI("sniff_loop done.");
    });

    std::thread send_thread([this]() {
        this->send_packets_task();
    });
    std::thread read_thread([this]() {
        this->read_packets_task();
    });
    std::thread expire_thread([this]() {
        this->expire_streams_task();
    });
    send_thread.detach();
    read_thread.detach();
    expire_thread.detach();
    return true;
}

void tcp_layer::stop() {
    closed_ = true;
    loop_thread_.join();
}

bool tcp_layer::connect() {
    if (!is_client_) {
        return false;
    }

    // remove all tcp streams
    {
        LOCK_GUARD(streams_mutex_);
        for (auto &pair: tcp_streams_) {
            delete pair.second;
        }
        tcp_streams_.clear();
    }

    tcp_stream *s = new tcp_stream;
    s->die_after(seconds(config_->sessionttl));
    s->established = false;
    s->src_port = static_cast<uint16_t>(random_uint(10000, 65536));
    s->dst_port = server_port_;
    s->src_ip = *src_ip_addr_;
    s->dst_ip = *server_ip_addr_;
    s->ip_id = static_cast<uint16_t>(random_uint(1, INT16_MAX));
    s->seq_number = random_uint(1, INT_MAX);
    s->ack_number = 0;
    {
        LOCK_GUARD(streams_mutex_);
        sock_address to(s->dst_ip, s->dst_port);
        tcp_streams_[to] = s;
        client_src_port_ = s->src_port;
    }

    std::string filter = "tcp and dst port " + std::to_string(s->src_port);
    sniffer_->set_filter(filter);
    LOGD("set sniffer filter: %s", filter.c_str());
    LOGI("connecting to %s:%d", s->dst_ip.to_string().c_str(), s->dst_port);
    for (int i = 0; i < 8; i++) {
        send_tcp_packet(*s, TCP::SYN);
        auto start = system_clock::now();
        while (!s->established) {
            std::this_thread::sleep_for(milliseconds(20));
            if (system_clock::now() - start > seconds(3)) {
                LOGI("syn timeout");
                break;
            }
        }
        if (s->established) {
            break;
        }
    }

    if (s->established) {
        LOGI("tcp connection established");
        return true;
    } else {
        LOGI("tcp connect timeout");
        return false;
    }
}

int tcp_layer::read_packets(std::vector<raw_packet *> &packets, bool block) {
    if (block)
        return rcv_queue_.wait_dequeue_bulk(packets.data(), packets.size());
    else
        return rcv_queue_.try_dequeue_bulk(packets.data(), packets.size());
}

void tcp_layer::send_packet(raw_packet *packet) {
    snd_queue_.enqueue(packet);
}

bool tcp_layer::process_packet(const Tins::IP &ip, const Tins::TCP &tcp) {
    uint32_t flags = tcp.flags();
    sock_address from(ip.src_addr(), tcp.sport());
    if (flags == (TCP::PSH | TCP::ACK)) {
        //payload
        LOCK_GUARD(streams_mutex_);
        auto it = tcp_streams_.find(from);
        if (it != tcp_streams_.end()) {
            const RawPDU &raw = tcp.rfind_pdu<RawPDU>();
            const RawPDU::payload_type &payload = raw.payload();
            //raw_packet *packet = new raw_packet(from, payload.data(), (int) payload.size());
            raw_packet *packet = process_input_packet(from, payload.data(), payload.size(), plaintext_buf_);
            if (packet) {
                rcv_queue_.enqueue(packet);
                tcp_stream *s = it->second;
                s->ack_number = tcp.seq();
                //reset deadline
                s->die_after(seconds(config_->sessionttl));
            }
        }
    } else {
        if (is_client_) {
            //client
            if (flags == (TCP::SYN | TCP::ACK)) {
                LOCK_GUARD(streams_mutex_);
                auto it = tcp_streams_.find(from);
                if (it != tcp_streams_.end()) {
                    tcp_stream *s = it->second;
                    if (tcp.ack_seq() == s->seq_number + 1) {
                        s->seq_number += 1;
                        s->ack_number = tcp.seq() + 1;
                        send_tcp_packet(*s, TCP::ACK);
                        s->established = true;
                    }
                }
            }
        } else {
            //server
            if (flags == TCP::SYN) {
                LOCK_GUARD(streams_mutex_);
                tcp_stream *s;
                auto it = tcp_streams_.find(from);
                if (it == tcp_streams_.end()) {
                    s = new tcp_stream;
                    //s->die_after(seconds(config_->sessionttl));
                    s->die_after(seconds(30));
                    s->src_ip = *src_ip_addr_;
                    s->src_port = server_port_;
                    s->dst_ip = ip.src_addr();
                    s->dst_port = tcp.sport();
                    s->ip_id = static_cast<uint16_t>(random_uint(1, INT16_MAX));
                    s->seq_number = random_uint(1, INT_MAX);
                    tcp_streams_[from] = s;
                    LOGD("add tcp stream %s", from.to_string().c_str());
                } else {
                    s = it->second;
                }
                s->ack_number = tcp.seq() + 1;
                send_tcp_packet(*s, (TCP::SYN | TCP::ACK)); // syn/ack

            } else if (flags == TCP::ACK) {
                LOCK_GUARD(streams_mutex_);
                auto it = tcp_streams_.find(from);
                if (it != tcp_streams_.end()) {
                    tcp_stream *s = it->second;
                    if (tcp.ack_seq() == s->seq_number + 1) {
                        s->seq_number += 1;
                        s->established = true;
                        LOGI("tcp connection established %s", from.to_string().c_str());
                    }
                }
            }
        }
    }

    return true;
}

void tcp_layer::read_packets_task() {
//    std::vector<IP *> packets(1024);
//    while (!closed_) {
//        size_t n = pdu_queue_.wait_dequeue_bulk(packets.data(), packets.size());
//        for (int i = 0; i < n; i++) {
//            const IP *ip = packets[i];
//
//            try {
//                const TCP &tcp = ip->rfind_pdu<TCP>();
//                process_packet(*ip, tcp);
//            } catch (malformed_packet &) {
//            }
//            catch (pdu_not_found &) {
//            }
//
//            delete ip;
//        }
//    }
}

void tcp_layer::send_packets_task() {
    uint8_t *plaintext_buf = new uint8_t[crypto_buf_size];
    uint8_t *ciphertext_buf = new uint8_t[crypto_buf_size];
    while (!closed_) {
        raw_packet *packet = nullptr;
        snd_queue_.wait_dequeue(packet);
        int n = process_output_packet(*packet, plaintext_buf, ciphertext_buf);
        if (n > 0) {
            LOCK_GUARD(streams_mutex_);
            const sock_address &to = packet->remote;
            auto it = tcp_streams_.find(to);
            if (it != tcp_streams_.end()) {
                tcp_stream *s = it->second;
                send_tcp_packet(*s, ciphertext_buf, n, TCP::PSH | TCP::ACK);
            }
        }
        delete packet;
    }
}

void tcp_layer::expire_streams_task() {
    while (!closed_) {
        streams_mutex_.lock();
        for (auto it = tcp_streams_.cbegin(); it != tcp_streams_.cend();) {
            tcp_stream *s = it->second;
            if (system_clock::now() > s->deadline) {
                LOGD("delete tcp_stream: %s", it->first.to_string().c_str());
                tcp_streams_.erase(it++);
                delete s;
            } else {
                ++it;
            }
        }
        streams_mutex_.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool tcp_layer::handle_dummy_packet(const Tins::PDU &pdu) {
    const EthernetII &eth = pdu.rfind_pdu<EthernetII>();
    const IP &ip = pdu.rfind_pdu<IP>();
    if (ip.dst_addr() == *dns_ip_addr_) {
        // get local and gateway mac
        eth_ = new EthernetII(eth.dst_addr(), eth.src_addr());
        // get local ip address
        src_ip_addr_ = new IPv4Address(ip.src_addr());
    }
    //capture once
    return false;
}

bool tcp_layer::handle_packet(const PDU &pdu) {
    if (closed_) {
        return false;
    }
    //const EthernetII &eth = pdu.rfind_pdu<EthernetII>();
    IP &ip = const_cast<IP &>(pdu.rfind_pdu<IP>());
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    process_packet(ip, tcp);
    return true;
}

bool tcp_layer::update_firewall_rules() {
#ifdef _WIN32
    int n;
    char cmd[512];
	bool is_admin;

	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			is_admin = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	if (!is_admin) {
		LOGE("must run as administrator");
		return false;
	}

    //turn on firewall
    n = system("netsh advfirewall set allprofiles state on");
    if (n != 0) {
        LOGE("cannot turn on firewall");
        return false;
    }
    if (is_client_) {

        //remove old rules
        sprintf(cmd, "%s", "netsh advfirewall firewall delete rule name=kcpp_client");
        system(cmd);

        sprintf(cmd, "netsh advfirewall firewall add rule name=kcpp_client protocol=TCP dir=in remoteport=%d remoteip=%s action=block",
            server_port_, server_ip_addr_->to_string().c_str());
        if (system(cmd) != 0) {
            LOGE("err: %s", cmd);
            return false;
        }

        sprintf(cmd, "netsh advfirewall firewall add rule name=kcpp_client protocol=TCP dir=out remoteport=%d remoteip=%s action=block",
            server_port_, server_ip_addr_->to_string().c_str());
        if (system(cmd) != 0) {
            LOGE("err: %s", cmd);
            return false;
        }
    }
    else {

        //remove old rules
        sprintf(cmd, "%s", "netsh advfirewall firewall delete rule name=kcpp_serve");
        system(cmd);

        sprintf(cmd, "netsh advfirewall firewall add rule name=kcpp_server protocol=TCP dir=in localport=%d  action=block", server_port_);
        if (system(cmd) != 0) {
            LOGE("err: %s", cmd);
            return false;
        }

        sprintf(cmd, "netsh advfirewall firewall add rule name=kcpp_server protocol=TCP dir=out localport=%d  action=block", server_port_);
        if (system(cmd) != 0) {
            LOGE("err: %s", cmd);
            return false;
        }
    }
    return true;
#endif // _WIN32

#ifdef linux

    char cmd[512];
    if (is_client_) {
        // remove kcpp rules
        system("/sbin/iptables -S | sed \"/kcpp_client/s/-A/iptables -D/e\"");

        // drop input
        sprintf(cmd, "/sbin/iptables -I INPUT -p tcp -s %s --sport %d -j DROP -m comment --comment %s",
                server_ip_addr_->to_string().c_str(), server_port_, "kcpp_client");
        system(cmd);

        // drop output
        sprintf(cmd, "/sbin/iptables -I OUTPUT -p tcp -d %s --dport %d -j DROP -m comment --comment %s",
                server_ip_addr_->to_string().c_str(), server_port_, "kcpp_client");
        system(cmd);

    } else {
        // remove kcpp rules
        system("/sbin/iptables -S | sed \"/kcpp_server/s/-A/iptables -D/e\"");

        // drop input
        sprintf(cmd, "/sbin/iptables -I INPUT -p tcp --dport %d -j DROP -m comment --comment %s",
                server_port_, "kcpp_server");
        system(cmd);
    }
    return true;
#endif
}
void tcp_layer::send_tcp_packet(tcp_stream &s, const uint8_t *data, size_t len, uint32_t flags) {
    if (len == 0)
        return;
    assert(flags & TCP::PSH);

    EthernetII packet(*eth_);
    IP ip(s.dst_ip, s.src_ip);
    ip.id(s.ip_id);
    ip.version(4);
    ip.flags(IP::Flags::DONT_FRAGMENT);
    ip.ttl(64);

    TCP tcp(s.dst_port, s.src_port);
    tcp.flags(flags);
    tcp.seq(s.seq_number);
    tcp.ack_seq(s.ack_number);

    RawPDU raw(data, len);

    packet /= ip / tcp / raw;
    sender_->send(packet);

    s.ip_id++;
    s.seq_number += len;
}

void tcp_layer::send_tcp_packet(tcp_stream &s, uint32_t flags) {
    EthernetII packet(*eth_);
    IP ip(s.dst_ip, s.src_ip);
    ip.id(s.ip_id);
    ip.version(4);
    ip.flags(IP::Flags::DONT_FRAGMENT);
    ip.ttl(64);

    TCP tcp(s.dst_port, s.src_port);
    tcp.flags(flags);
    tcp.seq(s.seq_number);
    tcp.ack_seq(s.ack_number);

    packet /= ip / tcp;
    sender_->send(packet);

    s.ip_id++;
}

void tcp_stream::die_after(tcp_stream::time_duration_type t) {
    deadline = std::chrono::system_clock::now() + t;
}
