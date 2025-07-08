#include "packetbuilder.hpp"
#include <array>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <iostream>

namespace PacketBuilder {

    struct PseudoHeader {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero = 0;
        uint8_t protocol = IPPROTO_TCP;
        uint16_t tcp_length;
    };

    mmsghdr PacketBatch::make_msg(iovec& iov) {
        mmsghdr msg{};
        msg.msg_hdr.msg_iov = &iov;
        msg.msg_hdr.msg_iovlen = 1;
        return msg;
    }

    std::vector<mmsghdr> PacketBatch::to_mmsg(std::vector<iovec>& iovecs) const {
        std::vector<mmsghdr> msgs;
        size_t total = spoofed.size();
        if (!probe1.empty()) {
            total += 1; // For probe1
        }
        if (!probe2.empty()) {
            total += 1; // For probe2
        }

        msgs.reserve(total);
        iovecs.reserve(total);

        // Add probe1
        if (!probe1.empty()) {
            iovecs.emplace_back(iovec{ const_cast<char*>(probe1.data()), probe1.size() });
            msgs.push_back(make_msg(iovecs.back()));
        }

        // Add spoofed packets
        for (const auto& pkt : spoofed) {
            iovecs.emplace_back(iovec{ const_cast<char*>(pkt.data()), pkt.size() });
            msgs.push_back(make_msg(iovecs.back()));
        }

        // Add probe2
        if (!probe2.empty()) {
            iovecs.emplace_back(iovec{ const_cast<char*>(probe2.data()), probe2.size() });
            msgs.push_back(make_msg(iovecs.back()));
        }

        return msgs;
    }

    static uint16_t compute_checksum(const uint16_t* data, size_t bytes) {
        uint32_t sum = 0;
        while (bytes > 1) {
            sum += *data++;
            bytes -= 2;
        }
        if (bytes == 1) {
            uint16_t odd = 0;
            *reinterpret_cast<uint8_t*>(&odd) = *reinterpret_cast<const uint8_t*>(data);
            sum += odd;
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    std::vector<char> build_packet(const Config& config) {
        const size_t payload_len = config.payload.size();
        if (payload_len > 1500UL)
            return {}; // Payload too large for typical MTU

        const size_t packet_len = sizeof(iphdr) + sizeof(tcphdr) + payload_len;
        std::vector<char> buffer(packet_len, 0);

        auto* iph = reinterpret_cast<iphdr*>(buffer.data());
        auto* tcph = reinterpret_cast<tcphdr*>(buffer.data() + sizeof(iphdr));
        char* payload_ptr = buffer.data() + sizeof(iphdr) + sizeof(tcphdr);

        // Copy payload if present
        if (payload_len > 0) {
            std::memcpy(payload_ptr, config.payload.data(), payload_len);
        }

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(static_cast<uint16_t>(packet_len));
        iph->id = htons(0);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        in_addr src{}, dst{};
        if (inet_pton(AF_INET, config.src_ip.c_str(), &src) != 1 ||
            inet_pton(AF_INET, config.dst_ip.c_str(), &dst) != 1) {
            std::cerr << "Invalid source or destination IP address.\n";
            return {}; // Invalid IPs
        }

        iph->saddr = src.s_addr;
        iph->daddr = dst.s_addr;

        iph->check = compute_checksum(reinterpret_cast<uint16_t*>(iph), sizeof(iphdr));

        tcph->source = htons(config.src_port);
        tcph->dest = htons(config.dst_port);
        tcph->seq = htonl(config.seq);
        tcph->ack_seq = htonl(config.ack);
        tcph->doff = 5;
        tcph->syn = config.syn;
        tcph->ack = config.ack_flag;
        tcph->rst = config.rst;
        tcph->psh = config.psh;
        tcph->window = htons(config.window);
        tcph->check = 0;

        PseudoHeader psh {
            .src_addr = iph->saddr,
            .dst_addr = iph->daddr,
            .tcp_length = htons(sizeof(tcphdr) + payload_len)
        };

        std::vector<char> pseudo_packet(sizeof(PseudoHeader) + sizeof(tcphdr) + payload_len);
        std::memcpy(pseudo_packet.data(), &psh, sizeof(PseudoHeader));
        std::memcpy(pseudo_packet.data() + sizeof(PseudoHeader), tcph, sizeof(tcphdr));
        if (payload_len > 0) {
            std::memcpy(pseudo_packet.data() + sizeof(PseudoHeader) + sizeof(tcphdr),
                        payload_ptr, payload_len);
        }

        tcph->check = compute_checksum(reinterpret_cast<const uint16_t*>(pseudo_packet.data()), pseudo_packet.size());

        return buffer;
    }

    std::vector<std::vector<char>> build_packet_batch(const Config& base_config, size_t packet_count) {
        std::vector<std::vector<char>> packets;
        std::size_t delta_seq = base_config.payload.size();

        for (size_t i = 0; i < packet_count; i++) {
            Config cfg = base_config;
            cfg.seq += static_cast<uint32_t>(i * delta_seq);
            packets.push_back(build_packet(cfg));
        }
        return packets;
    }

}
