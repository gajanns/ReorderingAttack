#include "packetbuilder.hpp"
#include "default.hpp"

#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>

using namespace packet_builder;

int setup_raw_socket(const std::string_view iface) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.data(), iface.size() + 1) < 0) {
        perror("setsockopt(SO_BINDTODEVICE)");
        close(sock);
        return -1;
    }

    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sock);
        return -1;
    }

    return sock;
}


int main() {
    const size_t num_iterations = 1;
    const size_t seq_length = 3;
    const uint32_t base_seq = 1000;
    const uint32_t base_ack = 5000;

    // Optional spoof payload
    std::string payload = "ABC";  // Can be "" for no payload

    // Setup probe/spoof config
    Config probe_cfg = packet_builder_defaults::probe_config(); // used for RST detection; seq/ack don't matter
    Config non_spoof_cfg = packet_builder_defaults::probe_config();
    Config spoof_cfg = packet_builder_defaults::spoof_config();
    spoof_cfg.seq = non_spoof_cfg.seq = base_seq; // Set a base SEQ for spoofed packets
    spoof_cfg.ack = non_spoof_cfg.ack = base_ack; // Set a base ACK for spoofed packets
    spoof_cfg.payload = non_spoof_cfg.payload = payload;
    spoof_cfg.psh = non_spoof_cfg.psh = !payload.empty();

    bool need_space = !payload.empty() || spoof_cfg.psh || spoof_cfg.syn || spoof_cfg.rst;
    const uint32_t delta_seq = need_space ? std::max(static_cast<uint32_t>(payload.size()), 1u) : 0;

    int sock = setup_raw_socket(connection_defaults::iface);
    if (sock < 0) return 1;

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(probe_cfg.dst_port);

    if (inet_pton(AF_INET, probe_cfg.dst_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    for (size_t i = 0; i < num_iterations; ++i) {
        bool in_connection = std::rand() % 2 == 0;
        Config& current_cfg = in_connection ? spoof_cfg : non_spoof_cfg;

        PacketBatch batch = {
            .probe1 = build_packet(probe_cfg),
            .spoofed = build_packet_batch(current_cfg, seq_length),
            .probe2 = build_packet(probe_cfg)
        };

        std::vector<iovec> iovecs;
        std::vector<mmsghdr> msgs = batch.to_mmsg(iovecs);

        for (auto& msg : msgs) {
            msg.msg_hdr.msg_name = &dest_addr;
            msg.msg_hdr.msg_namelen = sizeof(dest_addr);
        }

        auto start = std::chrono::steady_clock::now();
        int sent = sendmmsg(sock, msgs.data(), msgs.size(), 0);
        auto end = std::chrono::steady_clock::now();

        if (sent < 0) {
            perror("sendmmsg");
        } else {
            std::cout << "Batch " << (i + 1) << ": Sent " << sent << " packets, "
                      << "type=" << (in_connection ? "IN-CONNECTION" : "OUT-OF-CONNECTION") << ", "
                      << "seq=" << current_cfg.seq << ", ack=" << current_cfg.ack << ", ∆t="
                      << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
                      << " µs\n";

        }

        if(in_connection) {
            spoof_cfg.seq += delta_seq * seq_length;
        }

        usleep(1000); // Optional: sleep 1ms between batches
    }

    close(sock);
    return 0;
}